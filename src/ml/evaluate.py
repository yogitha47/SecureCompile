"""Evaluate rule-only, ML-only and hybrid analysis on the same held-out Juliet test split.

    python src/ml/evaluate.py

Ground truth (detection): a sample's label set is the categories of its CWE if the function is a
Juliet "bad" variant, else empty. A configuration's prediction for a sample is the set of
categories it reports for that function's text. Per category, a TP means the category is both
reported and in the label set; FP reported but not in labels; FN in labels but not reported.
Detection is NOT localisation: localisation is reported separately and only for rules, since
the ML model does not produce line numbers.

Rule-only  = pipeline rule engines (AST + text patterns), no ML, no compiler.
ML-only    = trained model with validation-selected per-category thresholds.
Hybrid     = union or intersection of the two; the policy is chosen on the validation split.
"""
from __future__ import annotations

import argparse
import json
import random
import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

import joblib  # noqa: E402

import pipeline  # noqa: E402
from findings import ML_CATEGORIES  # noqa: E402
from ml import infer  # noqa: E402
from ml.dataset import load_dataset  # noqa: E402
from ml.train import CANDIDATE_DIR, label_matrix, transform  # noqa: E402

REPORT_JSON = ROOT / "reports" / "ml_evaluation.json"
REPORT_MD = ROOT / "reports" / "ml_evaluation.md"
LOCALISATION_TOLERANCE = 2
BOOTSTRAPS = 300
COMPOSITES = 400


# ------------------------------------------------------------------ predictions

def rule_predictions(samples):
    """(matrix, per-sample {category: [lines]}) from the real pipeline rule engines."""
    index = {c: i for i, c in enumerate(ML_CATEGORIES)}
    matrix = np.zeros((len(samples), len(ML_CATEGORIES)), dtype=np.int8)
    lines = []
    for row, sample in enumerate(samples):
        per_category = {}
        try:
            result = pipeline.analyze(sample["text"], use_compiler=False, use_ml=False)
            for f in result["findings"]:
                if f["category"] in index:
                    matrix[row, index[f["category"]]] = 1
                    per_category.setdefault(f["category"], []).append(f["line"])
        except pipeline.AnalysisInputError:
            pass
        lines.append(per_category)
    return matrix, lines


def ml_predictions(samples, bundle):
    probs = infer.predict_normalized([s["normalized"] for s in samples])
    thresholds = np.array([bundle["thresholds"][c] for c in ML_CATEGORIES])
    return (probs >= thresholds).astype(np.int8), probs


# ------------------------------------------------------------------ metrics

def prf(tp, fp, fn):
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    f1 = 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else None
    return precision, recall, f1


def r4(x):
    return None if x is None else round(float(x), 4)


def metrics(y_true, y_pred):
    per_category = {}
    tp_all = fp_all = fn_all = 0
    f1s = []
    for j, category in enumerate(ML_CATEGORIES):
        t, p = y_true[:, j] == 1, y_pred[:, j] == 1
        tp, fp, fn, tn = int((t & p).sum()), int((~t & p).sum()), int((t & ~p).sum()), int((~t & ~p).sum())
        precision, recall, f1 = prf(tp, fp, fn)
        per_category[category] = {"support": int(t.sum()), "tp": tp, "fp": fp, "fn": fn, "tn": tn,
                                  "precision": r4(precision), "recall": r4(recall), "f1": r4(f1)}
        tp_all, fp_all, fn_all = tp_all + tp, fp_all + fp, fn_all + fn
        if t.sum() > 0 and f1 is not None:
            f1s.append(f1)
    micro_p, micro_r, micro_f = prf(tp_all, fp_all, fn_all)
    any_true, any_pred = y_true.any(axis=1), y_pred.any(axis=1)
    atp, afp, afn = int((any_true & any_pred).sum()), int((~any_true & any_pred).sum()), int((any_true & ~any_pred).sum())
    ap, ar, af = prf(atp, afp, afn)
    return {
        "per_category": per_category,
        "micro": {"precision": r4(micro_p), "recall": r4(micro_r), "f1": r4(micro_f),
                  "tp": tp_all, "fp": fp_all, "fn": fn_all},
        "macro_f1": r4(np.mean(f1s)) if f1s else None,
        "any_vulnerability": {"precision": r4(ap), "recall": r4(ar), "f1": r4(af), "tp": atp, "fp": afp, "fn": afn},
        "exact_match_ratio": r4((y_true == y_pred).all(axis=1).mean()),
        "samples": int(len(y_true)),
    }


def bootstrap_ci(y_true, preds, groups, rng):
    """Cluster bootstrap over Juliet test-case groups (flow variants are not independent samples)."""
    unique = sorted(set(groups))
    idx = {g: np.where(np.array(groups) == g)[0] for g in unique}
    results = {name: {"micro_f1": [], "macro_f1": []} for name in preds}
    for _ in range(BOOTSTRAPS):
        chosen = [rng.choice(unique) for _ in unique]
        rows = np.concatenate([idx[g] for g in chosen])
        for name, pred in preds.items():
            m = metrics(y_true[rows], pred[rows])
            results[name]["micro_f1"].append(m["micro"]["f1"])
            results[name]["macro_f1"].append(m["macro_f1"])
    out = {}
    for name, series in results.items():
        out[name] = {}
        for key, values in series.items():
            values = [v for v in values if v is not None]
            out[name][key] = [r4(np.percentile(values, 2.5)), r4(np.percentile(values, 97.5))] if values else None
    return out


def localisation(samples, y_pred_rules, rule_lines):
    """Among rule true positives that have FLAW annotations: was a reported line within tolerance?"""
    detected = hit = 0
    for i, s in enumerate(samples):
        if not s["flaw_lines"]:
            continue
        for category in s["labels"]:
            j = ML_CATEGORIES.index(category)
            if y_pred_rules[i, j] != 1:
                continue
            detected += 1
            if any(abs(line - flaw) <= LOCALISATION_TOLERANCE
                   for line in rule_lines[i].get(category, []) if line for flaw in s["flaw_lines"]):
                hit += 1
                break
    return {"tolerance_lines": LOCALISATION_TOLERANCE, "detected_with_flaw_annotation": detected,
            "localised": hit, "localisation_rate": r4(hit / detected) if detected else None}


# ------------------------------------------------------------------ composite multi-vulnerability files

def composite_eval(test, bundle, rng):
    """Synthetic files that contain several vulnerable functions of different categories."""
    vulnerable = [s for s in test if s["labels"]]
    safe = [s for s in test if not s["labels"]]
    by_label = {}
    for s in vulnerable:
        by_label.setdefault(tuple(s["labels"]), []).append(s)
    keys = sorted(by_label)
    cases = []
    for _ in range(COMPOSITES):
        picks = [rng.choice(by_label[k]) for k in rng.sample(keys, rng.choice([2, 3]))]
        picks.append(rng.choice(safe))
        names = [p["function"] for p in picks]
        if len(set(names)) != len(names):
            continue
        truth = sorted({c for p in picks for c in p["labels"]})
        source = "#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n\n" + "\n\n".join(p["text"] for p in picks) + "\n"
        cases.append((source, truth))
    y_true = np.zeros((len(cases), len(ML_CATEGORIES)), dtype=np.int8)
    ml = np.zeros_like(y_true)
    rules = np.zeros_like(y_true)
    for row, (source, truth) in enumerate(cases):
        for c in truth:
            y_true[row, ML_CATEGORIES.index(c)] = 1
        result = infer.predict_source(source)
        for scope in result.get("scopes", []):
            for c in scope["predicted"]:
                ml[row, ML_CATEGORIES.index(c)] = 1
        for f in pipeline.analyze(source, use_compiler=False, use_ml=False)["findings"]:
            if f["category"] in ML_CATEGORIES:
                rules[row, ML_CATEGORIES.index(f["category"])] = 1
    return {
        "note": ("Synthetic files built by concatenating 2-3 vulnerable test-split functions of different "
                 "categories plus one safe function. Exercises the file-level path (function splitting, "
                 "pooling); not real multi-vulnerability code."),
        "files": len(cases),
        "labels_per_file_mean": r4(y_true.sum(axis=1).mean()),
        "rule_only": metrics(y_true, rules), "ml_only": metrics(y_true, ml),
        "hybrid_union": metrics(y_true, np.maximum(rules, ml)),
    }


# ------------------------------------------------------------------ out-of-distribution sanity (hand-written cases)

def manifest_sanity(bundle):
    manifest = json.loads((ROOT / "evaluation" / "manifest.json").read_text(encoding="utf-8"))
    from findings import RULES
    rows = []
    for case in manifest["cases"]:
        source = (ROOT / case["file"]).read_text(encoding="utf-8")
        expected = None
        if case["label"] == "vulnerable":
            category = RULES.get(case["expected_rule_id"], (None,))[0]
            expected = category
        result = infer.predict_source(source)
        ml_cats = sorted({c for scope in result.get("scopes", []) for c in scope["predicted"]})
        rule_cats = sorted({f["category"] for f in pipeline.analyze(source, use_compiler=False, use_ml=False)["findings"]})
        rows.append({"id": case["id"], "label": case["label"], "expected_category": expected,
                     "rule_categories": rule_cats, "ml_categories": ml_cats})
    in_scope = [r for r in rows if r["label"] == "vulnerable" and r["expected_category"] in ML_CATEGORIES]
    return {
        "note": ("20 hand-written snippets from the original project (not Juliet). A tiny sanity check on "
                 "out-of-distribution input, not a performance estimate."),
        "cases": rows,
        "vulnerable_cases_in_ml_scope": len(in_scope),
        "ml_detected_expected_category": sum(r["expected_category"] in r["ml_categories"] for r in in_scope),
        "rules_detected_expected_category": sum(r["expected_category"] in r["rule_categories"] for r in in_scope),
        "safe_cases": sum(r["label"] == "safe" for r in rows),
        "safe_cases_with_ml_flag": sum(r["label"] == "safe" and bool(r["ml_categories"]) for r in rows),
        "safe_cases_with_rule_flag": sum(r["label"] == "safe" and bool(r["rule_categories"]) for r in rows),
    }


# ------------------------------------------------------------------ main

def hybrid(rules, ml, policy):
    return np.maximum(rules, ml) if policy == "union" else np.minimum(rules, ml)


def _column_f1(y, pred):
    tp, fp, fn = int(((y == 1) & (pred == 1)).sum()), int(((y == 0) & (pred == 1)).sum()), int(((y == 1) & (pred == 0)).sum())
    return 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else 0.0


def choose_per_category_policy(y_val, rules_val, ml_val):
    """For each category pick rule / ml / union / intersection by validation F1 (ties: earlier wins)."""
    options = {"ml": lambda r, m: m, "union": np.maximum, "rule": lambda r, m: r, "intersection": np.minimum}
    chosen = {}
    for j, category in enumerate(ML_CATEGORIES):
        best_name, best_f1 = None, -1.0
        for name, fn in options.items():
            f1 = _column_f1(y_val[:, j], fn(rules_val[:, j], ml_val[:, j]))
            if f1 > best_f1 + 1e-9:
                best_name, best_f1 = name, f1
        chosen[category] = {"policy": best_name, "validation_f1": r4(best_f1)}
    return chosen, options


def apply_per_category_policy(chosen, options, rules, ml):
    out = np.zeros_like(rules)
    for j, category in enumerate(ML_CATEGORIES):
        out[:, j] = options[chosen[category]["policy"]](rules[:, j], ml[:, j])
    return out


def markdown(report):
    lines = ["# SecureCompile evaluation (generated by src/ml/evaluate.py)", "",
             f"Dataset: {report['dataset']['name']}; split seed {report['dataset']['split_seed']}; "
             f"test samples {report['test']['samples']} from {report['dataset']['test_groups']} test-case groups.",
             f"Hybrid policy (chosen on validation): **{report['hybrid_policy']}**.", "",
             "## Test split, per category (precision / recall / F1, FP, FN)", "",
             "| Category | Support | Rule P/R/F1 (FP,FN) | ML P/R/F1 (FP,FN) | Hybrid P/R/F1 (FP,FN) |", "|---|---|---|---|---|"]

    def cell(m):
        f = lambda v: "n/a" if v is None else f"{v:.2f}"
        return f"{f(m['precision'])}/{f(m['recall'])}/{f(m['f1'])} ({m['fp']},{m['fn']})"

    for c in ML_CATEGORIES:
        r, m, h = (report["test"][k]["per_category"][c] for k in ("rule_only", "ml_only", "hybrid"))
        lines.append(f"| {c} | {r['support']} | {cell(r)} | {cell(m)} | {cell(h)} |")
    lines += ["", "| Aggregate | Rule-only | ML-only | Hybrid (union) | Hybrid (per-category policy) |", "|---|---|---|---|---|"]
    for label, getter in (("micro F1", lambda x: x["micro"]["f1"]), ("macro F1", lambda x: x["macro_f1"]),
                          ("any-vulnerability F1", lambda x: x["any_vulnerability"]["f1"]),
                          ("exact-match ratio", lambda x: x["exact_match_ratio"])):
        lines.append(f"| {label} | " + " | ".join(str(getter(report["test"][k])) for k in ("rule_only", "ml_only", "hybrid", "hybrid_per_category_policy")) + " |")
    lines += ["", "Per-category hybrid policy chosen on validation: " +
              ", ".join(f"{c}={v['policy']}" for c, v in report["hybrid_per_category_policy"].items())]
    return "\n".join(lines) + "\n"


def main():
    cli = argparse.ArgumentParser()
    cli.add_argument("--seed", type=int, default=1337)
    args = cli.parse_args()
    rng = random.Random(args.seed)

    bundle, meta = infer.load_model()
    rows = load_dataset()
    val = [s for s in rows if s["split"] == "validation"]
    test = [s for s in rows if s["split"] == "test"]
    y_val, y_test = label_matrix(val), label_matrix(test)

    print("rule engines on validation ...")
    rules_val, _ = rule_predictions(val)
    print("rule engines on test ...")
    rules_test, rule_lines = rule_predictions(test)
    ml_val, _ = ml_predictions(val, bundle)
    ml_test, ml_probs = ml_predictions(test, bundle)

    # Hybrid policy chosen on validation only.
    policies = {p: metrics(y_val, hybrid(rules_val, ml_val, p))["micro"]["f1"] or 0 for p in ("union", "intersection")}
    chosen = max(policies, key=policies.get)
    print("validation micro-F1 by hybrid policy:", policies, "-> chosen:", chosen)

    per_cat, options = choose_per_category_policy(y_val, rules_val, ml_val)
    preds_test = {"rule_only": rules_test, "ml_only": ml_test, "hybrid": hybrid(rules_test, ml_test, chosen),
                  "hybrid_per_category_policy": apply_per_category_policy(per_cat, options, rules_test, ml_test)}
    test_metrics = {name: metrics(y_test, pred) for name, pred in preds_test.items()}
    test_metrics["hybrid_other_policy"] = metrics(y_test, hybrid(rules_test, ml_test, "intersection" if chosen == "union" else "union"))
    groups = [s["group"] for s in test]
    ci = bootstrap_ci(y_test, preds_test, groups, rng)

    print("feature-set comparison on test ...")
    comparison = []
    for path in sorted(CANDIDATE_DIR.glob("*.joblib")):
        cand = joblib.load(path)
        x = transform(cand["vectorizers"], test)
        probs = cand["classifier"].predict_proba(x)
        pred = (probs >= np.array([cand["thresholds"][c] for c in ML_CATEGORIES])).astype(np.int8)
        m = metrics(y_test, pred)
        comparison.append({"candidate": path.stem, "feature_set": cand["feature_set"], "C": cand["C"],
                           "selected": cand["feature_set"] == meta["feature_set"] and cand["C"] == meta["C"],
                           "test_micro_f1": m["micro"]["f1"], "test_macro_f1": m["macro_f1"]})

    report = {
        "dataset": {"name": meta["dataset"]["name"], "license": meta["dataset"]["license"],
                    "split_seed": meta["dataset"]["split_seed"], "test_groups": len(set(groups)),
                    "train_samples": meta["dataset"]["train_samples"],
                    "validation_samples": meta["dataset"]["validation_samples"]},
        "methodology": {
            "split": "Grouped by Juliet test case (all flow variants of one CWE/data-source/sink stay together), "
                     "stratified by CWE; exact-duplicate and near-duplicate (TF-IDF cosine >= 0.95) validation/test "
                     "samples against training were removed.",
            "ground_truth": "Function-level category labels from CWE directory + Juliet bad/good naming; detection is "
                            "scored per category per function. Localisation is scored separately for rules only.",
            "model_selection": "Feature set, C and per-category thresholds were chosen on the validation split only.",
            "hybrid_policy_selection": policies,
            "caveats": ["Juliet is synthetic and highly templated; these numbers do not estimate real-world performance.",
                        "Several categories have small test support (see 'support'); intervals are wide.",
                        "Rule thresholds were not tuned on this data; the rules were written before this dataset was used."],
        },
        "hybrid_policy": chosen,
        "hybrid_per_category_policy": per_cat,
        "validation_policy_micro_f1": policies,
        "test": {"samples": len(test), **test_metrics},
        "bootstrap_95ci_cluster_by_group": ci,
        "rule_localisation": localisation(test, rules_test, rule_lines),
        "feature_set_comparison": comparison,
        "composite_multi_vulnerability_files": composite_eval(test, bundle, rng),
        "handwritten_cases_sanity": manifest_sanity(bundle),
        "model": {"feature_set": meta["feature_set"], "C": meta["C"], "thresholds": meta["thresholds"],
                  "validation_f1_per_category": meta["validation_f1_per_category"]},
    }
    REPORT_JSON.parent.mkdir(exist_ok=True)
    REPORT_JSON.write_text(json.dumps(report, indent=2), encoding="utf-8")
    REPORT_MD.write_text(markdown(report), encoding="utf-8")
    print(markdown(report))
    print(f"Wrote {REPORT_JSON} and {REPORT_MD}")


if __name__ == "__main__":
    main()
