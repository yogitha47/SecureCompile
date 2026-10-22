"""Train the multi-label vulnerability classifier on the prepared Juliet function dataset.

    python src/ml/train.py

Model selection (feature set, regularisation, per-category thresholds) uses the validation
split only. The held-out test split is touched by ml/evaluate.py, never here.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import platform
import sys
from pathlib import Path

import joblib
import numpy as np
import scipy.sparse as sp
import sklearn
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.multiclass import OneVsRestClassifier

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from findings import ML_CATEGORIES  # noqa: E402
from ml.dataset import STATS_PATH, load_dataset  # noqa: E402
from ml.features import structure_tokens  # noqa: E402

MODEL_DIR = ROOT / "models"
MODEL_PATH = MODEL_DIR / "securecompile_ml.joblib"
META_PATH = MODEL_DIR / "securecompile_ml.json"
CANDIDATE_DIR = MODEL_DIR / "candidates"
FEATURE_SETS = ("text", "structure", "combined")
C_GRID = (1.0, 10.0)
THRESHOLD_GRID = np.round(np.arange(0.05, 0.951, 0.05), 2)
DEFAULT_THRESHOLD = 0.5


def label_matrix(samples):
    index = {c: i for i, c in enumerate(ML_CATEGORIES)}
    y = np.zeros((len(samples), len(ML_CATEGORIES)), dtype=np.int8)
    for row, s in enumerate(samples):
        for label in s["labels"]:
            y[row, index[label]] = 1
    return y


def make_vectorizers(feature_set):
    vectorizers = {}
    if feature_set in ("text", "combined"):
        vectorizers["text"] = TfidfVectorizer(token_pattern=r"\S+", lowercase=False, ngram_range=(1, 3),
                                              min_df=3, max_features=300_000, sublinear_tf=True,
                                              dtype=np.float32)
    if feature_set in ("structure", "combined"):
        vectorizers["structure"] = TfidfVectorizer(token_pattern=r"\S+", lowercase=False, ngram_range=(1, 4),
                                                   min_df=3, max_features=300_000, sublinear_tf=True,
                                                   dtype=np.float32)
    return vectorizers


def documents(samples, kind):
    if kind == "text":
        return [s["normalized"] for s in samples]
    return [structure_tokens(s["normalized"]) for s in samples]


def transform(vectorizers, samples, fit=False):
    parts = []
    for kind, vec in vectorizers.items():
        docs = documents(samples, kind)
        parts.append(vec.fit_transform(docs) if fit else vec.transform(docs))
    return sp.hstack(parts, format="csr") if len(parts) > 1 else parts[0]


def f1_scores(y_true, y_pred):
    tp = ((y_true == 1) & (y_pred == 1)).sum(axis=0)
    fp = ((y_true == 0) & (y_pred == 1)).sum(axis=0)
    fn = ((y_true == 1) & (y_pred == 0)).sum(axis=0)
    denom = 2 * tp + fp + fn
    return np.where(denom > 0, 2 * tp / np.maximum(denom, 1), 0.0)


def choose_thresholds(y_val, probs):
    """Per-category threshold maximising validation F1 (ties -> higher threshold)."""
    thresholds, notes = {}, {}
    for j, category in enumerate(ML_CATEGORIES):
        if y_val[:, j].sum() == 0:
            thresholds[category] = DEFAULT_THRESHOLD
            notes[category] = "no validation positives; default threshold used"
            continue
        best_t, best_f1 = DEFAULT_THRESHOLD, -1.0
        for t in THRESHOLD_GRID:
            pred = (probs[:, j] >= t).astype(np.int8)
            f1 = f1_scores(y_val[:, [j]], pred[:, None])[0]
            if f1 >= best_f1:
                best_t, best_f1 = float(t), float(f1)
        thresholds[category] = best_t
    return thresholds, notes


def apply_thresholds(probs, thresholds):
    return np.column_stack([(probs[:, j] >= thresholds[c]).astype(np.int8)
                            for j, c in enumerate(ML_CATEGORIES)])


def fit_candidate(feature_set, C, train, val, y_train, y_val, seed):
    vectorizers = make_vectorizers(feature_set)
    x_train = transform(vectorizers, train, fit=True)
    x_val = transform(vectorizers, val)
    clf = OneVsRestClassifier(
        LogisticRegression(C=C, solver="liblinear", class_weight="balanced", max_iter=200, random_state=seed))
    clf.fit(x_train, y_train)
    probs = clf.predict_proba(x_val)
    thresholds, notes = choose_thresholds(y_val, probs)
    pred = apply_thresholds(probs, thresholds)
    f1 = f1_scores(y_val, pred)
    return {
        "feature_set": feature_set, "C": C, "vectorizers": vectorizers, "classifier": clf,
        "thresholds": thresholds, "threshold_notes": notes,
        "validation_macro_f1": float(f1[y_val.sum(axis=0) > 0].mean()),
        "validation_f1_per_category": {c: float(f1[j]) for j, c in enumerate(ML_CATEGORIES)},
        "n_features": int(x_train.shape[1]),
    }


def sha256_of(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def bundle_for(candidate, extra):
    return {"labels": list(ML_CATEGORIES), "feature_set": candidate["feature_set"], "C": candidate["C"],
            "vectorizers": candidate["vectorizers"], "classifier": candidate["classifier"],
            "thresholds": candidate["thresholds"], **extra}


def main():
    cli = argparse.ArgumentParser()
    cli.add_argument("--seed", type=int, default=1337)
    args = cli.parse_args()

    rows = load_dataset()
    train = [s for s in rows if s["split"] == "train"]
    val = [s for s in rows if s["split"] == "validation"]
    y_train, y_val = label_matrix(train), label_matrix(val)
    print(f"train={len(train)} validation={len(val)} (test split is not used here)")

    candidates = []
    for feature_set in FEATURE_SETS:
        for C in C_GRID:
            cand = fit_candidate(feature_set, C, train, val, y_train, y_val, args.seed)
            print(f"  {feature_set:9s} C={C:<5} features={cand['n_features']:>7} "
                  f"validation macro-F1={cand['validation_macro_f1']:.4f}")
            candidates.append(cand)

    best = max(candidates, key=lambda c: c["validation_macro_f1"])
    print(f"Selected on validation: feature_set={best['feature_set']} C={best['C']}")

    extra = {
        "version": 1,
        "trained_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "sklearn_version": sklearn.__version__, "python_version": platform.python_version(),
        "seed": args.seed,
    }
    MODEL_DIR.mkdir(exist_ok=True)
    CANDIDATE_DIR.mkdir(exist_ok=True)
    for cand in candidates:
        joblib.dump(bundle_for(cand, extra), CANDIDATE_DIR / f"{cand['feature_set']}_C{cand['C']}.joblib", compress=3)
    joblib.dump(bundle_for(best, extra), MODEL_PATH, compress=3)

    dataset_stats = json.loads(STATS_PATH.read_text(encoding="utf-8")) if STATS_PATH.exists() else {}
    metadata = {
        "name": "securecompile-tfidf-logreg", "version": 1, "trained_at": extra["trained_at"],
        "labels": list(ML_CATEGORIES), "feature_set": best["feature_set"], "C": best["C"],
        "thresholds": best["thresholds"], "threshold_notes": best["threshold_notes"],
        "validation_macro_f1": best["validation_macro_f1"],
        "validation_f1_per_category": best["validation_f1_per_category"],
        "candidates": [{"feature_set": c["feature_set"], "C": c["C"],
                        "validation_macro_f1": c["validation_macro_f1"]} for c in candidates],
        "dataset": {"name": "NIST Juliet C/C++ 1.3 (function level)", "source": dataset_stats.get("source"),
                    "license": "Public domain / CC0 for foreign rights, per NIST SARD",
                    "split_seed": dataset_stats.get("split_seed"),
                    "train_samples": len(train), "validation_samples": len(val)},
        "sklearn_version": sklearn.__version__, "python_version": platform.python_version(),
        "model_sha256": sha256_of(MODEL_PATH),
        "caveat": ("Trained on synthetic, templated Juliet functions. Performance on real-world code is not "
                   "established by this model's reported metrics."),
    }
    META_PATH.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    print(f"Saved {MODEL_PATH} and {META_PATH}")


if __name__ == "__main__":
    main()
