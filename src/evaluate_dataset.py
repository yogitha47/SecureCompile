r"""Run SecureCompile's labelled evaluation snippets and report basic metrics.

Run from project root:
    .\venv\Scripts\python.exe src\evaluate_dataset.py

The dataset contains restricted-C snippets, not necessarily complete C programs.
"""
from __future__ import annotations
import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from lexer import lexer
from parser import parser
from security_analyzer import SecurityAnalyzer

MANIFEST_PATH = ROOT / "evaluation" / "manifest.json"
REPORT_DIR = ROOT / "reports"
REPORT_DIR.mkdir(parents=True, exist_ok=True)

def analyze(source: str):
    lexer.lineno = 1
    ast = parser.parse(source, lexer=lexer)
    if ast is None:
        return None
    return SecurityAnalyzer().analyze(ast)

def safe_ratio(numerator: int, denominator: int):
    return round(numerator / denominator, 4) if denominator else None

def main():
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    rows = []
    parse_errors = 0
    exact_rule_passes = 0
    vulnerable_total = 0
    safe_total = 0
    tp = fp = tn = fn = 0

    print("\nSecureCompile - Dataset Evaluation")
    print("=" * 45)
    for case in manifest["cases"]:
        path = ROOT / case["file"]
        source = path.read_text(encoding="utf-8")
        try:
            findings = analyze(source)
        except Exception as exc:
            findings = None
            error = f"{type(exc).__name__}: {exc}"
        else:
            error = None

        if findings is None:
            parse_errors += 1
            rows.append({
                "id": case["id"], "label": case["label"],
                "expected_rule_id": case["expected_rule_id"],
                "expected_type": case["expected_type"],
                "status": "PARSE_ERROR", "expected_rule_detected": False,
                "finding_count": 0, "finding_types": "", "error": error or "Parser returned no AST"
            })
            print(f"PARSE ERROR: {case['id']}")
            continue

        expected_positive = case["label"] == "vulnerable"
        predicted_positive = len(findings) > 0
        expected_rule = case["expected_rule_id"]
        exact_match = (not expected_positive and not findings) or any(
            finding.get("rule_id") == expected_rule for finding in findings
        )
        if exact_match:
            exact_rule_passes += 1

        if expected_positive:
            vulnerable_total += 1
            if predicted_positive: tp += 1
            else: fn += 1
        else:
            safe_total += 1
            if predicted_positive: fp += 1
            else: tn += 1

        row = {
            "id": case["id"], "label": case["label"],
            "expected_rule_id": expected_rule,
            "expected_type": case["expected_type"],
            "status": "ANALYZED",
            "expected_rule_detected": bool(exact_match),
            "finding_count": len(findings),
            "finding_types": "; ".join(f.get("type", "Unknown") for f in findings),
            "finding_rule_ids": "; ".join(f.get("rule_id", "") for f in findings),
            "lines": "; ".join(str(f.get("line")) for f in findings),
            "error": ""
        }
        rows.append(row)
        marker = "PASS" if exact_match else "CHECK"
        print(f"{marker}: {case['id']} | expected={expected_rule or 'no findings'} | actual={row['finding_types'] or 'no findings'}")

    analyzed = len(rows) - parse_errors
    metrics = {
        "true_positive": tp, "false_positive": fp,
        "true_negative": tn, "false_negative": fn,
        "precision": safe_ratio(tp, tp + fp),
        "recall": safe_ratio(tp, tp + fn),
        "specificity": safe_ratio(tn, tn + fp),
        "accuracy": safe_ratio(tp + tn, tp + tn + fp + fn),
        "exact_rule_or_safe_case_passes": exact_rule_passes,
        "analyzed_cases": analyzed, "total_cases": len(manifest["cases"]),
        "parse_errors": parse_errors,
        "vulnerable_cases": vulnerable_total, "safe_cases": safe_total,
        "metric_note": "Metrics are case-level results on this small hand-labelled dataset. They are not evidence of performance on arbitrary C programs."
    }
    report = {"project": "SecureCompile", "dataset": manifest.get("dataset_version"), "metrics": metrics, "results": rows}
    json_path = REPORT_DIR / "evaluation_report.json"
    csv_path = REPORT_DIR / "evaluation_results.csv"
    json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()) if rows else ["id"])
        writer.writeheader()
        writer.writerows(rows)

    print("\nMetrics (case-level, any finding vs no finding)")
    print("-" * 45)
    for key in ("true_positive", "false_positive", "true_negative", "false_negative", "precision", "recall", "specificity", "accuracy", "parse_errors"):
        print(f"{key}: {metrics[key]}")
    print(f"\nJSON report: {json_path}")
    print(f"CSV report:  {csv_path}")
    print("Review every CHECK and PARSE ERROR before using these numbers in a report.")

if __name__ == "__main__":
    main()
