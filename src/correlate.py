"""Correlation of rule-based findings with ML predictions.

Rules and the ML model are never merged into one score. A rule finding and an ML
prediction in the same category (and the same function, when the model gave a
function scope) are shown as agreeing; otherwise the disagreement is surfaced for
human review. ML confidence is only attached to ML-originated findings.
"""
from __future__ import annotations

from findings import CATEGORIES, ml_finding


def _in_scope(finding, scope):
    line = finding.get("line")
    if scope.get("start_line") is None or line is None:
        return True
    return scope["start_line"] <= line <= scope["end_line"]


def correlate(rule_findings, ml_result, parse_status="complete"):
    """Return (all_findings, disagreements). Mutates ``review`` on rule findings."""
    disagreements = []
    if not ml_result or ml_result.get("status") != "ok":
        return list(rule_findings), disagreements

    scopes = ml_result.get("scopes", [])
    thresholds = ml_result.get("thresholds", {})
    ml_cats = set(thresholds)
    out = list(rule_findings)
    agreed_ids = set()

    for scope in scopes:
        for category in scope.get("predicted", []):
            probability = scope["probabilities"][category]
            matches = [f for f in rule_findings
                       if f["category"] == category and _in_scope(f, scope)]
            if matches:
                for f in matches:
                    agreed_ids.add(f["id"])
                    f["review"] = {
                        "status": "agreement",
                        "note": "The ML model also flagged this weakness class in the same code region.",
                    }
                continue
            finding = ml_finding(category, probability, thresholds.get(category, 0.5), scope, parse_status)
            finding["review"] = {
                "status": "ml-only",
                "note": "Only the ML model flagged this category; no rule produced evidence. "
                        "Treat it as a lead to review, not a confirmed issue.",
            }
            out.append(finding)
            disagreements.append({"kind": "ml-only", "category": category, "finding_id": finding["id"],
                                  "note": finding["review"]["note"]})

    for f in rule_findings:
        if f["category"] not in ml_cats or f["id"] in agreed_ids:
            continue
        f["review"] = {
            "status": "rule-only",
            "note": "A rule fired but the ML model did not flag this category in this region. "
                    "Neither engine is treated as authoritative; review the evidence.",
        }
        disagreements.append({"kind": "rule-only", "category": f["category"], "finding_id": f["id"],
                              "note": f["review"]["note"]})
    return out, disagreements
