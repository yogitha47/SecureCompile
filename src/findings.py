"""Unified finding schema shared by every SecureCompile analysis engine.

Engines: ``ast-rule`` (PLY AST analyzer), ``source-rule`` (text-pattern checks),
``ml`` (trained classifier), ``compiler`` (optional gcc/clang diagnostics) and
``parser`` (syntax diagnostics, kept in a separate list from security findings).
"""
from __future__ import annotations

import hashlib

# Canonical categories. ``ml`` marks categories the trained classifier can predict.
CATEGORIES = {
    "buffer-overflow": {"title": "Buffer overflow / unbounded write", "severity": "HIGH", "ml": True},
    "format-string": {"title": "Format string vulnerability", "severity": "HIGH", "ml": True},
    "integer-overflow": {"title": "Integer overflow", "severity": "MEDIUM", "ml": True},
    "divide-by-zero": {"title": "Division or modulo by zero", "severity": "HIGH", "ml": True},
    "null-pointer-dereference": {"title": "Null pointer dereference", "severity": "HIGH", "ml": True},
    "double-free": {"title": "Double free", "severity": "HIGH", "ml": True},
    "use-after-free": {"title": "Use after free", "severity": "HIGH", "ml": True},
    "memory-leak": {"title": "Memory leak", "severity": "MEDIUM", "ml": True},
    "uninitialized-variable": {"title": "Uninitialized variable", "severity": "HIGH", "ml": True},
    "command-injection": {"title": "Command execution risk", "severity": "MEDIUM", "ml": True},
    "invalid-free": {"title": "Free of non-heap or unallocated pointer", "severity": "HIGH", "ml": True},
    "invalid-array-access": {"title": "Invalid array access", "severity": "HIGH", "ml": False},
    "weak-randomness": {"title": "Predictable pseudorandom sequence", "severity": "LOW", "ml": False},
    "logic": {"title": "Logic / code-quality issue", "severity": "LOW", "ml": False},
}
ML_CATEGORIES = [name for name, meta in CATEGORIES.items() if meta["ml"]]

# rule id -> (category, CWE id or None)
RULES = {
    "SC-MEM-001": ("buffer-overflow", "CWE-242"),
    "SC-MEM-002": ("buffer-overflow", "CWE-120"),
    "SC-MEM-003": ("buffer-overflow", "CWE-120"),
    "SC-MEM-004": ("buffer-overflow", "CWE-120"),
    "SC-INPUT-001": ("buffer-overflow", "CWE-120"),
    "SC-INPUT-002": ("format-string", "CWE-134"),
    "SC-CMD-001": ("command-injection", "CWE-78"),
    "SC-ARITH-001": ("divide-by-zero", "CWE-369"),
    "SC-ARITH-002": ("divide-by-zero", "CWE-369"),
    "SC-ARITH-003": ("integer-overflow", "CWE-190"),
    "SC-DATA-001": ("uninitialized-variable", "CWE-457"),
    "SC-MEM-005": ("invalid-array-access", None),
    "SC-MEM-006": ("invalid-free", "CWE-590"),
    "SC-MEM-007": ("null-pointer-dereference", "CWE-476"),
    "SC-MEM-008": ("double-free", "CWE-415"),
    "SC-MEM-009": ("use-after-free", "CWE-416"),
    "SC-MEM-010": ("memory-leak", "CWE-401"),
    "SC-RAND-001": ("weak-randomness", "CWE-338"),
    "SC-LOGIC-001": ("logic", "CWE-570"),
    "SC-LOGIC-002": ("logic", "CWE-835"),
    "SC-LOGIC-003": ("logic", "CWE-561"),
    "SC-LOGIC-004": ("logic", "CWE-484"),
}
# Reported by the text-pattern engine but they describe syntax, not security.
SYNTAX_RULES = {"SC-SYN-001", "SC-PP-001"}

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
UNCERTAINTY_ORDER = ["low", "medium", "high"]


def category_for_rule(rule_id):
    return RULES.get(rule_id, ("logic", None))


def finding_id(rule_id, category, line, offset):
    raw = f"{rule_id}|{category}|{line}|{offset}".encode()
    return "f-" + hashlib.sha1(raw).hexdigest()[:10]


def source_line(source_lines, line):
    if not line or line < 1 or line > len(source_lines):
        return ""
    return source_lines[line - 1].strip()[:240]


def column_for(source, offset):
    if offset is None:
        return None
    return offset - (source.rfind("\n", 0, offset) + 1) + 1


def bump(level, steps=1):
    index = min(UNCERTAINTY_ORDER.index(level) + steps, len(UNCERTAINTY_ORDER) - 1)
    return UNCERTAINTY_ORDER[index]


def rule_finding(raw, engine, source, source_lines, parse_status, parse_error_count):
    """Wrap an engine-specific rule dict in the unified schema."""
    rule_id = raw.get("rule_id")
    category, cwe = category_for_rule(rule_id)
    line = raw.get("line")
    offset = raw.get("offset")
    column = column_for(source, offset)
    support = "exact" if offset is not None else ("line" if line else "none")

    confidence = (raw.get("confidence") or "MEDIUM").upper()
    level = {"HIGH": "low", "MEDIUM": "medium", "LOW": "high"}.get(confidence, "medium")
    reasons = []
    if engine == "source-rule":
        reasons.append("Text-pattern match; not path-sensitive and does not model aliases.")
    else:
        reasons.append("Matched on the restricted-C AST; only the supported C subset is modelled.")
    if parse_status != "complete":
        level = bump(level)
        reasons.append(
            f"Parsing was incomplete ({parse_error_count} syntax diagnostic(s)); "
            "evidence may come from partly unparsed source."
        )
    return {
        "id": finding_id(rule_id, category, line, offset),
        "rule_id": rule_id,
        "category": category,
        "cwe": cwe,
        "type": raw.get("type") or CATEGORIES[category]["title"],
        "title": raw.get("type") or CATEGORIES[category]["title"],
        "severity": raw.get("severity", "MEDIUM"),
        "confidence": confidence,
        "message": raw.get("message", ""),
        "explanation": raw.get("explanation", ""),
        "suggestion": raw.get("suggestion", ""),
        "line": line,
        "evidence": {"line": line, "snippet": source_line(source_lines, line)},
        "location": {"line": line, "column": column, "offset": offset, "support": support},
        "origin": "rule",
        "engines": [engine],
        "engine_reports": [{"engine": engine, "confidence": confidence, "message": raw.get("message", "")}],
        "ml_confidence": None,
        "uncertainty": {"level": level, "reasons": reasons},
        "review": None,
    }


def merge_findings(primary, other):
    """Fold ``other`` (same underlying issue from a second engine) into ``primary``."""
    for engine in other["engines"]:
        if engine not in primary["engines"]:
            primary["engines"].append(engine)
    primary["engine_reports"].extend(other["engine_reports"])
    if primary["location"]["offset"] is None and other["location"]["offset"] is not None:
        primary["location"] = other["location"]
    if len(primary["engines"]) > 1:
        # Two independent engines agreeing lowers uncertainty by one step.
        steps = UNCERTAINTY_ORDER.index(primary["uncertainty"]["level"])
        primary["uncertainty"]["level"] = UNCERTAINTY_ORDER[max(steps - 1, 0)]
        primary["uncertainty"]["reasons"].append("Reported by more than one engine.")
    return primary


def ml_finding(category, probability, threshold, scope, parse_status):
    meta = CATEGORIES[category]
    reasons = [
        "Statistical prediction; there is no rule evidence for this category.",
        f"Prediction scope: {scope['kind']}"
        + (f" '{scope['name']}'" if scope.get("name") else "")
        + (f" (lines {scope['start_line']}-{scope['end_line']})" if scope.get("start_line") else "")
        + ".",
    ]
    return {
        "id": finding_id("ML", category, scope.get("start_line"), scope.get("name")),
        "rule_id": None,
        "category": category,
        "cwe": None,
        "type": meta["title"] + " (ML prediction)",
        "title": meta["title"] + " (ML prediction)",
        "severity": meta["severity"] if probability >= 0.9 else "LOW",
        "confidence": None,
        "message": f"The ML model flagged this {scope['kind']} as possibly containing: {meta['title'].lower()}.",
        "explanation": (
            "A TF-IDF/logistic-regression model trained on labelled C functions scored this code above its "
            "validation-selected threshold for this category. It does not point to a specific line and can be wrong; "
            "review the code or compare with the rule-based findings."
        ),
        "suggestion": "Inspect the highlighted function for this weakness class and confirm or dismiss the prediction.",
        "line": scope.get("start_line"),
        "evidence": {"line": scope.get("start_line"), "snippet": scope.get("signature", "")},
        "location": {"line": scope.get("start_line"), "column": None, "offset": None,
                     "support": "function" if scope.get("start_line") else "none"},
        "origin": "ml",
        "engines": ["ml"],
        "engine_reports": [{"engine": "ml", "confidence": round(float(probability), 4), "message": "model probability"}],
        "ml_confidence": round(float(probability), 4),
        "ml_threshold": round(float(threshold), 4),
        "uncertainty": {"level": "high" if probability < 0.9 else "medium", "reasons": reasons},
        "review": None,
    }
