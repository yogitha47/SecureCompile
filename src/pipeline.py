"""SecureCompile analysis pipeline: parse -> rules -> compiler -> ML -> correlation."""
from __future__ import annotations

import hashlib
import re

from compiler import compile_check
from correlate import correlate
from findings import (
    SEVERITY_ORDER,
    SYNTAX_RULES,
    merge_findings,
    rule_finding,
)
from parser import parse_with_recovery
from security_analyzer import SecurityAnalyzer
from semantic import SemanticAnalyzer
from source_analyzer import analyze_source

try:  # ML is optional; the app must keep working without a trained model.
    from ml import infer as ml_infer
except Exception as _exc:  # pragma: no cover - import problems are reported at run time
    ml_infer = None
    _ML_IMPORT_ERROR = f"{type(_exc).__name__}: {_exc}"
else:
    _ML_IMPORT_ERROR = None

MAX_SOURCE_CHARS = 100_000


class AnalysisInputError(ValueError):
    """Raised for input that cannot be analysed (empty, too large, wrong type)."""


def validate_source(source):
    if not isinstance(source, str):
        raise AnalysisInputError("Source must be text.")
    if "\x00" in source:
        raise AnalysisInputError("Source contains NUL bytes; this does not look like C source text.")
    if not source.strip():
        raise AnalysisInputError("Paste or upload a C program first.")
    if len(source) > MAX_SOURCE_CHARS:
        raise AnalysisInputError(f"Please keep source code under {MAX_SOURCE_CHARS:,} characters.")


def build_memory_summary(source: str):
    """Intentionally approximate pointer/lifetime overview from source text."""
    code = re.sub(r"/\*.*?\*/|//[^\n]*", " ", source, flags=re.S)
    entries = []
    pattern = re.compile(r"\b(?:char|short|int|long|float|double|void|struct\s+\w+)\s*\*\s*(\w+)\s*(?:=\s*([^;]+))?;")
    for match in pattern.finditer(code):
        name, init = match.group(1), (match.group(2) or "").strip()
        state = "uninitialized pointer"
        target = "unknown address"
        if re.search(r"\b(?:malloc|calloc|realloc)\s*\(", init):
            state, target = "heap allocation (visible)", "heap block"
        elif re.search(r"\bNULL\b|^0$", init):
            state, target = "null pointer", "no object"
        elif init:
            state, target = "initialized pointer (target unknown)", init[:80]
        frees = list(re.finditer(rf"\bfree\s*\(\s*{re.escape(name)}\s*\)", code))
        allocation_visible = bool(re.search(rf"\b{re.escape(name)}\s*=\s*(?:\([^;]*?\)\s*)?(?:malloc|calloc|realloc)\s*\(", code))
        if allocation_visible:
            state, target = "heap allocation (visible)", "heap block"
            if frees:
                state, target = "allocation and free both visible", "heap block released in source"
        elif frees and state == "uninitialized pointer":
            state, target = "uninitialized pointer passed to free", "unknown address (unsafe to free)"
        elif frees and state == "null pointer":
            state, target = "NULL passed to free (safe no-op)", "no object"
        elif frees:
            state, target = "free call visible; ownership unclear", "target needs manual review"
        entries.append({"name": name, "state": state, "target": target,
                        "decl_line": source.count("\n", 0, match.start()) + 1})
        if len(entries) >= 30:
            break
    return entries


def _unify_rule_findings(ast_findings, source_findings, source, parse):
    lines = source.splitlines()
    status = parse["status"]
    count = len(parse["diagnostics"])
    unified = []
    by_key = {}
    for raw in source_findings:
        f = rule_finding(raw, "source-rule", source, lines, status, count)
        unified.append(f)
        by_key.setdefault((f["rule_id"], f["line"]), []).append(f)
    for raw in ast_findings:
        f = rule_finding(raw, "ast-rule", source, lines, status, count)
        existing = by_key.get((f["rule_id"], f["line"]))
        if existing:
            # Same rule on the same line from both engines: one underlying issue.
            merge_findings(existing[0], f)
        else:
            unified.append(f)
            by_key.setdefault((f["rule_id"], f["line"]), []).append(f)
    return unified


def _classify_parser_diagnostics(parse, compiler):
    """Say whether a parser complaint is a real syntax error or an unsupported construct."""
    compiler_ran = compiler.get("ran")
    for diag in parse["diagnostics"]:
        if diag["kind"] != "syntax":
            diag["classification"] = diag["kind"]
        elif compiler_ran and compiler.get("error_count", 0) == 0:
            diag["classification"] = "unsupported-construct"
            diag["note"] = (f"{compiler['compiler']} accepts this source, so SecureCompile's restricted "
                            "grammar does not cover this construct (not a user syntax error).")
        elif compiler_ran:
            diag["classification"] = "syntax-error"
            diag["note"] = f"{compiler['compiler']} also reports errors in this source."
        else:
            diag["classification"] = "unverified"
            diag["note"] = ("No compiler ran, so a genuine syntax error cannot be told apart from "
                            "a construct outside the restricted grammar.")


def analyze(source, *, use_compiler=True, use_ml=True):
    """Analyse ``source`` and return the full result dict. Raises AnalysisInputError."""
    validate_source(source)
    notes = []

    parse = parse_with_recovery(source)
    ast = parse["ast"]

    ast_findings = []
    if ast is not None:
        try:
            ast_findings = SecurityAnalyzer().analyze(ast)
        except Exception as exc:  # defensive: a rule bug must not break the request
            notes.append(f"AST security analysis failed ({type(exc).__name__}); text-pattern checks still ran.")

    source_all = analyze_source(source)
    source_findings = [f for f in source_all if f["rule_id"] not in SYNTAX_RULES]
    source_syntax = [f for f in source_all if f["rule_id"] in SYNTAX_RULES]

    rule_findings = _unify_rule_findings(ast_findings, source_findings, source, parse)

    compiler = compile_check(source) if use_compiler else {
        "available": False, "ran": False, "compiler": None, "diagnostics": [],
        "error_count": 0, "warning_count": 0, "note": "Compiler check was disabled for this run."}
    _classify_parser_diagnostics(parse, compiler)

    syntax_diagnostics = list(parse["diagnostics"])
    for f in source_syntax:
        syntax_diagnostics.append({
            "kind": "syntax", "severity": "error", "line": f["line"], "column": None, "offset": f.get("offset"),
            "message": f["message"], "expected": [], "found": None, "recovery": "none",
            "engine": "source-fallback", "classification": "delimiter-check",
            "note": f["explanation"]})
    for d in syntax_diagnostics:
        d.setdefault("engine", "parser")

    semantic_diagnostics = []
    if ast is not None and parse["status"] == "complete":
        try:
            for message in SemanticAnalyzer().analyze(ast):
                semantic_diagnostics.append({"kind": "semantic", "severity": "warning", "line": None,
                                             "message": message, "engine": "semantic"})
        except Exception as exc:
            notes.append(f"Semantic analysis failed ({type(exc).__name__}).")

    ml_result = {"status": "disabled", "message": "ML analysis was disabled for this run."}
    if use_ml:
        if ml_infer is None:
            ml_result = {"status": "error", "message": f"ML module could not be imported: {_ML_IMPORT_ERROR}"}
        else:
            try:
                ml_result = ml_infer.predict_source(source)
            except Exception as exc:  # inference failures must never crash the app
                ml_result = {"status": "error", "message": f"ML inference failed ({type(exc).__name__})."}

    findings, disagreements = correlate(rule_findings, ml_result, parse["status"])
    findings.sort(key=lambda f: (f["line"] or 0, SEVERITY_ORDER.get(f["severity"], 3), f["id"]))

    counts = {sev: sum(f["severity"] == sev for f in findings) for sev in ("HIGH", "MEDIUM", "LOW")}
    if parse["status"] == "complete":
        mode = "restricted AST + text-pattern checks"
    elif parse["status"] == "recovered":
        mode = "restricted AST (recovered) + text-pattern checks"
    else:
        mode = "text-pattern checks only (parse failed)"

    return {
        "ok": True,
        "source_sha256": hashlib.sha256(source.encode("utf-8")).hexdigest(),
        "findings": findings,
        "total": len(findings),
        "counts": counts,
        "syntax_diagnostics": syntax_diagnostics,
        "semantic_diagnostics": semantic_diagnostics,
        "syntax_repairs": parse["repairs"],
        "parse": {"status": parse["status"], "diagnostic_count": len(parse["diagnostics"]),
                  "truncated": parse["truncated"]},
        "analysis_mode": mode,
        "analysis_note": (
            None if parse["status"] == "complete" else
            "Parsing was incomplete: syntax diagnostics are listed separately and findings from unparsed "
            "regions are marked with higher uncertainty."),
        "notes": notes,
        "compiler": compiler,
        "ml": ml_result,
        "disagreements": disagreements,
        "memory_model": build_memory_summary(source),
    }
