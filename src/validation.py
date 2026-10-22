"""Post-fix validation: only checks that actually ran are reported, never assumed.

Overall status
  Failed             - a check that ran found a problem introduced or left by the patch
  Unable to verify   - the checks needed to confirm the patch could not run, or compiler
                       errors remain in the proposed code
  Passed             - parser, compiler (ran, zero errors) and fresh rule scan all passed

Validation is evidence, not a guarantee: the submitted program is never executed, so
behavioural regressions cannot be detected.
"""
from __future__ import annotations

import collections

import pipeline
from compiler import compile_check

PASSED, FAILED, UNABLE = "Passed", "Failed", "Unable to verify"


def _check(check_id, name, status, detail, **extra):
    return {"id": check_id, "name": name, "status": status, "detail": detail, **extra}


def _rule_scan(source):
    try:
        return pipeline.analyze(source, use_compiler=False, use_ml=False), None
    except pipeline.AnalysisInputError as exc:
        return None, str(exc)


def _counts(findings):
    return collections.Counter(f["rule_id"] for f in findings if f.get("rule_id"))


def validate_patch(original: str, proposed: str, target_rules=None, use_ml=True) -> dict:
    """Validate ``proposed`` against ``original``. ``target_rules`` maps rule id -> expected reduction."""
    target_rules = dict(target_rules or {})
    checks, warnings = [], []

    before, error = _rule_scan(original)
    after, after_error = _rule_scan(proposed)
    if before is None or after is None:
        checks.append(_check("rescan", "Fresh security scan", "failed",
                             f"Scan could not run: {error or after_error}"))
        return _result(checks, [], [], warnings)

    # 1. Parser / syntax recovery
    n_before, n_after = len(before["syntax_diagnostics"]), len(after["syntax_diagnostics"])
    parse_status = "passed" if n_after <= n_before and not (
        after["parse"]["status"] == "failed" and before["parse"]["status"] != "failed") else "failed"
    checks.append(_check("parser", "Restricted-C parser and syntax diagnostics", parse_status,
                         f"Syntax diagnostics: {n_before} before, {n_after} after "
                         f"(parse status {before['parse']['status']} -> {after['parse']['status']}).",
                         ran=True))

    # 2. Compiler
    comp_before, comp_after = compile_check(original), compile_check(proposed)
    compiler_ok_to_judge = comp_before.get("ran") and comp_after.get("ran")
    if not compiler_ok_to_judge:
        checks.append(_check("compiler", "Compiler syntax check", "skipped",
                             comp_after.get("note") or comp_before.get("note") or "Compiler did not run.", ran=False))
    else:
        old_errors = {d["message"] for d in comp_before["diagnostics"] if d["severity"] == "error"}
        new_errors = [d for d in comp_after["diagnostics"] if d["severity"] == "error" and d["message"] not in old_errors]
        old_warn = {d["message"] for d in comp_before["diagnostics"] if d["severity"] == "warning"}
        new_warn = [d for d in comp_after["diagnostics"] if d["severity"] == "warning" and d["message"] not in old_warn]
        name = comp_after["compiler"]
        if new_errors or comp_after["error_count"] > comp_before["error_count"]:
            status = "failed"
            detail = (f"{name} -fsyntax-only reports {comp_after['error_count']} error(s) after the patch "
                      f"(was {comp_before['error_count']}); new: " + "; ".join(d["message"] for d in new_errors[:3]))
        elif comp_after["error_count"] == 0:
            status = "passed"
            detail = f"{name} -fsyntax-only: 0 errors after the patch (was {comp_before['error_count']})."
        else:
            status = "warning"
            detail = (f"{name} -fsyntax-only still reports {comp_after['error_count']} error(s) after the patch "
                      f"(was {comp_before['error_count']}); none are new, but the program does not compile yet.")
        if new_warn:
            warnings.append(f"{len(new_warn)} new compiler warning(s): " + "; ".join(d["message"] for d in new_warn[:3]))
        checks.append(_check("compiler", "Compiler syntax check", status, detail, ran=True,
                             warnings_before=comp_before["warning_count"], warnings_after=comp_after["warning_count"]))

    # 3. Fresh rule scan
    b_counts, a_counts = _counts(before["findings"]), _counts(after["findings"])
    new_rules = {r: a_counts[r] - b_counts.get(r, 0) for r in a_counts if a_counts[r] > b_counts.get(r, 0)}
    unresolved = {r: n for r, n in target_rules.items() if b_counts.get(r, 0) - a_counts.get(r, 0) < n}
    resolved = {r: b_counts.get(r, 0) - a_counts.get(r, 0) for r in b_counts if b_counts[r] > a_counts.get(r, 0)}
    new_findings = [f for f in after["findings"] if f.get("rule_id") in new_rules]
    if new_rules:
        status, detail = "failed", "The patch introduced new findings: " + ", ".join(f"{r} (+{n})" for r, n in new_rules.items()) + "."
    elif unresolved:
        status, detail = "failed", "The targeted finding(s) are still reported after the patch: " + ", ".join(sorted(unresolved)) + "."
    else:
        status = "passed"
        detail = ("Rule findings by id (before -> after): " +
                  (", ".join(f"{r} {b_counts[r]}->{a_counts.get(r, 0)}" for r in sorted(b_counts)) or "none") + ".")
    checks.append(_check("rescan", "Fresh security scan (rule engines)", status, detail, ran=True,
                         total_before=len(before["findings"]), total_after=len(after["findings"])))

    # 4. ML re-scan (advisory)
    if use_ml:
        ml_before, ml_after = _ml_categories(original), _ml_categories(proposed)
        if ml_before is None or ml_after is None:
            checks.append(_check("ml", "ML re-scan", "skipped", "ML model unavailable; no ML re-scan was run.", ran=False))
        else:
            added = sorted(ml_after - ml_before)
            if added:
                warnings.append("ML newly flags: " + ", ".join(added))
            checks.append(_check("ml", "ML re-scan (advisory)", "warning" if added else "passed",
                                 ("New ML categories after the patch: " + ", ".join(added)) if added
                                 else "No new ML-predicted categories.", ran=True))

    # 5. Regression tests
    checks.append(_check("regression", "Regression tests", "skipped",
                         "No tests exist for the submitted program and it is never executed, so behavioural "
                         "regressions cannot be detected here.", ran=False))
    return _result(checks, new_findings, [r for r in resolved], warnings)


def _ml_categories(source):
    try:
        from ml import infer
        result = infer.predict_source(source)
    except Exception:
        return None
    if result.get("status") != "ok":
        return None
    return {c for scope in result["scopes"] for c in scope["predicted"]}


def _result(checks, new_findings, resolved_rules, warnings):
    statuses = {c["id"]: c["status"] for c in checks}
    if "failed" in statuses.values():
        overall = FAILED
    elif statuses.get("compiler") in ("skipped", "warning", None) or statuses.get("rescan") != "passed":
        overall = UNABLE
    else:
        overall = PASSED
    ran = [c["name"] for c in checks if c.get("ran", True) and c["status"] != "skipped"]
    skipped = [c["name"] for c in checks if c["status"] == "skipped"]
    return {
        "status": overall,
        "checks": checks,
        "checks_run": ran,
        "checks_not_run": skipped,
        "new_findings": [{"rule_id": f["rule_id"], "line": f["line"], "message": f["message"], "severity": f["severity"]}
                         for f in new_findings],
        "resolved_rules": resolved_rules,
        "warnings": warnings,
        "disclaimer": "Validation is evidence, not a guarantee of correctness or security.",
    }
