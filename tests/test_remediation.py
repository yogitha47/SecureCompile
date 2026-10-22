"""Code-correction workflow: individual fixes, full-program correction, validation."""
import fixer
import pipeline
import remediation as rem
import validation
import pytest


def analyze(src):
    return pipeline.analyze(src, use_compiler=False, use_ml=False)


def finding_id(src, rule_id):
    return next(f["id"] for f in analyze(src)["findings"] if f["rule_id"] == rule_id)


PROGRAM = """#include <stdio.h>
#include <string.h>
int main(void) {
    char buf[8];
    char name[16];
    char w[10];
    gets(buf);
    strcpy(name, buf);
    scanf("%s", w);
    sprintf(w, "%d", 5);
    printf(name);
    return 0;
}
"""


@pytest.mark.parametrize("rule_id, expected", [
    ("SC-MEM-001", "fgets(buf, sizeof(buf), stdin);"),
    ("SC-MEM-002", 'snprintf(name, sizeof(name), "%s", buf);'),
    ("SC-INPUT-001", 'scanf("%9s", w);'),
    ("SC-MEM-004", 'snprintf(w, sizeof(w), "%d", 5);'),
    ("SC-INPUT-002", 'printf("%s", name);'),
])
def test_individual_fix_produces_expected_replacement(rule_id, expected):
    result = fixer.fix_finding(PROGRAM, finding_id(PROGRAM, rule_id))
    assert result["changed"] and expected in result["proposed_source"]
    assert result["assumptions"], "every automatic fix must state its assumptions"
    assert result["diff"].startswith("--- original.c")
    assert result["changes"][0]["explanation"]


def test_individual_fix_leaves_other_findings_untouched():
    result = fixer.fix_finding(PROGRAM, finding_id(PROGRAM, "SC-MEM-001"))
    assert "strcpy(name, buf);" in result["proposed_source"]
    assert "gets(buf)" not in result["proposed_source"]


def test_original_source_is_preserved_and_hashes_reported():
    original = str(PROGRAM)
    result = fixer.fix_finding(PROGRAM, finding_id(PROGRAM, "SC-MEM-001"))
    full = fixer.generate_corrected(PROGRAM)
    assert PROGRAM == original
    assert result["original_sha256"] == rem.sha256(original)
    assert full["original_sha256"] == rem.sha256(original)
    assert result["proposed_sha256"] != result["original_sha256"]


def test_full_program_correction_handles_multiple_findings_and_validates():
    result = fixer.generate_corrected(PROGRAM)
    assert result["changed"]
    fixed_rules = {i["rule_id"] for i in result["items"] if i["status"] == "fixed"}
    assert {"SC-MEM-001", "SC-MEM-002", "SC-INPUT-001", "SC-MEM-004", "SC-INPUT-002"} <= fixed_rules
    checks = {c["id"]: c for c in result["validation"]["checks"]}
    assert checks["parser"]["status"] == "passed"
    assert checks["rescan"]["status"] == "passed"
    assert checks["regression"]["status"] == "skipped"
    assert result["validation"]["status"] in {"Passed", "Unable to verify"}  # depends on a compiler being installed
    re_scan = analyze(result["proposed_source"])
    assert not {f["rule_id"] for f in re_scan["findings"]} & {"SC-MEM-001", "SC-MEM-002", "SC-INPUT-001", "SC-MEM-004", "SC-INPUT-002"}


def test_full_correction_also_repairs_missing_semicolons_as_a_proposal():
    src = "int main(void) {\n int x = 5\n return x;\n}\n"
    result = fixer.generate_corrected(src)
    assert result["changed"] and "int x = 5;" in result["proposed_source"]
    assert src.count(";") == 1  # original untouched
    assert any(i["rule_id"] == "SYNTAX" for i in result["items"])


def test_review_required_findings_are_not_changed_and_explain_why():
    src = "int main(void){ int d = 0; return 10 / d; }"
    fid = finding_id(src, "SC-ARITH-001")
    result = fixer.fix_finding(src, fid)
    assert result["changed"] is False and result["proposed_source"] == src
    item = result["items"][0]
    assert item["status"] == "review-required"
    assert "program decision" in item["reason"] and "if (divisor != 0)" in item["guidance_snippet"]


def test_unknown_buffer_size_is_review_required_not_guessed():
    src = "void f(char *dst) { gets(dst); }"
    result = fixer.fix_finding(src, finding_id(src, "SC-MEM-001"))
    assert result["changed"] is False
    assert result["items"][0]["status"] == "review-required"


def test_function_parameter_array_is_not_assumed_to_have_a_known_size():
    src = "void f(char dst[32]) { gets(dst); }"
    result = fixer.fix_finding(src, finding_id(src, "SC-MEM-001"))
    assert result["changed"] is False


def test_ml_only_findings_cannot_drive_a_repair():
    ml_finding = {"id": "f-ml", "origin": "ml", "rule_id": None, "category": "double-free", "line": 3}
    proposal = rem.propose_fix("int main(){return 0;}", ml_finding)
    assert proposal.kind == rem.UNAVAILABLE and "ML" in proposal.reason


def test_unknown_finding_id_raises():
    with pytest.raises(fixer.FixError):
        fixer.fix_finding(PROGRAM, "f-does-not-exist")


def test_nothing_to_fix_returns_unchanged_source():
    src = "int main(void){ return 0; }"
    result = fixer.generate_corrected(src)
    assert result["changed"] is False and result["proposed_source"] == src and result["validation"] is None


def test_missing_include_is_added_as_an_explained_change():
    src = "int main(void){ char a[8]; char b[8]; strcpy(a, b); return 0; }"
    result = fixer.generate_corrected(src)
    assert "#include <stdio.h>" in result["proposed_source"]
    assert any("#include" in c["explanation"] for c in result["changes"])


def test_double_free_gets_null_after_first_free():
    src = "#include <stdlib.h>\nint main(void){ int *p = malloc(4); free(p); free(p); return 0; }"
    result = fixer.fix_finding(src, finding_id(src, "SC-MEM-008"))
    assert "free(p); p = NULL;" in result["proposed_source"]
    assert not [f for f in analyze(result["proposed_source"])["findings"] if f["rule_id"] == "SC-MEM-008"]


def test_edit_application_never_overlaps():
    edits = [rem.Edit(0, 5, "AAA", "x"), rem.Edit(3, 8, "BBB", "y")]
    out, applied, skipped = rem.apply_edits("0123456789", edits)
    assert len(applied) == 1 and len(skipped) == 1 and out == "AAA56789"


# ----------------------------------------------------------------------- validation

def test_validation_fails_when_a_patch_introduces_a_new_finding():
    original = 'int main(void){ char b[8]; fgets(b, sizeof(b), stdin); return 0; }'
    bad = 'int main(void){ char b[8]; gets(b); return 0; }'
    result = validation.validate_patch(original, bad, use_ml=False)
    assert result["status"] == "Failed"
    assert any(f["rule_id"] == "SC-MEM-001" for f in result["new_findings"])


def test_validation_fails_when_the_target_finding_is_not_resolved():
    src = "int main(void){ char b[8]; gets(b); return 0; }"
    result = validation.validate_patch(src, src, target_rules={"SC-MEM-001": 1}, use_ml=False)
    assert result["status"] == "Failed"
    assert any("still reported" in c["detail"] for c in result["checks"])


def test_validation_fails_when_a_patch_breaks_compilation(monkeypatch):
    def fake_compile(source, timeout=8):
        broken = "BROKEN" in source
        return {"available": True, "ran": True, "compiler": "fakecc", "error_count": 1 if broken else 0,
                "warning_count": 0, "diagnostics": ([{"kind": "compiler", "severity": "error", "line": 1,
                                                       "column": 1, "message": "boom"}] if broken else [])}
    monkeypatch.setattr(validation, "compile_check", fake_compile)
    result = validation.validate_patch("int main(void){return 0;}", "int main(void){return 0;} BROKEN", use_ml=False)
    assert result["status"] == "Failed"


def test_validation_is_unable_to_verify_without_a_compiler(monkeypatch):
    monkeypatch.setattr(validation, "compile_check", lambda s, timeout=8: {
        "available": False, "ran": False, "compiler": None, "diagnostics": [], "error_count": 0,
        "warning_count": 0, "note": "No Clang/GCC executable was found on PATH."})
    src = "int main(void){ char b[8]; gets(b); return 0; }"
    fixed = "int main(void){ char b[8]; fgets(b, sizeof(b), stdin); return 0; }"
    result = validation.validate_patch(src, fixed, target_rules={"SC-MEM-001": 1}, use_ml=False)
    assert result["status"] == "Unable to verify"
    assert "Compiler syntax check" in result["checks_not_run"]
    assert "Compiler syntax check" not in result["checks_run"]


def test_remaining_preexisting_compile_errors_mean_unable_to_verify(monkeypatch):
    def fake_compile(source, timeout=8):
        return {"available": True, "ran": True, "compiler": "fakecc", "error_count": 1, "warning_count": 0,
                "diagnostics": [{"kind": "compiler", "severity": "error", "line": 1, "column": 1, "message": "old error"}]}
    monkeypatch.setattr(validation, "compile_check", fake_compile)
    src = "int main(void){ char b[8]; gets(b); return 0; }"
    fixed = "int main(void){ char b[8]; fgets(b, sizeof(b), stdin); return 0; }"
    result = validation.validate_patch(src, fixed, target_rules={"SC-MEM-001": 1}, use_ml=False)
    assert result["status"] == "Unable to verify"


def test_validation_reports_that_regression_tests_were_not_run():
    src = "int main(void){ char b[8]; gets(b); return 0; }"
    fixed = "int main(void){ char b[8]; fgets(b, sizeof(b), stdin); return 0; }"
    result = validation.validate_patch(src, fixed, target_rules={"SC-MEM-001": 1}, use_ml=False)
    assert "Regression tests" in result["checks_not_run"]
    assert "not a guarantee" in result["disclaimer"]
