"""Unified pipeline: findings, syntax separation, dedup, uncertainty, correlation."""
import pipeline
import pytest
from correlate import correlate


def run(src, **kw):
    kw.setdefault("use_compiler", False)
    kw.setdefault("use_ml", False)
    return pipeline.analyze(src, **kw)


def rule_ids(result):
    return [f["rule_id"] for f in result["findings"]]


SAFE = """#include <stdio.h>
int main(void) {
    char buf[16];
    if (fgets(buf, sizeof(buf), stdin) != NULL) {
        printf("%s", buf);
    }
    return 0;
}
"""


def test_safe_program_has_no_findings_and_no_syntax_diagnostics():
    result = run(SAFE)
    assert result["findings"] == []
    assert result["syntax_diagnostics"] == []
    assert result["parse"]["status"] == "complete"


def test_single_vulnerability():
    result = run("#include <stdio.h>\nint main(void){ char b[4]; gets(b); return 0; }")
    assert rule_ids(result) == ["SC-MEM-001"]
    f = result["findings"][0]
    assert f["category"] == "buffer-overflow" and f["cwe"] == "CWE-242"
    assert f["evidence"]["snippet"].startswith("int main") or "gets" in f["evidence"]["snippet"]
    assert f["location"]["support"] == "exact" and f["location"]["column"]
    assert f["ml_confidence"] is None


def test_multiple_distinct_vulnerabilities_are_all_reported():
    src = ('#include <stdio.h>\n#include <string.h>\n#include <stdlib.h>\n'
           'int main(void){\n char a[8]; char b[8];\n gets(a);\n strcpy(b, a);\n printf(a);\n system(a);\n'
           ' int d = 0; int r = 10 / d;\n return r;\n}\n')
    ids = set(rule_ids(run(src)))
    assert {"SC-MEM-001", "SC-MEM-002", "SC-INPUT-002", "SC-CMD-001", "SC-ARITH-001"} <= ids


def test_same_issue_found_by_two_engines_is_one_finding_with_both_engines_listed():
    src = "int main(void){ char b[4]; gets(b); return 0; }"
    findings = [f for f in run(src)["findings"] if f["rule_id"] == "SC-MEM-001"]
    assert len(findings) == 1
    assert set(findings[0]["engines"]) == {"ast-rule", "source-rule"}
    assert len(findings[0]["engine_reports"]) == 2


def test_two_calls_of_the_same_rule_on_one_line_are_not_collapsed():
    src = "int main(void){ char a[4]; char b[4]; strcpy(a,\"x\"); strcpy(b,\"y\"); return 0; }"
    count = sum(f["rule_id"] == "SC-MEM-002" for f in run(src)["findings"])
    assert count == 2


def test_different_risks_on_the_same_line_stay_separate():
    src = "int main(void){ char b[4]; sprintf(b, b); return 0; }"
    ids = rule_ids(run(src))
    assert "SC-MEM-004" in ids and "SC-INPUT-002" in ids


def test_syntax_diagnostics_are_separate_from_security_findings():
    result = run("int main(void) {\n char b[4];\n gets(b)\n return 0;\n}\n")
    assert result["syntax_diagnostics"] and all(d["kind"] in {"syntax", "lexical"} for d in result["syntax_diagnostics"])
    assert all(f["rule_id"] != "SC-SYN-001" for f in result["findings"])
    assert "SC-MEM-001" in rule_ids(result)  # later/earlier analysis survives the syntax error


def test_findings_from_incomplete_parse_are_marked_more_uncertain():
    complete = run("int main(void){ char b[4]; gets(b); return 0; }")["findings"][0]
    broken = run("int main(void){ char b[4]; gets(b); int x = ; return 0; }")["findings"][0]
    order = ["low", "medium", "high"]
    assert order.index(broken["uncertainty"]["level"]) > order.index(complete["uncertainty"]["level"])
    assert any("incomplete" in r.lower() for r in broken["uncertainty"]["reasons"])


def test_unbalanced_delimiters_are_syntax_diagnostics_not_findings():
    result = run("int main(void) { if (1) { return 0; }\n")
    assert any(d.get("engine") == "source-fallback" for d in result["syntax_diagnostics"])
    assert all(f["category"] != "syntax" for f in result["findings"])


def test_empty_and_whitespace_input_is_rejected():
    for bad in ("", "   \n\t "):
        with pytest.raises(pipeline.AnalysisInputError):
            pipeline.analyze(bad)


def test_oversized_and_binary_input_is_rejected():
    with pytest.raises(pipeline.AnalysisInputError):
        pipeline.analyze("a" * (pipeline.MAX_SOURCE_CHARS + 1))
    with pytest.raises(pipeline.AnalysisInputError):
        pipeline.analyze("int x;\x00")


def test_unsupported_c_construct_still_gets_text_pattern_checks():
    src = "int main(void){ switch (1) { case 1: break; } char b[4]; gets(b); return 0; }"
    result = run(src)
    assert "SC-MEM-001" in rule_ids(result)
    assert result["parse"]["status"] != "complete"


def test_input_source_is_not_mutated():
    src = "int x = 5\nint y = 0;\n"
    copy = str(src)
    run(src)
    assert src == copy


# ----------------------------------------------------------------- correlation layer

def _ml(predicted, probs=None, scope=None):
    scope = scope or {"kind": "function", "name": "main", "start_line": 1, "end_line": 50, "signature": "int main()"}
    probabilities = {"buffer-overflow": 0.1, "double-free": 0.1}
    probabilities.update(probs or {})
    return {"status": "ok", "thresholds": {"buffer-overflow": 0.5, "double-free": 0.5},
            "scopes": [{**scope, "probabilities": probabilities, "predicted": predicted}]}


def _finding_for(src="int main(void){ char b[4]; gets(b); return 0; }"):
    return run(src)["findings"]


def test_agreement_marks_the_rule_finding_without_leaking_ml_confidence():
    findings = _finding_for()
    merged, disagreements = correlate(findings, _ml(["buffer-overflow"], {"buffer-overflow": 0.93}))
    rule = next(f for f in merged if f["rule_id"] == "SC-MEM-001")
    assert rule["review"]["status"] == "agreement"
    assert rule["ml_confidence"] is None
    assert not any(f["origin"] == "ml" for f in merged)
    assert disagreements == []


def test_ml_only_prediction_is_a_separate_finding_with_confidence_and_disagreement_entry():
    findings = _finding_for()
    merged, disagreements = correlate(findings, _ml(["double-free"], {"double-free": 0.88}))
    ml = next(f for f in merged if f["origin"] == "ml")
    assert ml["ml_confidence"] == 0.88 and ml["rule_id"] is None
    assert ml["review"]["status"] == "ml-only"
    kinds = {d["kind"] for d in disagreements}
    assert kinds == {"ml-only", "rule-only"}  # gets() rule fired; ML did not flag buffer-overflow


def test_rule_only_disagreement_is_shown_for_review_not_resolved_automatically():
    findings = _finding_for()
    merged, disagreements = correlate(findings, _ml([]))
    rule = next(f for f in merged if f["rule_id"] == "SC-MEM-001")
    assert rule["review"]["status"] == "rule-only"
    assert [d["kind"] for d in disagreements] == ["rule-only"]


def test_correlation_is_a_noop_when_ml_is_unavailable():
    findings = _finding_for()
    merged, disagreements = correlate(findings, {"status": "unavailable", "message": "x"})
    assert merged == findings and disagreements == []
    assert all(f["review"] is None for f in merged)
