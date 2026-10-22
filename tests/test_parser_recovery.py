"""Syntax error recovery: diagnostics, repairs, and continued parsing."""
from parser import parse_with_recovery

import pytest
from ast_nodes import Declaration, FunctionDefinition


def names(program):
    out = []
    for node in program.statements:
        if isinstance(node, FunctionDefinition):
            out.extend(n.name for n in node.body if isinstance(n, Declaration))
        elif isinstance(node, Declaration):
            out.append(node.name)
    return out


def test_valid_program_has_no_diagnostics():
    result = parse_with_recovery("int main(void) { int a = 1; a += 2; return a; }")
    assert result["status"] == "complete"
    assert result["diagnostics"] == []
    assert result["repairs"] == []


def test_missing_semicolon_is_reported_with_location_and_recovered():
    src = "int x = 5\nint y = 0;\n"
    result = parse_with_recovery(src)
    assert result["status"] == "recovered"
    (diag,) = result["diagnostics"]
    assert (diag["line"], diag["column"]) == (1, 10)
    assert "Missing ';'" in diag["message"]
    assert names(result["ast"]) == ["x", "y"]  # the statement after the error is still parsed


def test_multiple_missing_semicolons():
    src = "int main(void) {\n int a = 1\n int b = 2\n a = a + b\n return a\n}\n"
    result = parse_with_recovery(src)
    assert [d["line"] for d in result["diagnostics"]] == [2, 3, 4, 5]
    assert len(result["repairs"]) == 4
    assert names(result["ast"]) == ["a", "b"]


def test_missing_semicolon_at_end_of_input():
    result = parse_with_recovery("int x = 5")
    assert result["status"] == "recovered"
    assert result["repairs"][0]["offset"] == len("int x = 5")


def test_repairs_are_proposals_and_never_applied_to_the_input():
    src = "int x = 5\nint y = 0;\n"
    result = parse_with_recovery(src)
    assert src == "int x = 5\nint y = 0;\n"
    edit = result["repairs"][0]
    repaired = src[: edit["offset"]] + edit["insert"] + src[edit["offset"]:]
    assert repaired == "int x = 5;\nint y = 0;\n"
    assert parse_with_recovery(repaired)["status"] == "complete"


def test_malformed_expression_is_skipped_and_later_statements_survive():
    result = parse_with_recovery("int a = 1;\nint b = (2 + ;\nint c = 3;\n")
    assert result["status"] == "recovered"
    assert names(result["ast"]) == ["a", "c"]


def test_malformed_condition_keeps_following_code():
    src = "int main(){ if (x == ) { y = 1; } int z = 3; return z; }"
    result = parse_with_recovery(src)
    assert result["diagnostics"]
    assert "z" in names(result["ast"])


def test_severely_malformed_code_does_not_crash_or_hang():
    junk = "}}}{{{ ((( int int ; ; = = if else while ] [ ) ( return return"
    result = parse_with_recovery(junk)
    assert result["status"] in {"failed", "recovered"}
    assert result["diagnostics"]


def test_unsupported_construct_reports_a_diagnostic():
    result = parse_with_recovery("int main(){ switch (1) { case 1: break; } return 0; }")
    assert result["diagnostics"]  # outside the restricted grammar (documented limitation)


def test_illegal_character_is_a_lexical_diagnostic():
    result = parse_with_recovery("int a = 1 @;\n")
    kinds = {d["kind"] for d in result["diagnostics"]}
    assert "lexical" in kinds


def test_diagnostic_cap_prevents_runaway_output():
    result = parse_with_recovery("int a = ;\n" * 200)
    assert len(result["diagnostics"]) <= 40
    assert result["truncated"] is True


@pytest.mark.parametrize("src", [
    "int main(void) { char b[8]; scanf(\"%d\", &b[0]); return 0; }",
    "int *p = (int *)malloc(sizeof(int)); *p = 3;",
    "void f(int n) { for (int i = 0; i < n; i++) { if (i) continue; else break; } }",
    "int x = 0x1F + 10L;",
    "char *s = \"hi\"; int t[3] = {1, 2, 3};",
])
def test_extended_c_constructs_parse_cleanly(src):
    result = parse_with_recovery(src)
    assert result["diagnostics"] == [], result["diagnostics"]


def test_parser_is_reentrant_across_calls():
    first = parse_with_recovery("int a = 1\nint b = 2;")
    second = parse_with_recovery("int a = 1;")
    assert first["status"] == "recovered"
    assert second["status"] == "complete"
