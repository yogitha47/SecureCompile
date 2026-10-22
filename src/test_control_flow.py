r"""Regression tests for SecureCompile if/else flow tracking.

Run from the project root:
    .\venv\Scripts\python.exe src\test_control_flow.py
"""
import sys
from pathlib import Path

SRC = Path(__file__).resolve().parent
sys.path.insert(0, str(SRC))

from lexer import lexer
from parser import parser
from security_analyzer import SecurityAnalyzer


def analyze(source):
    lexer.lineno = 1
    tree = parser.parse(source, lexer=lexer)
    assert tree is not None, "Parser returned no AST"
    return SecurityAnalyzer().analyze(tree)


def uninitialized_names(findings):
    names = set()
    for finding in findings:
        if finding.get("rule_id") == "SC-DATA-001":
            message = finding.get("message", "")
            # Messages have the form: Variable 'x' used before initialization.
            parts = message.split("'")
            if len(parts) >= 3:
                names.add(parts[1])
    return names


def test_both_branches_initialize():
    findings = analyze("""
        int condition;
        int x;
        if (condition) {
            x = 10;
        } else {
            x = 20;
        }
        int y = x + 1;
    """)
    names = uninitialized_names(findings)
    assert "x" not in names, f"x should be initialized on both paths: {findings}"
    assert "condition" in names, f"condition read should be reported in this restricted test: {findings}"


def test_only_if_branch_initializes():
    findings = analyze("""
        int condition;
        int x;
        if (condition) {
            x = 10;
        }
        int y = x + 1;
    """)
    names = uninitialized_names(findings)
    assert "x" in names, f"x may be uninitialized when the branch is skipped: {findings}"


def test_known_true_condition():
    findings = analyze("""
        int condition = 1;
        int x;
        if (condition) {
            x = 10;
        }
        int y = x + 1;
    """)
    names = uninitialized_names(findings)
    assert "x" not in names, f"x is initialized on the known-true path: {findings}"


def test_known_false_condition():
    findings = analyze("""
        int condition = 0;
        int x;
        if (condition) {
            x = 10;
        }
        int y = x + 1;
    """)
    names = uninitialized_names(findings)
    assert "x" in names, f"the known-false branch does not initialize x: {findings}"


if __name__ == "__main__":
    tests = [
        test_both_branches_initialize,
        test_only_if_branch_initializes,
        test_known_true_condition,
        test_known_false_condition,
    ]
    failed = 0
    for test in tests:
        try:
            test()
            print(f"PASS: {test.__name__}")
        except Exception as exc:
            failed += 1
            print(f"FAIL: {test.__name__}: {exc}")
    print(f"\nControl-flow tests: {len(tests) - failed}/{len(tests)} passed")
    raise SystemExit(1 if failed else 0)
