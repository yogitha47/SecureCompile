
# ==========================================
# SecureCompile - Consolidated Test Runner
# ==========================================

from pathlib import Path
import json

from lexer import lexer
from parser import parser
from security_analyzer import SecurityAnalyzer


PROJECT_ROOT = Path(__file__).resolve().parent.parent
REPORT_DIR = PROJECT_ROOT / "reports"
REPORT_DIR.mkdir(parents=True, exist_ok=True)

TEST_DIRS = [
    PROJECT_ROOT / "tests" / "safe",
    PROJECT_ROOT / "tests" / "vulnerabilities"
]

BUILT_IN_TESTS = {
    "regression_modulo_by_zero.c": (
        "int x = 10 % 0;",
        "Modulo by Zero"
    ),
    "regression_unsafe_scanf.c": (
        'char buffer;\nscanf("%s", buffer);',
        "Unbounded String Input"
    ),
    "regression_format_string.c": (
        "int value;\nprintf(value);",
        "Potential Format String Vulnerability"
    ),
    "regression_system_call.c": (
        'system("example-command");',
        "Command Execution Risk"
    ),
    "regression_safe_arithmetic.c": (
        "int x = 10;\nint y = 2;\nint result = x / y;",
        None
    )
}


def analyze_source(source_code):
    lexer.lineno = 1
    ast = parser.parse(source_code, lexer=lexer)

    if ast is None:
        return None

    analyzer = SecurityAnalyzer()
    return analyzer.analyze(ast)


def print_findings(findings):
    for finding in findings:
        line = finding.get("line")
        line_label = line if line is not None else "Unknown"

        print(
            f"\n[{finding['severity']}] "
            f"{finding['type']} "
            f"(Line: {line_label})"
        )
        print(f"Rule ID: {finding.get('rule_id', 'N/A')}")
        print(f"Confidence: {finding.get('confidence', 'N/A')}")
        print(f"Problem: {finding['message']}")
        print(f"Explanation: {finding['explanation']}")
        print(f"Suggested fix: {finding['suggestion']}")


def main():
    results = []
    total_findings = 0
    errors = 0

    print("\n==========================================")
    print("SecureCompile - Consolidated Test Suite")
    print("==========================================")

    source_files = []

    for directory in TEST_DIRS:
        if directory.exists():
            source_files.extend(sorted(directory.glob("*.c")))

    for file_path in source_files:
        print(f"\nFile: {file_path.name}")
        print("-" * 45)

        try:
            source = file_path.read_text(encoding="utf-8")
            findings = analyze_source(source)

            if findings is None:
                errors += 1
                results.append({
                    "file": str(file_path.relative_to(PROJECT_ROOT)),
                    "status": "PARSE_ERROR",
                    "findings": []
                })
                print("Status: PARSE ERROR")
                continue

            total_findings += len(findings)
            results.append({
                "file": str(file_path.relative_to(PROJECT_ROOT)),
                "status": "ANALYZED",
                "findings": findings
            })

            print(f"Status: ANALYZED")
            print(f"Findings: {len(findings)}")

            if findings:
                print_findings(findings)
            else:
                print("No findings from the implemented rules.")

        except Exception as error:
            errors += 1
            results.append({
                "file": str(file_path),
                "status": "ERROR",
                "error": str(error),
                "findings": []
            })
            print(f"ERROR: {error}")

    # --------------------------------------
    # Built-in regression cases
    # --------------------------------------

    print("\n==========================================")
    print("Built-in Regression Tests")
    print("==========================================")

    regression_results = []

    for name, (source, expected_type) in BUILT_IN_TESTS.items():
        try:
            findings = analyze_source(source)

            passed = (
                findings is not None
                and (
                    expected_type is None
                    or any(
                        finding["type"] == expected_type
                        for finding in findings
                    )
                )
            )

            status = "PASS" if passed else "FAIL"

            print(f"{status}: {name}")

            if findings is None:
                errors += 1
            else:
                total_findings += len(findings)

            regression_results.append({
                "name": name,
                "expected_finding": expected_type,
                "status": status,
                "findings": findings if findings is not None else []
            })

        except Exception as error:
            errors += 1
            regression_results.append({
                "name": name,
                "status": "ERROR",
                "error": str(error),
                "findings": []
            })
            print(f"ERROR: {name}: {error}")

    report = {
        "project": "SecureCompile",
        "files_processed": len(source_files),
        "errors": errors,
        "total_findings": total_findings,
        "file_results": results,
        "regression_results": regression_results
    }

    report_path = REPORT_DIR / "security_report.json"
    report_path.write_text(
        json.dumps(report, indent=4),
        encoding="utf-8"
    )

    print("\n==========================================")
    print("Final Summary")
    print("==========================================")
    print(f"Existing files processed: {len(source_files)}")
    print(f"Built-in tests: {len(BUILT_IN_TESTS)}")
    print(f"Errors: {errors}")
    print(f"JSON report: {report_path}")


if __name__ == "__main__":
    main()
