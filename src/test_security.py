
from lexer import lexer
from parser import parser
from security_analyzer import SecurityAnalyzer

# --------------------------------------
# Read C source code
# --------------------------------------

file_path = "../tests/vulnerabilities/uninitialized.c"

with open(file_path, "r") as file:
    source_code = file.read()

# --------------------------------------
# Parse source code
# --------------------------------------

lexer.lineno = 1
ast = parser.parse(source_code, lexer=lexer)

print("\n==========================================")
print("SecureCompile - AST")
print("==========================================\n")
print(ast)

# --------------------------------------
# Run security analysis
# --------------------------------------

if ast is None:
    print("\nAnalysis stopped because the source code has syntax errors.")
    raise SystemExit(1)

analyzer = SecurityAnalyzer()
findings = analyzer.analyze(ast)

print("\n==========================================")
print("SecureCompile - Security Analysis")
print("==========================================\n")

if findings:
    print(f"Total findings: {len(findings)}\n")

    for index, finding in enumerate(findings, start=1):
        print(f"Finding {index}")
        print("-" * 40)
        print(f"Category     : {finding['type']}")
        print(f"Severity     : {finding['severity']}")
        print(f"Problem      : {finding['message']}")
        print(
            "Explanation  : "
            + finding.get("explanation", "No explanation available.")
        )
        print(
            "Suggested Fix: "
            + finding.get("suggestion", "No suggestion available.")
        )
        print()

else:
    print("No security vulnerabilities detected.")
