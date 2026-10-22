from lexer import lexer
from parser import parser
from semantic import SemanticAnalyzer


# ------------------------------------------
# Read C source code
# ------------------------------------------

with open("../tests/safe/basics.c", "r") as file:
    source_code = file.read()


# ------------------------------------------
# Parse source code into AST
# ------------------------------------------

lexer.input(source_code)

ast = parser.parse(source_code, lexer=lexer)


# ------------------------------------------
# Run semantic analysis
# ------------------------------------------

analyzer = SemanticAnalyzer()

errors = analyzer.analyze(ast)


# ------------------------------------------
# Display results
# ------------------------------------------

print("\nSemantic Analysis:\n")

if errors:
    print("Semantic errors found:\n")

    for error in errors:
        print("-", error)

else:
    print("No semantic errors found.")