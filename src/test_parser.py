from lexer import lexer
from parser import parser


with open("../tests/safe/while_test.c", "r") as file:
    source_code = file.read()


lexer.input(source_code)

result = parser.parse(source_code, lexer=lexer)

print("\nParser result:\n")
print(result)