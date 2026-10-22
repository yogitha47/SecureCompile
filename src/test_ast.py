from ast_nodes import (
    Program,
    Declaration,
    Assignment,
    IfStatement,
    BinaryOperation,
    Number,
    Identifier
)


# Create a small AST manually

program = Program([
    Declaration("int", "x", Number(10)),
    Declaration("int", "y", Number(20)),

    Assignment(
        "x",
        BinaryOperation(
            "+",
            Identifier("x"),
            Identifier("y")
        )
    ),

    IfStatement(
        BinaryOperation(
            ">",
            Identifier("x"),
            Number(10)
        ),
        [
            Assignment(
                "x",
                BinaryOperation(
                    "-",
                    Identifier("x"),
                    Number(1)
                )
            )
        ]
    )
])


print("\nSecureCompile AST:\n")
print(program)