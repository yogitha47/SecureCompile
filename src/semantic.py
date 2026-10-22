# ==========================================
# SecureCompile - Semantic Analyzer
# ==========================================

from symbol_table import SymbolTable

from ast_nodes import (
    Program,
    Declaration,
    Assignment,
    IfStatement,
    BinaryOperation,
    Number,
    Identifier
)


class SemanticAnalyzer:
    """
    Performs semantic checks on the SecureCompile AST.
    """

    def __init__(self):
        self.symbol_table = SymbolTable()
        self.errors = []

    # --------------------------------------
    # Analyze the complete program
    # --------------------------------------

    def analyze(self, node):
        self.visit(node)

        return self.errors

    # --------------------------------------
    # Generic visitor
    # --------------------------------------

    def visit(self, node):

        if isinstance(node, Program):
            self.visit_program(node)

        elif isinstance(node, Declaration):
            self.visit_declaration(node)

        elif isinstance(node, Assignment):
            self.visit_assignment(node)

        elif isinstance(node, IfStatement):
            self.visit_if(node)

        elif isinstance(node, BinaryOperation):
            self.visit_binary_operation(node)

        elif isinstance(node, Identifier):
            self.visit_identifier(node)

        elif isinstance(node, Number):
            pass

    # --------------------------------------
    # Program
    # --------------------------------------

    def visit_program(self, node):

        for statement in node.statements:
            self.visit(statement)

    # --------------------------------------
    # Declaration
    # --------------------------------------

    def visit_declaration(self, node):

        # Check duplicate declaration
        if self.symbol_table.exists(node.name):

            self.errors.append(
                f"Variable '{node.name}' "
                f"already declared."
            )

            return

        # Determine initialization status
        initialized = node.value is not None

        # Add variable to symbol table
        self.symbol_table.declare(
            node.name,
            node.data_type,
            initialized
        )

        # Analyze initializer
        if node.value is not None:
            self.visit(node.value)

    # --------------------------------------
    # Assignment
    # --------------------------------------

    def visit_assignment(self, node):

        # Check whether variable exists
        if not self.symbol_table.exists(node.name):

            self.errors.append(
                f"Variable '{node.name}' "
                f"used before declaration."
            )

            # Still analyze the expression
            self.visit(node.value)

            return

        # Analyze right-hand side first
        self.visit(node.value)

        # Mark variable as initialized
        self.symbol_table.initialize(node.name)

    # --------------------------------------
    # If statement
    # --------------------------------------

    def visit_if(self, node):

        # Analyze condition
        self.visit(node.condition)

        # Analyze statements inside if
        for statement in node.body:
            self.visit(statement)

    # --------------------------------------
    # Binary operation
    # --------------------------------------

    def visit_binary_operation(self, node):

        # Analyze left side
        self.visit(node.left)

        # Analyze right side
        self.visit(node.right)

    # --------------------------------------
    # Identifier
    # --------------------------------------

    def visit_identifier(self, node):

        # Check declaration
        if not self.symbol_table.exists(node.name):

            self.errors.append(
                f"Variable '{node.name}' "
                f"used before declaration."
            )

            return

        # Check initialization
        if not self.symbol_table.is_initialized(node.name):

            self.errors.append(
                f"Variable '{node.name}' "
                f"used before initialization."
            )