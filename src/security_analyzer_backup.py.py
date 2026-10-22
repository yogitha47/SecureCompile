# ==========================================
# SecureCompile - Security Analyzer
# ==========================================

from ast_nodes import (
    Program,
    Declaration,
    Assignment,
    IfStatement,
    BinaryOperation,
    Number,
    Identifier,
    FunctionCall
)


class SecurityAnalyzer:
    """
    Performs security checks on the AST.
    """

    def __init__(self):
        self.findings = []

        # Stores simple constant values.
        # Example:
        # int y = 0;
        # constants["y"] = 0
        self.constants = {}

        # Stores variables that have been initialized.
        self.initialized = set()

    # --------------------------------------
    # Analyze complete program
    # --------------------------------------

    def analyze(self, node):
        self.visit(node)
        return self.findings

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

        elif isinstance(node, FunctionCall):
            self.visit_function_call(node)

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

        if node.value is not None:

            # Analyze initializer first
            self.visit(node.value)

            # Mark variable as initialized
            self.initialized.add(node.name)

            # Remember simple constant values
            value = self.get_constant_value(node.value)

            if value is not None:
                self.constants[node.name] = value

        else:

            # Variable is declared but not initialized
            self.initialized.discard(node.name)

    # --------------------------------------
    # Assignment
    # --------------------------------------

    def visit_assignment(self, node):

        # Analyze right-hand side first
        self.visit(node.value)

        # Assignment initializes variable
        self.initialized.add(node.name)

        # Track simple constant assignments
        value = self.get_constant_value(node.value)

        if value is not None:
            self.constants[node.name] = value
        else:
            self.constants.pop(node.name, None)

    # --------------------------------------
    # If Statement
    # --------------------------------------

    def visit_if(self, node):

        # Analyze the condition
        self.visit(node.condition)

        # Check for constant condition
        condition_value = self.evaluate_condition(
            node.condition
        )

        if condition_value is True:

            self.findings.append({
                "type": "Constant Condition",
                "severity": "MEDIUM",
                "message": "Condition is always true."
            })

        elif condition_value is False:

            self.findings.append({
                "type": "Constant Condition",
                "severity": "MEDIUM",
                "message": "Condition is always false."
            })

        # Analyze statements inside if
        for statement in node.body:
            self.visit(statement)

    # --------------------------------------
    # Binary Operation
    # --------------------------------------

    def visit_binary_operation(self, node):

        # Check for division by zero
        if node.operator == "/":

            divisor = self.get_constant_value(
                node.right
            )

            if divisor == 0:

                self.findings.append({
                    "type": "Division by Zero",
                    "severity": "HIGH",
                    "message": "Division by zero detected."
                })

        # Analyze both sides
        self.visit(node.left)
        self.visit(node.right)

    # --------------------------------------
    # Identifier
    # --------------------------------------

    def visit_identifier(self, node):

        # Detect use before initialization
        if node.name not in self.initialized:

            self.findings.append({
                "type": "Uninitialized Variable",
                "severity": "HIGH",
                "message": (
                    f"Variable '{node.name}' "
                    f"used before initialization."
                )
            })

    # --------------------------------------
    # Function Call
    # --------------------------------------

    def visit_function_call(self, node):

        # Functions considered unsafe for this prototype
        unsafe_functions = {
            "gets",
            "strcpy",
            "strcat",
            "sprintf"
        }

        if node.name in unsafe_functions:

            self.findings.append({
                "type": "Unsafe Function",
                "severity": "HIGH",
                "message": (
                    f"Potentially unsafe function "
                    f"'{node.name}' detected."
                )
            })

        # Analyze function arguments
        for argument in node.arguments:
            self.visit(argument)

    # --------------------------------------
    # Evaluate Constant Condition
    # --------------------------------------

    def evaluate_condition(self, node):

        if not isinstance(node, BinaryOperation):
            return None

        left = self.get_constant_value(node.left)
        right = self.get_constant_value(node.right)

        if left is None or right is None:
            return None

        if node.operator == "==":
            return left == right

        if node.operator == "!=":
            return left != right

        if node.operator == "<":
            return left < right

        if node.operator == ">":
            return left > right

        if node.operator == "<=":
            return left <= right

        if node.operator == ">=":
            return left >= right

        return None

    # --------------------------------------
    # Get Constant Value
    # --------------------------------------

    def get_constant_value(self, node):

        # Direct number
        if isinstance(node, Number):
            return node.value

        # Identifier with known constant value
        if isinstance(node, Identifier):
            return self.constants.get(node.name)

        # Binary operation with constants
        if isinstance(node, BinaryOperation):

            left = self.get_constant_value(node.left)
            right = self.get_constant_value(node.right)

            if left is None or right is None:
                return None

            if node.operator == "+":
                return left + right

            if node.operator == "-":
                return left - right

            if node.operator == "*":
                return left * right

            if node.operator == "/":

                if right == 0:
                    return None

                return left / right

        return None