
# ==========================================
# SecureCompile - Security Analyzer
# ==========================================

import re

from ast_nodes import (
    Program,
    FunctionDefinition,
    Declaration,
    Assignment,
    IfStatement,
    WhileStatement,
    BinaryOperation,
    Number,
    Identifier,
    StringLiteral,
    FunctionCall
)


class SecurityAnalyzer:
    """AST-based security checks for a restricted C subset."""

    
    def __init__(self):
        self.findings = []
        self.constants = {}
        self.initialized = set()
        self.declared = set()

    def analyze(self, node):
        # Reset state so the analyzer can be reused.
        self.findings = []
        self.constants = {}
        self.initialized = set()
        self.declared = set()

        if node is None:
            return []

        self.visit(node)
        return self.findings

    # --------------------------------------
    # Structured findings
    # --------------------------------------

    
    def add_finding(
        self,
        node,
        rule_id,
        category,
        severity,
        confidence,
        message,
        explanation,
        suggestion
    ):
        line = getattr(node, "line", None)

        # Prevent duplicate reports for the same rule and source line.
        for finding in self.findings:
            if finding["rule_id"] == rule_id and finding["line"] == line:
                return

        self.findings.append({
            "rule_id": rule_id,
            "type": category,
            "severity": severity,
            "confidence": confidence,
            "message": message,
            "explanation": explanation,
            "suggestion": suggestion,
            "line": line
        })


    # --------------------------------------
    # AST visitor
    # --------------------------------------

    def visit(self, node):
        if isinstance(node, Program):
            self.visit_program(node)

        elif isinstance(node, FunctionDefinition):
            for statement in node.body:
                self.visit(statement)

        elif isinstance(node, Declaration):
            self.visit_declaration(node)

        elif isinstance(node, Assignment):
            self.visit_assignment(node)

        elif isinstance(node, IfStatement):
            self.visit_if(node)

        elif isinstance(node, WhileStatement):
            self.visit_while(node)

        elif isinstance(node, BinaryOperation):
            self.visit_binary_operation(node)

        elif isinstance(node, FunctionCall):
            self.visit_function_call(node)

        elif isinstance(node, Identifier):
            self.visit_identifier(node)

        elif isinstance(node, (Number, StringLiteral)):
            pass

    def visit_program(self, node):
        for statement in node.statements:
            self.visit(statement)

    # --------------------------------------
    # Declarations and assignments
    # --------------------------------------

    def visit_declaration(self, node):
        self.declared.add(node.name)
        if node.value is not None:
            self.visit(node.value)
            self.initialized.add(node.name)

            value = self.get_constant_value(node.value)

            if value is not None:
                self.constants[node.name] = value
            else:
                self.constants.pop(node.name, None)
        else:
            self.initialized.discard(node.name)
            self.constants.pop(node.name, None)

    def visit_assignment(self, node):
        self.visit(node.value)
        self.initialized.add(node.name)

        value = self.get_constant_value(node.value)

        if value is not None:
            self.constants[node.name] = value
        else:
            self.constants.pop(node.name, None)

    # --------------------------------------
    # If statements
    # --------------------------------------

    def visit_if(self, node):
        self.visit(node.condition)
        result = self.evaluate_condition(node.condition)

        if result is True:
            self.add_finding(
                node,
                "SC-LOGIC-001",
                "Constant Condition",
                "MEDIUM",
                "HIGH",
                "Condition is always true.",
                (
                    "The condition has a fixed value and "
                    "always evaluates to true."
                ),
                (
                    "Check whether this is intentional. "
                    "If not, review the comparison or use "
                    "the variable that should control it."
                )
            )

        elif result is False:
            self.add_finding(
                node,
                "SC-LOGIC-001",
                "Constant Condition",
                "MEDIUM",
                "HIGH",
                "Condition is always false.",
                (
                    "The condition always evaluates to false, "
                    "so the if block will not execute."
                ),
                "Review the condition and correct it if necessary."
            )

        # Analyze each possible path from the same incoming state.
        # A variable is definitely initialized after an unknown condition
        # only if it is initialized on every possible path.
        incoming_initialized = set(self.initialized)
        incoming_constants = dict(self.constants)

        if result is True:
            for statement in node.body:
                self.visit(statement)
            return

        if result is False:
            for statement in node.else_body:
                self.visit(statement)
            return

        # Unknown condition: analyze the if branch.
        self.initialized = set(incoming_initialized)
        self.constants = dict(incoming_constants)
        for statement in node.body:
            self.visit(statement)
        if_initialized = set(self.initialized)
        if_constants = dict(self.constants)

        # Analyze the else branch from the original state. An absent else
        # branch represents a path where none of its statements execute.
        self.initialized = set(incoming_initialized)
        self.constants = dict(incoming_constants)
        for statement in node.else_body:
            self.visit(statement)
        else_initialized = set(self.initialized)
        else_constants = dict(self.constants)

        self.initialized = if_initialized & else_initialized
        self.constants = {
            name: value
            for name, value in if_constants.items()
            if name in else_constants and else_constants[name] == value
        }

    # --------------------------------------
    # While loops
    # --------------------------------------

    def visit_while(self, node):
        # Evaluate the condition before entering the loop, but avoid a
        # misleading constant-loop warning when the body updates a variable
        # used by that condition (for example: while (x < 10) { x = x + 1; }).
        self.visit(node.condition)
        result = self.evaluate_condition(node.condition)
        condition_names = self.identifiers_in(node.condition)
        assigned_names = self.assignments_in(node.body)
        condition_changes_in_body = bool(condition_names & assigned_names)

        if result is True and not condition_changes_in_body:
            self.add_finding(
                node,
                "SC-LOGIC-002",
                "Constant Loop Condition",
                "MEDIUM",
                "MEDIUM",
                "The while condition appears to remain true.",
                (
                    "The condition evaluates to true using the values "
                    "known before the loop. SecureCompile checks whether "
                    "the loop body updates a variable used in that condition; "
                    "this is a conservative check, not a proof of termination."
                ),
                (
                    "Confirm that the loop has an intentional and reachable "
                    "termination mechanism, such as a condition update or break."
                )
            )

        for statement in node.body:
            self.visit(statement)

    def identifiers_in(self, node):
        """Collect identifier names referenced by an expression."""
        names = set()
        if isinstance(node, Identifier):
            names.add(node.name)
        elif isinstance(node, BinaryOperation):
            names.update(self.identifiers_in(node.left))
            names.update(self.identifiers_in(node.right))
        return names

    def assignments_in(self, statements):
        """Collect assigned names in a loop body, including nested if/while bodies."""
        names = set()
        for statement in statements:
            if isinstance(statement, Assignment):
                names.add(statement.name)
            elif isinstance(statement, Declaration) and statement.value is not None:
                names.add(statement.name)
            elif isinstance(statement, IfStatement):
                names.update(self.assignments_in(statement.body))
                names.update(self.assignments_in(statement.else_body))
            elif isinstance(statement, WhileStatement):
                names.update(self.assignments_in(statement.body))
        return names

    # --------------------------------------
    # Arithmetic
    # --------------------------------------

    def visit_binary_operation(self, node):
        if node.operator in {"/", "%"}:
            divisor = self.get_constant_value(node.right)

            if divisor == 0:
                is_modulo = node.operator == "%"

                if is_modulo:
                    self.add_finding(
                        node,
                        "SC-ARITH-002",
                        "Modulo by Zero",
                        "HIGH",
                        "HIGH",
                        "Modulo by zero detected.",
                        (
                            "The remainder operator is being "
                            "used with zero as its divisor. "
                            "This is invalid arithmetic and "
                            "can cause undefined behaviour."
                        ),
                        (
                            "Check that the divisor is not zero "
                            "before calculating the remainder."
                        )
                    )
                else:
                    self.add_finding(
                        node,
                        "SC-ARITH-001",
                        "Division by Zero",
                        "HIGH",
                        "HIGH",
                        "Division by zero detected.",
                        (
                            "Your program is trying to divide "
                            "a number by zero. This is invalid "
                            "arithmetic and can cause "
                            "undefined behaviour."
                        ),
                        (
                            "Check that the divisor is not zero "
                            "before performing the division."
                        )
                    )

        self.visit(node.left)
        self.visit(node.right)

    # --------------------------------------
    # Uninitialized variables
    # --------------------------------------

    
    def visit_identifier(self, node):
        if node.name in self.declared and node.name not in self.initialized:
            self.add_finding(
                node,
                "SC-DATA-001",
                "Uninitialized Variable",
                "HIGH",
                "MEDIUM",
                f"Variable '{node.name}' used before initialization.",
                (
                    f"The variable '{node.name}' may not have "
                    "a known value before it is read."
                ),
                (
                    f"Assign an appropriate value to '{node.name}' "
                    "before using it."
                )
            )


    # --------------------------------------
    # Function calls
    # --------------------------------------

    def visit_function_call(self, node):
        name = node.name
        args = node.arguments
                # Visit arguments that are read by the function.
        # Output destinations must not be treated as input reads.
        if name == "scanf":
            # scanf reads the format string; other arguments are destinations.
            if args:
                self.visit(args[0])

        elif name == "gets":
            # gets writes into its destination buffer.
            pass

        elif name in {"strcpy", "sprintf"}:
            # First argument is the destination buffer.
            for arg in args[1:]:
                self.visit(arg)

        else:
            # printf, system, strcat, and other calls read their arguments.
            for arg in args:
                self.visit(arg)

        unsafe_functions = {
            "gets": (
                "SC-MEM-001",
                "The gets() function reads input without "
                "a destination-size limit.",
                "Use fgets() with the actual buffer capacity."
            ),
            "strcpy": (
                "SC-MEM-002",
                "strcpy() does not check whether the "
                "destination can hold the source string.",
                (
                    "Check destination capacity and source "
                    "length, and use a bounded copying approach "
                    "with correct termination handling."
                )
            ),
            "strcat": (
                "SC-MEM-003",
                "strcat() can exceed the destination buffer "
                "when insufficient space remains.",
                (
                    "Check the available destination capacity "
                    "before appending the string."
                )
            ),
            "sprintf": (
                "SC-MEM-004",
                "sprintf() writes formatted output without "
                "a destination-size limit.",
                (
                    "Use snprintf() with the actual destination "
                    "buffer capacity and check its return value."
                )
            )
        }

        if name in unsafe_functions:
            rule_id, explanation, suggestion = unsafe_functions[name]

            self.add_finding(
                node,
                rule_id,
                "Potentially Unsafe Function",
                "HIGH",
                "MEDIUM",
                f"Potentially unsafe function '{name}' detected.",
                explanation,
                suggestion
            )

        # Unbounded scanf string input.
        if name == "scanf" and args:
            format_node = args[0]

            if isinstance(format_node, StringLiteral):
                format_string = format_node.value[1:-1]

                # Ignore escaped %%; inspect %s conversions.
                conversions = re.findall(
                    r"%(?!%)(\d*)s",
                    format_string
                )

                if any(width == "" for width in conversions):
                    self.add_finding(
                        node,
                        "SC-INPUT-001",
                        "Unbounded String Input",
                        "HIGH",
                        "HIGH",
                        "scanf() contains a %s conversion without a width limit.",
                        (
                            "The input conversion does not specify "
                            "a maximum number of characters. If "
                            "the destination buffer is too small, "
                            "input may overwrite adjacent memory."
                        ),
                        (
                            "Specify a field width based on the "
                            "actual destination capacity, leaving "
                            "space for the terminating null byte. "
                            "Check the input result as well."
                        )
                    )

            # scanf arguments after the format string are output
            # destinations, not ordinary values being read.
            return

        # Format-string misuse: printf(user_controlled_value).
        if name in {"printf", "fprintf", "sprintf"}:
            format_index = 1 if name in {"fprintf", "sprintf"} else 0

            if len(args) > format_index:
                format_arg = args[format_index]

                if not isinstance(format_arg, StringLiteral):
                    self.add_finding(
                        node,
                        "SC-INPUT-002",
                        "Potential Format String Vulnerability",
                        "HIGH",
                        "MEDIUM",
                        (
                            f"{name}() may use a non-literal "
                            "format string."
                        ),
                        (
                            "If this value contains user-controlled "
                            "text, formatting directives may be "
                            "interpreted instead of printed literally."
                        ),
                        (
                            "Use a fixed format string such as "
                            'printf("%s", value) when printing text.'
                        )
                    )

        # Command execution requires context; this is a warning.
        if name in {"system", "popen"}:
            self.add_finding(
                node,
                "SC-CMD-001",
                "Command Execution Risk",
                "MEDIUM",
                "MEDIUM",
                f"Use of '{name}()' requires security review.",
                (
                    "This function can execute a system command. "
                    "If command content includes untrusted input, "
                    "it may allow unintended command execution."
                ),
                (
                    "Avoid shell commands when possible. If needed, "
                    "use safer APIs and never concatenate untrusted "
                    "input into a command string."
                )
            )

        # Avoid treating write-only destination arguments as reads.
        if name == "gets":
            return

        if name in {"strcpy", "strcat", "sprintf"}:
            for argument in args[1:]:
                self.visit(argument)
            return

        for argument in args:
            self.visit(argument)

    # --------------------------------------
    # Constant-condition evaluation
    # --------------------------------------

    def evaluate_condition(self, node):
        # C treats zero as false and nonzero scalar values as true.
        # This also lets the analyzer honor conditions such as `if (flag)`
        # when `flag` has a known constant value.
        if isinstance(node, Number):
            return bool(node.value)

        if isinstance(node, Identifier):
            value = self.constants.get(node.name)
            return bool(value) if value is not None else None

        if not isinstance(node, BinaryOperation):
            return None

        left = self.get_constant_value(node.left)
        right = self.get_constant_value(node.right)

        if left is None or right is None:
            return None

        operations = {
            "==": lambda a, b: a == b,
            "!=": lambda a, b: a != b,
            "<": lambda a, b: a < b,
            ">": lambda a, b: a > b,
            "<=": lambda a, b: a <= b,
            ">=": lambda a, b: a >= b
        }

        operation = operations.get(node.operator)

        if operation is not None:
            return operation(left, right)

        return None

    # --------------------------------------
    # Constant-value evaluation
    # --------------------------------------

    def get_constant_value(self, node):
        if isinstance(node, Number):
            return node.value

        if isinstance(node, Identifier):
            return self.constants.get(node.name)

        if isinstance(node, BinaryOperation):
            left = self.get_constant_value(node.left)
            right = self.get_constant_value(node.right)

            if left is None or right is None:
                return None

            try:
                operations = {
                    "+": lambda a, b: a + b,
                    "-": lambda a, b: a - b,
                    "*": lambda a, b: a * b,
                    "/": lambda a, b: a / b,
                    "%": lambda a, b: a % b
                }

                if node.operator in {"/", "%"} and right == 0:
                    return None

                operation = operations.get(node.operator)

                if operation is not None:
                    return operation(left, right)

            except (ArithmeticError, TypeError, ValueError):
                return None

        return None
