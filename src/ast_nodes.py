
# ==========================================
# SecureCompile - AST Node Definitions
# ==========================================

class ASTNode:
    def __init__(self, line=None):
        self.line = line


class Program(ASTNode):
    def __init__(self, statements, line=None):
        super().__init__(line)
        self.statements = statements

    def __repr__(self):
        return f"Program({self.statements})"


class Declaration(ASTNode):
    def __init__(self, data_type, name, value=None, line=None):
        super().__init__(line)
        self.data_type = data_type
        self.name = name
        self.value = value

    def __repr__(self):
        return (
            f"Declaration(type={self.data_type}, "
            f"name={self.name}, value={self.value})"
        )


class Assignment(ASTNode):
    def __init__(self, name, value, line=None):
        super().__init__(line)
        self.name = name
        self.value = value

    def __repr__(self):
        return f"Assignment(name={self.name}, value={self.value})"


class IfStatement(ASTNode):
    def __init__(self, condition, body, else_body=None, line=None):
        super().__init__(line)
        self.condition = condition
        self.body = body
        self.else_body = else_body or []

    def __repr__(self):
        return (
            f"IfStatement(condition={self.condition}, "
            f"body={self.body}, else_body={self.else_body})"
        )


class WhileStatement(ASTNode):
    def __init__(self, condition, body, line=None):
        super().__init__(line)
        self.condition = condition
        self.body = body

    def __repr__(self):
        return (
            f"WhileStatement(condition={self.condition}, "
            f"body={self.body})"
        )


class BinaryOperation(ASTNode):
    def __init__(self, operator, left, right, line=None):
        super().__init__(line)
        self.operator = operator
        self.left = left
        self.right = right

    def __repr__(self):
        return (
            f"BinaryOperation(operator='{self.operator}', "
            f"left={self.left}, right={self.right})"
        )


class Number(ASTNode):
    def __init__(self, value, line=None):
        super().__init__(line)
        self.value = value

    def __repr__(self):
        return f"Number({self.value})"


class Identifier(ASTNode):
    def __init__(self, name, line=None):
        super().__init__(line)
        self.name = name

    def __repr__(self):
        return f"Identifier({self.name})"


class StringLiteral(ASTNode):
    def __init__(self, value, line=None):
        super().__init__(line)
        self.value = value

    def __repr__(self):
        return f"StringLiteral({self.value!r})"


class FunctionCall(ASTNode):
    def __init__(self, name, arguments, line=None):
        super().__init__(line)
        self.name = name
        self.arguments = arguments

    def __repr__(self):
        return (
            f"FunctionCall(name={self.name}, "
            f"arguments={self.arguments})"
        )

# ==========================================
# Additional AST Nodes for C Syntax Support
# ==========================================

class ArrayDeclaration(ASTNode):
    def __init__(self, data_type, name, size=None, line=None):
        super().__init__(line)
        self.data_type = data_type
        self.name = name
        self.size = size

    def __repr__(self):
        return (
            f"ArrayDeclaration(type={self.data_type}, "
            f"name={self.name}, size={self.size})"
        )


class ArrayAccess(ASTNode):
    def __init__(self, name, index, line=None):
        super().__init__(line)
        self.name = name
        self.index = index

    def __repr__(self):
        return f"ArrayAccess(name={self.name}, index={self.index})"


class ArrayAssignment(ASTNode):
    def __init__(self, name, index, value, line=None):
        super().__init__(line)
        self.name = name
        self.index = index
        self.value = value

    def __repr__(self):
        return (
            f"ArrayAssignment(name={self.name}, "
            f"index={self.index}, value={self.value})"
        )


class UnaryOperation(ASTNode):
    def __init__(self, operator, operand, postfix=False, line=None):
        super().__init__(line)
        self.operator = operator
        self.operand = operand
        self.postfix = postfix

    def __repr__(self):
        return (
            f"UnaryOperation(operator={self.operator!r}, "
            f"operand={self.operand}, postfix={self.postfix})"
        )


class ForStatement(ASTNode):
    def __init__(self, initialization, condition, update, body, line=None):
        super().__init__(line)
        self.initialization = initialization
        self.condition = condition
        self.update = update
        self.body = body

    def __repr__(self):
        return (
            f"ForStatement(initialization={self.initialization}, "
            f"condition={self.condition}, update={self.update}, "
            f"body={self.body})"
        )


class ReturnStatement(ASTNode):
    def __init__(self, value=None, line=None):
        super().__init__(line)
        self.value = value

    def __repr__(self):
        return f"ReturnStatement(value={self.value})"


class FunctionDefinition(ASTNode):
    def __init__(
        self, return_type, name, parameters, body, line=None
    ):
        super().__init__(line)
        self.return_type = return_type
        self.name = name
        self.parameters = parameters
        self.body = body

    def __repr__(self):
        return (
            f"FunctionDefinition(return_type={self.return_type}, "
            f"name={self.name}, parameters={self.parameters}, "
            f"body={self.body})"
        )


class PointerAssignment(ASTNode):
    def __init__(self, name, value, line=None):
        super().__init__(line)
        self.name = name
        self.value = value

    def __repr__(self):
        return f"PointerAssignment(name={self.name}, value={self.value})"


class CastExpression(ASTNode):
    def __init__(self, target_type, operand, line=None):
        super().__init__(line)
        self.target_type = target_type
        self.operand = operand

    def __repr__(self):
        return f"CastExpression(type={self.target_type}, operand={self.operand})"


class SizeofExpression(ASTNode):
    def __init__(self, operand, line=None):
        super().__init__(line)
        self.operand = operand

    def __repr__(self):
        return f"SizeofExpression({self.operand})"


class MemberAccess(ASTNode):
    def __init__(self, base, member, arrow=False, line=None):
        super().__init__(line)
        self.base = base
        self.member = member
        self.arrow = arrow

    def __repr__(self):
        return f"MemberAccess(base={self.base}, member={self.member}, arrow={self.arrow})"


class JumpStatement(ASTNode):
    def __init__(self, kind, line=None):
        super().__init__(line)
        self.kind = kind

    def __repr__(self):
        return f"JumpStatement({self.kind})"
