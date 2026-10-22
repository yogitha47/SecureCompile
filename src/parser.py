
# ==========================================
# SecureCompile - Extended C Subset Parser
# ==========================================

import ply.yacc as yacc

from lexer import tokens
from ast_nodes import (
    Program,
    Declaration,
    Assignment,
    IfStatement,
    WhileStatement,
    BinaryOperation,
    Number,
    Identifier,
    StringLiteral,
    FunctionCall,
    ArrayDeclaration,
    ArrayAccess,
    ArrayAssignment,
    UnaryOperation,
    ForStatement,
    ReturnStatement,
    FunctionDefinition,
)

start = "program"

precedence = (
    ("left", "OR"),
    ("left", "AND"),
    ("left", "EQ", "NE"),
    ("left", "LT", "LE", "GT", "GE"),
    ("left", "BIT_OR"),
    ("left", "BIT_XOR"),
    ("left", "BIT_AND"),
    ("left", "LSHIFT", "RSHIFT"),
    ("left", "PLUS", "MINUS"),
    ("left", "TIMES", "DIVIDE", "MOD"),
    ("right", "NOT", "BIT_NOT", "UMINUS", "UPLUS"),
)

# ------------------------------------------
# Program and statements
# ------------------------------------------

def p_program(p):
    """program : external_list"""
    p[0] = Program(p[1], line=1)


def p_external_list_multiple(p):
    """external_list : external_list external"""
    p[0] = p[1] + [p[2]]


def p_external_list_empty(p):
    """external_list : empty"""
    p[0] = []


def p_external(p):
    """external : statement
                | function_definition"""
    p[0] = p[1]


def p_statement(p):
    """statement : declaration
                 | array_declaration
                 | assignment SEMICOLON
                 | array_assignment SEMICOLON
                 | if_statement
                 | while_statement
                 | for_statement
                 | function_call SEMICOLON
                 | return_statement
                 | SEMICOLON"""
    p[0] = None if p.slice[1].type == "SEMICOLON" else p[1]


# ------------------------------------------
# Types and declarations
# ------------------------------------------

def p_type(p):
    """type : INT
            | FLOAT
            | DOUBLE
            | CHAR
            | VOID
            | LONG
            | SHORT
            | SIGNED
            | UNSIGNED"""
    p[0] = p[1]


def p_declaration(p):
    """declaration : type IDENTIFIER SEMICOLON
                   | type IDENTIFIER ASSIGN expression SEMICOLON"""
    if len(p) == 4:
        p[0] = Declaration(p[1], p[2], line=p.lineno(1))
    else:
        p[0] = Declaration(
            p[1], p[2], p[4], line=p.lineno(1)
        )


def p_array_declaration(p):
    """array_declaration : type IDENTIFIER LBRACKET expression RBRACKET SEMICOLON
                         | type IDENTIFIER LBRACKET RBRACKET SEMICOLON"""
    size = p[4] if len(p) == 7 else None
    p[0] = ArrayDeclaration(
        p[1], p[2], size=size, line=p.lineno(1)
    )


# ------------------------------------------
# Assignments
# ------------------------------------------

def p_assignment(p):
    """assignment : IDENTIFIER ASSIGN expression"""
    p[0] = Assignment(
        p[1], p[3], line=p.lineno(1)
    )


def p_array_assignment(p):
    """array_assignment : IDENTIFIER LBRACKET expression RBRACKET ASSIGN expression"""
    p[0] = ArrayAssignment(
        p[1], p[3], p[6], line=p.lineno(1)
    )


# ------------------------------------------
# Conditional and loop statements
# ------------------------------------------

def p_if_statement(p):
    """if_statement : IF LPAREN expression RPAREN compound_statement if_else"""
    p[0] = IfStatement(
        p[3], p[5], else_body=p[6], line=p.lineno(1)
    )


def p_if_else(p):
    """if_else : ELSE compound_statement
               | empty"""
    p[0] = p[2] if len(p) == 3 else []


def p_while_statement(p):
    """while_statement : WHILE LPAREN expression RPAREN compound_statement"""
    p[0] = WhileStatement(
        p[3], p[5], line=p.lineno(1)
    )


def p_for_statement(p):
    """for_statement : FOR LPAREN for_initialization SEMICOLON optional_expression SEMICOLON for_update RPAREN compound_statement"""
    p[0] = ForStatement(
        p[3], p[5], p[7], p[9], line=p.lineno(1)
    )


def p_for_initialization(p):
    """for_initialization : declaration_no_semicolon
                          | assignment
                          | empty"""
    p[0] = p[1]


def p_declaration_no_semicolon(p):
    """declaration_no_semicolon : type IDENTIFIER
                                | type IDENTIFIER ASSIGN expression"""
    if len(p) == 3:
        p[0] = Declaration(p[1], p[2], line=p.lineno(1))
    else:
        p[0] = Declaration(
            p[1], p[2], p[4], line=p.lineno(1)
        )


def p_optional_expression(p):
    """optional_expression : expression
                           | empty"""
    p[0] = p[1]


def p_for_update(p):
    """for_update : IDENTIFIER INCREMENT
                  | IDENTIFIER DECREMENT
                  | IDENTIFIER ASSIGN expression
                  | empty"""
    if len(p) == 3:
        p[0] = UnaryOperation(
            p[2], Identifier(p[1]), postfix=True,
            line=p.lineno(1)
        )
    elif len(p) == 4:
        p[0] = Assignment(
            p[1], p[3], line=p.lineno(1)
        )
    else:
        p[0] = None


def p_compound_statement(p):
    """compound_statement : LBRACE statements RBRACE"""
    p[0] = p[2]


def p_statements_multiple(p):
    """statements : statements statement"""
    p[0] = p[1] + ([] if p[2] is None else [p[2]])


def p_statements_empty(p):
    """statements :"""
    p[0] = []





# ------------------------------------------
# Function definitions and return
# ------------------------------------------

def p_function_definition(p):
    """function_definition : type IDENTIFIER LPAREN parameter_list RPAREN compound_statement"""
    p[0] = FunctionDefinition(
        p[1], p[2], p[4], p[6], line=p.lineno(1)
    )


def p_parameter_list_multiple(p):
    """parameter_list : parameter_list COMMA parameter"""
    p[0] = p[1] + [p[3]]


def p_parameter_list_single(p):
    """parameter_list : parameter"""
    p[0] = [p[1]]


def p_parameter_list_empty(p):
    """parameter_list : empty"""
    p[0] = []


def p_parameter(p):
    """parameter : type IDENTIFIER"""
    p[0] = Declaration(p[1], p[2], line=p.lineno(1))


def p_return_statement(p):
    """return_statement : RETURN expression SEMICOLON
                        | RETURN SEMICOLON"""
    value = p[2] if len(p) == 4 else None
    p[0] = ReturnStatement(value, line=p.lineno(1))


# ------------------------------------------
# Function calls and arguments
# ------------------------------------------

def p_function_call(p):
    """function_call : IDENTIFIER LPAREN argument_list RPAREN"""
    p[0] = FunctionCall(
        p[1], p[3], line=p.lineno(1)
    )


def p_argument_list_multiple(p):
    """argument_list : argument_list COMMA expression"""
    p[0] = p[1] + [p[3]]


def p_argument_list_single(p):
    """argument_list : expression"""
    p[0] = [p[1]]


def p_argument_list_empty(p):
    """argument_list : empty"""
    p[0] = []


# ------------------------------------------
# Expressions
# ------------------------------------------

def p_expression_binary(p):
    """expression : expression PLUS expression
                  | expression MINUS expression
                  | expression TIMES expression
                  | expression DIVIDE expression
                  | expression MOD expression
                  | expression EQ expression
                  | expression NE expression
                  | expression LT expression
                  | expression LE expression
                  | expression GT expression
                  | expression GE expression
                  | expression AND expression
                  | expression OR expression
                  | expression BIT_AND expression
                  | expression BIT_OR expression
                  | expression BIT_XOR expression
                  | expression LSHIFT expression
                  | expression RSHIFT expression"""
    operators = {
        "+": "+", "-": "-", "*": "*", "/": "/", "%": "%",
        "==": "==", "!=": "!=", "<": "<", "<=": "<=",
        ">": ">", ">=": ">=", "&&": "&&", "||": "||",
        "&": "&", "|": "|", "^": "^", "<<": "<<", ">>": ">>",
    }
    p[0] = BinaryOperation(
        operators[p[2]], p[1], p[3], line=p.lineno(2)
    )


def p_expression_unary(p):
    """expression : MINUS expression %prec UMINUS
                  | PLUS expression %prec UPLUS
                  | NOT expression
                  | BIT_NOT expression"""
    p[0] = UnaryOperation(
        p[1], p[2], line=p.lineno(1)
    )


def p_expression_increment(p):
    """expression : IDENTIFIER INCREMENT
                  | IDENTIFIER DECREMENT"""
    p[0] = UnaryOperation(
        p[2], Identifier(p[1]), postfix=True,
        line=p.lineno(1)
    )


def p_expression_term(p):
    """expression : factor"""
    p[0] = p[1]


# ------------------------------------------
# Factors
# ------------------------------------------

def p_factor_number(p):
    """factor : NUMBER"""
    p[0] = Number(p[1], line=p.lineno(1))


def p_factor_identifier(p):
    """factor : IDENTIFIER"""
    p[0] = Identifier(p[1], line=p.lineno(1))


def p_factor_array_access(p):
    """factor : IDENTIFIER LBRACKET expression RBRACKET"""
    p[0] = ArrayAccess(
        p[1], p[3], line=p.lineno(1)
    )


def p_factor_string(p):
    """factor : STRING
              | CHARACTER"""
    p[0] = StringLiteral(p[1], line=p.lineno(1))


def p_factor_group(p):
    """factor : LPAREN expression RPAREN"""
    p[0] = p[2]


def p_factor_call(p):
    """factor : function_call"""
    p[0] = p[1]


# ------------------------------------------
# Empty production and error handling
# ------------------------------------------

def p_empty(p):
    """empty :"""
    p[0] = None


def p_error(p):
    if p:
        print(
            f"Syntax error near {p.value!r} "
            f"at line {p.lineno}"
        )
    else:
        print("Syntax error at end of input")


# ------------------------------------------
# Build parser
# ------------------------------------------

parser = yacc.yacc()
