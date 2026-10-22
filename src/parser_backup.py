
# ==========================================
# SecureCompile - Parser
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
    FunctionCall
)


def p_program(p):
    """program : statements"""
    p[0] = Program(p[1], line=1)


def p_statements_multiple(p):
    """statements : statements statement"""
    p[0] = p[1] + [p[2]]


def p_statements_single(p):
    """statements : statement"""
    p[0] = [p[1]]


def p_statement_declaration(p):
    """statement : declaration"""
    p[0] = p[1]


def p_statement_assignment(p):
    """statement : assignment"""
    p[0] = p[1]



def p_statement_if(p):
    """
    statement : IF LPAREN expression RPAREN LBRACE statements RBRACE if_else
    """
    p[0] = IfStatement(
        p[3],
        p[6],
        else_body=p[8],
        line=p.lineno(1)
    )


def p_if_else(p):
    """
    if_else : ELSE LBRACE statements RBRACE
            | empty
    """
    p[0] = p[3] if len(p) == 5 else []


def p_statement_while(p):
    """
    statement : WHILE LPAREN expression RPAREN LBRACE statements RBRACE
    """
    p[0] = WhileStatement(
        p[3],
        p[6],
        line=p.lineno(1)
    )


def p_statement_function_call(p):
    """statement : function_call SEMICOLON"""
    p[0] = p[1]


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


def p_empty(p):
    """empty :"""
    p[0] = None


def p_declaration(p):
    """declaration : type IDENTIFIER SEMICOLON
                   | type IDENTIFIER ASSIGN expression SEMICOLON"""

    if len(p) == 4:
        p[0] = Declaration(
            p[1], p[2], line=p.lineno(1)
        )
    else:
        p[0] = Declaration(
            p[1], p[2], p[4], line=p.lineno(1)
        )


def p_type(p):
    """type : INT
            | FLOAT
            | CHAR"""
    p[0] = p[1]


def p_assignment(p):
    """assignment : IDENTIFIER ASSIGN expression SEMICOLON"""
    p[0] = Assignment(
        p[1], p[3], line=p.lineno(1)
    )


# ------------------------------------------
# Expressions
# ------------------------------------------

def p_expression_plus(p):
    """expression : expression PLUS term"""
    p[0] = BinaryOperation(
        "+", p[1], p[3], line=p.lineno(2)
    )


def p_expression_minus(p):
    """expression : expression MINUS term"""
    p[0] = BinaryOperation(
        "-", p[1], p[3], line=p.lineno(2)
    )


def p_expression_eq(p):
    """expression : expression EQ term"""
    p[0] = BinaryOperation(
        "==", p[1], p[3], line=p.lineno(2)
    )


def p_expression_ne(p):
    """expression : expression NE term"""
    p[0] = BinaryOperation(
        "!=", p[1], p[3], line=p.lineno(2)
    )


def p_expression_lt(p):
    """expression : expression LT term"""
    p[0] = BinaryOperation(
        "<", p[1], p[3], line=p.lineno(2)
    )


def p_expression_gt(p):
    """expression : expression GT term"""
    p[0] = BinaryOperation(
        ">", p[1], p[3], line=p.lineno(2)
    )


def p_expression_le(p):
    """expression : expression LE term"""
    p[0] = BinaryOperation(
        "<=", p[1], p[3], line=p.lineno(2)
    )


def p_expression_ge(p):
    """expression : expression GE term"""
    p[0] = BinaryOperation(
        ">=", p[1], p[3], line=p.lineno(2)
    )


def p_expression_term(p):
    """expression : term"""
    p[0] = p[1]


# ------------------------------------------
# Arithmetic terms
# ------------------------------------------

def p_term_times(p):
    """term : term TIMES factor"""
    p[0] = BinaryOperation(
        "*", p[1], p[3], line=p.lineno(2)
    )


def p_term_divide(p):
    """term : term DIVIDE factor"""
    p[0] = BinaryOperation(
        "/", p[1], p[3], line=p.lineno(2)
    )


def p_term_modulo(p):
    """term : term MOD factor"""
    p[0] = BinaryOperation(
        "%", p[1], p[3], line=p.lineno(2)
    )


def p_term_factor(p):
    """term : factor"""
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


def p_factor_string(p):
    """factor : STRING"""
    p[0] = StringLiteral(
        p[1], line=p.lineno(1)
    )


def p_factor_group(p):
    """factor : LPAREN expression RPAREN"""
    p[0] = p[2]


# ------------------------------------------
# Error handling
# ------------------------------------------

def p_error(p):
    if p:
        print(
            f"Syntax error near '{p.value}' "
            f"at line {p.lineno}"
        )
    else:
        print("Syntax error at end of input")


# ------------------------------------------
# Build parser
# ------------------------------------------

parser = yacc.yacc()
