
import ply.lex as lex

# --------------------------------------
# Reserved C keywords
# --------------------------------------

reserved = {
    "int": "INT",
    "float": "FLOAT",
    "double": "DOUBLE",
    "char": "CHAR",
    "void": "VOID",
    "long": "LONG",
    "short": "SHORT",
    "signed": "SIGNED",
    "unsigned": "UNSIGNED",
    "const": "CONST",
    "if": "IF",
    "else": "ELSE",
    "while": "WHILE",
    "for": "FOR",
    "do": "DO",
    "return": "RETURN",
    "break": "BREAK",
    "continue": "CONTINUE",
    "switch": "SWITCH",
    "case": "CASE",
    "default": "DEFAULT",
    "sizeof": "SIZEOF",
    "struct": "STRUCT",
}

# --------------------------------------
# Tokens
# --------------------------------------

tokens = [
    "IDENTIFIER",
    "NUMBER",
    "STRING",
    "CHARACTER",

    # Arithmetic operators
    "PLUS", "MINUS", "TIMES", "DIVIDE", "MOD",
    "INCREMENT", "DECREMENT",

    # Assignment operators
    "ASSIGN", "PLUS_ASSIGN", "MINUS_ASSIGN",
    "TIMES_ASSIGN", "DIVIDE_ASSIGN", "MOD_ASSIGN",

    # Comparison operators
    "EQ", "NE", "LT", "GT", "LE", "GE",

    # Logical and bitwise operators
    "AND", "OR", "NOT",
    "BIT_AND", "BIT_OR", "BIT_XOR", "BIT_NOT",
    "LSHIFT", "RSHIFT",

    # Punctuation
    "LPAREN", "RPAREN",
    "LBRACE", "RBRACE",
    "LBRACKET", "RBRACKET",
    "SEMICOLON", "COMMA", "DOT", "COLON", "QUESTION",
] + list(reserved.values())

# --------------------------------------
# Ignore preprocessor directive lines
# Examples: #include <stdio.h>, #define SIZE 10
# --------------------------------------

def t_PREPROCESSOR(t):
    r"\#[^\n]*"
    pass


# --------------------------------------
# Comments
# --------------------------------------

def t_LINE_COMMENT(t):
    r"//[^\n]*"
    pass


def t_BLOCK_COMMENT(t):
    r"/\*[\s\S]*?\*/"
    t.lexer.lineno += t.value.count("\n")
    pass


# --------------------------------------
# Multi-character operators
# Keep these before single-character operator rules.
# --------------------------------------

t_INCREMENT = r"\+\+"
t_DECREMENT = r"--"

t_PLUS_ASSIGN = r"\+="
t_MINUS_ASSIGN = r"-="
t_TIMES_ASSIGN = r"\*="
t_DIVIDE_ASSIGN = r"/="
t_MOD_ASSIGN = r"%="

t_EQ = r"=="
t_NE = r"!="
t_LE = r"<="
t_GE = r">="

t_AND = r"&&"
t_OR = r"\|\|"
t_LSHIFT = r"<<"
t_RSHIFT = r">>"

# --------------------------------------
# Single-character operators
# --------------------------------------

t_PLUS = r"\+"
t_MINUS = r"-"
t_TIMES = r"\*"
t_DIVIDE = r"/"
t_MOD = r"%"

t_ASSIGN = r"="
t_LT = r"<"
t_GT = r">"
t_NOT = r"!"

t_BIT_AND = r"&"
t_BIT_OR = r"\|"
t_BIT_XOR = r"\^"
t_BIT_NOT = r"~"

# --------------------------------------
# Punctuation
# --------------------------------------

t_LPAREN = r"\("
t_RPAREN = r"\)"
t_LBRACE = r"\{"
t_RBRACE = r"\}"
t_LBRACKET = r"\["
t_RBRACKET = r"\]"

t_SEMICOLON = r";"
t_COMMA = r","
t_DOT = r"\."
t_COLON = r":"
t_QUESTION = r"\?"


# --------------------------------------
# String literals
# --------------------------------------

def t_STRING(t):
    r'"([^"\\\n]|\\.)*"'
    return t


# --------------------------------------
# Character literals
# --------------------------------------

def t_CHARACTER(t):
    r"'([^'\\\n]|\\.)'"
    return t


# --------------------------------------
# Numbers
# Supports integers, decimals and exponents.
# --------------------------------------

def t_NUMBER(t):
    r"((\d+\.\d*|\.\d+)([eE][+-]?\d+)?|\d+[eE][+-]?\d+|\d+)"

    if any(c in t.value for c in ".eE"):
        t.value = float(t.value)
    else:
        t.value = int(t.value)

    return t


# --------------------------------------
# Identifiers and keywords
# --------------------------------------

def t_IDENTIFIER(t):
    r"[a-zA-Z_][a-zA-Z0-9_]*"
    t.type = reserved.get(t.value, "IDENTIFIER")
    return t


# --------------------------------------
# Line tracking and ignored whitespace
# --------------------------------------

t_ignore = " \t\r"


def t_newline(t):
    r"\n+"
    t.lexer.lineno += len(t.value)


# --------------------------------------
# Lexical error tracking
# --------------------------------------

def t_error(t):
    message = (
        f"Illegal character {t.value[0]!r} "
        f"at line {t.lineno}"
    )

    errors = getattr(t.lexer, "errors", None)

    if errors is None:
        t.lexer.errors = []
        errors = t.lexer.errors

    errors.append(message)
    print(message)
    t.lexer.skip(1)


# --------------------------------------
# Build lexer
# --------------------------------------

lexer = lex.lex()
