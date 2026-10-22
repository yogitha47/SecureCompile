
# ==========================================
# SecureCompile - Extended C Subset Parser
# ==========================================
#
# Recovery model (see parse_with_recovery):
#   1. A restricted *semicolon insertion* repair: when the parser reports an
#      error in a state that accepts ';' and the offending token starts a new
#      line (or is '}', a type keyword, or a statement keyword), a virtual ';'
#      is fed to the parser and the repair is recorded. The user's source is
#      never changed; the repair is only reported as a proposal.
#   2. Grammar-level `error` productions (statement, if/while conditions, call
#      arguments) for panic-mode resynchronisation, so later statements are
#      still parsed.
# Anything else is reported as a diagnostic only.

import os
import sys
import threading

import ply.yacc as yacc

from lexer import tokens, lexer as _base_lexer
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
    PointerAssignment,
    CastExpression,
    SizeofExpression,
    MemberAccess,
    JumpStatement,
)

start = "program"

precedence = (
    ("left", "OR"),
    ("left", "AND"),
    ("left", "BIT_OR"),
    ("left", "BIT_XOR"),
    ("left", "BIT_AND"),
    ("left", "EQ", "NE"),
    ("left", "LT", "LE", "GT", "GE"),
    ("left", "LSHIFT", "RSHIFT"),
    ("left", "PLUS", "MINUS"),
    ("left", "TIMES", "DIVIDE", "MOD"),
    ("right", "NOT", "BIT_NOT", "UMINUS", "UPLUS", "UADDR", "UDEREF", "CAST"),
)


def _flatten(items):
    out = []
    for item in items:
        if item is None:
            continue
        if isinstance(item, list):
            out.extend(_flatten(item))
        else:
            out.append(item)
    return out


# ------------------------------------------
# Program and statements
# ------------------------------------------

def p_program(p):
    """program : external_list"""
    p[0] = Program(p[1], line=1)


def p_external_list_multiple(p):
    """external_list : external_list external"""
    p[0] = p[1] + _flatten([p[2]])


def p_external_list_empty(p):
    """external_list : empty"""
    p[0] = []


def p_external(p):
    """external : statement
                | function_definition
                | function_prototype"""
    p[0] = p[1]


def p_statement(p):
    """statement : declaration
                 | assignment SEMICOLON
                 | array_assignment SEMICOLON
                 | pointer_assignment SEMICOLON
                 | if_statement
                 | while_statement
                 | for_statement
                 | function_call SEMICOLON
                 | return_statement
                 | jump_statement
                 | incdec_statement"""
    p[0] = p[1]


def p_statement_empty(p):
    """statement : SEMICOLON"""
    p[0] = None


def p_statement_error(p):
    """statement : error SEMICOLON"""
    p[0] = None


def p_block_compound(p):
    """block : compound_statement"""
    p[0] = p[1]


def p_block_single(p):
    """block : statement"""
    p[0] = _flatten([p[1]])


# ------------------------------------------
# Types and declarations
# ------------------------------------------

def p_type_word(p):
    """type_word : INT
                 | FLOAT
                 | DOUBLE
                 | CHAR
                 | VOID
                 | LONG
                 | SHORT
                 | SIGNED
                 | UNSIGNED
                 | CONST"""
    p[0] = p[1]


def p_type_struct(p):
    """type_word : STRUCT IDENTIFIER"""
    p[0] = f"struct {p[2]}"


def p_type_single(p):
    """type : type_word"""
    p[0] = p[1]


def p_type_multiple(p):
    """type : type type_word"""
    p[0] = f"{p[1]} {p[2]}"


def p_opt_stars(p):
    """opt_stars : stars
                 | empty"""
    p[0] = p[1] or ""


def p_stars(p):
    """stars : stars TIMES
             | TIMES"""
    p[0] = (p[1] + "*") if len(p) == 3 else "*"


def p_declaration(p):
    """declaration : type init_declarator_list SEMICOLON"""
    nodes = []
    for stars, name, size, has_size, value, is_array, line in p[2]:
        if is_array:
            node = ArrayDeclaration(p[1] + stars, name, size=size, line=p.lineno(1) or line)
            node.value = value
        else:
            node = Declaration(p[1] + stars, name, value, line=p.lineno(1) or line)
        nodes.append(node)
    p[0] = nodes


def p_init_declarator_list(p):
    """init_declarator_list : init_declarator_list COMMA init_declarator
                            | init_declarator"""
    p[0] = p[1] + [p[3]] if len(p) == 4 else [p[1]]


def p_init_declarator_plain(p):
    """init_declarator : opt_stars IDENTIFIER
                       | opt_stars IDENTIFIER ASSIGN expression"""
    value = p[4] if len(p) == 5 else None
    p[0] = (p[1], p[2], None, False, value, False, p.lineno(2))


def p_init_declarator_array(p):
    """init_declarator : opt_stars IDENTIFIER LBRACKET expression RBRACKET
                       | opt_stars IDENTIFIER LBRACKET RBRACKET
                       | opt_stars IDENTIFIER LBRACKET expression RBRACKET ASSIGN array_initializer
                       | opt_stars IDENTIFIER LBRACKET RBRACKET ASSIGN array_initializer"""
    size = None
    value = None
    if len(p) == 6:
        size = p[4]
    elif len(p) == 8:
        size = p[4]
        value = p[7]
    elif len(p) == 7:
        value = p[6]
    p[0] = (p[1], p[2], size, True, value, True, p.lineno(2))


def p_array_initializer(p):
    """array_initializer : expression
                         | LBRACE argument_list RBRACE"""
    p[0] = p[1] if len(p) == 2 else p[2]


# ------------------------------------------
# Assignments
# ------------------------------------------

def p_assignment(p):
    """assignment : IDENTIFIER ASSIGN expression"""
    p[0] = Assignment(p[1], p[3], line=p.lineno(1))


def p_assignment_compound(p):
    """assignment : IDENTIFIER PLUS_ASSIGN expression
                  | IDENTIFIER MINUS_ASSIGN expression
                  | IDENTIFIER TIMES_ASSIGN expression
                  | IDENTIFIER DIVIDE_ASSIGN expression
                  | IDENTIFIER MOD_ASSIGN expression"""
    operator = p[2][0]
    value = BinaryOperation(operator, Identifier(p[1], line=p.lineno(1)), p[3], line=p.lineno(2))
    p[0] = Assignment(p[1], value, line=p.lineno(1))


def p_array_assignment(p):
    """array_assignment : IDENTIFIER LBRACKET expression RBRACKET ASSIGN expression"""
    p[0] = ArrayAssignment(p[1], p[3], p[6], line=p.lineno(1))


def p_array_assignment_compound(p):
    """array_assignment : IDENTIFIER LBRACKET expression RBRACKET PLUS_ASSIGN expression
                        | IDENTIFIER LBRACKET expression RBRACKET MINUS_ASSIGN expression
                        | IDENTIFIER LBRACKET expression RBRACKET TIMES_ASSIGN expression
                        | IDENTIFIER LBRACKET expression RBRACKET DIVIDE_ASSIGN expression
                        | IDENTIFIER LBRACKET expression RBRACKET MOD_ASSIGN expression"""
    current = ArrayAccess(p[1], p[3], line=p.lineno(1))
    value = BinaryOperation(p[5][0], current, p[6], line=p.lineno(5))
    p[0] = ArrayAssignment(p[1], p[3], value, line=p.lineno(1))


def p_pointer_assignment(p):
    """pointer_assignment : TIMES IDENTIFIER ASSIGN expression"""
    p[0] = PointerAssignment(p[2], p[4], line=p.lineno(1))


def p_incdec_statement(p):
    """incdec_statement : IDENTIFIER INCREMENT SEMICOLON
                        | IDENTIFIER DECREMENT SEMICOLON"""
    p[0] = Assignment(
        p[1],
        BinaryOperation(p[2][0], Identifier(p[1], line=p.lineno(1)), Number(1, line=p.lineno(1)), line=p.lineno(1)),
        line=p.lineno(1),
    )


# ------------------------------------------
# Conditional and loop statements
# ------------------------------------------

def p_if_statement(p):
    """if_statement : IF LPAREN expression RPAREN block if_else"""
    p[0] = IfStatement(p[3], p[5], else_body=p[6], line=p.lineno(1))


def p_if_statement_error(p):
    """if_statement : IF LPAREN error RPAREN block if_else"""
    p[0] = IfStatement(Number(1, line=p.lineno(1)), p[5], else_body=p[6], line=p.lineno(1))
    p[0].condition_unparsed = True


def p_if_else(p):
    """if_else : ELSE block
               | empty"""
    p[0] = p[2] if len(p) == 3 else []


def p_while_statement(p):
    """while_statement : WHILE LPAREN expression RPAREN block"""
    p[0] = WhileStatement(p[3], p[5], line=p.lineno(1))


def p_while_statement_error(p):
    """while_statement : WHILE LPAREN error RPAREN block"""
    p[0] = WhileStatement(Identifier("<unparsed>", line=p.lineno(1)), p[5], line=p.lineno(1))
    p[0].condition_unparsed = True


def p_for_statement(p):
    """for_statement : FOR LPAREN for_initialization SEMICOLON optional_expression SEMICOLON for_update RPAREN block"""
    p[0] = ForStatement(p[3], p[5], p[7], p[9], line=p.lineno(1))


def p_for_initialization(p):
    """for_initialization : declaration_no_semicolon
                          | assignment
                          | empty"""
    p[0] = p[1]


def p_declaration_no_semicolon(p):
    """declaration_no_semicolon : type opt_stars IDENTIFIER
                                | type opt_stars IDENTIFIER ASSIGN expression"""
    value = p[5] if len(p) == 6 else None
    p[0] = Declaration(p[1] + p[2], p[3], value, line=p.lineno(1))


def p_optional_expression(p):
    """optional_expression : expression
                           | empty"""
    p[0] = p[1]


def p_for_update(p):
    """for_update : IDENTIFIER INCREMENT
                  | IDENTIFIER DECREMENT
                  | IDENTIFIER ASSIGN expression
                  | assignment_compound_update
                  | empty"""
    if len(p) == 3:
        p[0] = UnaryOperation(p[2], Identifier(p[1]), postfix=True, line=p.lineno(1))
    elif len(p) == 4:
        p[0] = Assignment(p[1], p[3], line=p.lineno(1))
    else:
        p[0] = p[1]


def p_for_update_compound(p):
    """assignment_compound_update : IDENTIFIER PLUS_ASSIGN expression
                                  | IDENTIFIER MINUS_ASSIGN expression"""
    value = BinaryOperation(p[2][0], Identifier(p[1], line=p.lineno(1)), p[3], line=p.lineno(2))
    p[0] = Assignment(p[1], value, line=p.lineno(1))


def p_compound_statement(p):
    """compound_statement : LBRACE statements RBRACE"""
    p[0] = p[2]


def p_statements_multiple(p):
    """statements : statements statement"""
    p[0] = p[1] + _flatten([p[2]])


def p_statements_empty(p):
    """statements :"""
    p[0] = []


def p_jump_statement(p):
    """jump_statement : BREAK SEMICOLON
                      | CONTINUE SEMICOLON"""
    p[0] = JumpStatement(p[1], line=p.lineno(1))


# ------------------------------------------
# Function definitions and return
# ------------------------------------------

def p_function_definition(p):
    """function_definition : type opt_stars IDENTIFIER LPAREN parameter_list RPAREN compound_statement"""
    p[0] = FunctionDefinition(p[1] + p[2], p[3], p[5], p[7], line=p.lineno(1))


def p_function_prototype(p):
    """function_prototype : type opt_stars IDENTIFIER LPAREN parameter_list RPAREN SEMICOLON"""
    p[0] = None


def p_parameter_list_multiple(p):
    """parameter_list : parameter_list COMMA parameter"""
    p[0] = p[1] + [p[3]]


def p_parameter_list_single(p):
    """parameter_list : parameter"""
    p[0] = [p[1]]


def p_parameter_list_void(p):
    """parameter_list : VOID"""
    p[0] = []


def p_parameter_list_empty(p):
    """parameter_list : empty"""
    p[0] = []


def p_parameter(p):
    """parameter : type opt_stars IDENTIFIER
                 | type opt_stars IDENTIFIER LBRACKET RBRACKET"""
    suffix = "[]" if len(p) == 6 else ""
    p[0] = Declaration(p[1] + p[2] + suffix, p[3], line=p.lineno(1))


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
    p[0] = FunctionCall(p[1], p[3], line=p.lineno(1))


def p_function_call_error(p):
    """function_call : IDENTIFIER LPAREN error RPAREN"""
    p[0] = FunctionCall(p[1], [], line=p.lineno(1))
    p[0].arguments_unparsed = True


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
    p[0] = BinaryOperation(p[2], p[1], p[3], line=p.lineno(2))


def p_expression_unary(p):
    """expression : MINUS expression %prec UMINUS
                  | PLUS expression %prec UPLUS
                  | NOT expression
                  | BIT_NOT expression
                  | BIT_AND expression %prec UADDR
                  | TIMES expression %prec UDEREF"""
    p[0] = UnaryOperation(p[1], p[2], line=p.lineno(1))


def p_expression_increment(p):
    """expression : IDENTIFIER INCREMENT
                  | IDENTIFIER DECREMENT"""
    p[0] = UnaryOperation(p[2], Identifier(p[1]), postfix=True, line=p.lineno(1))


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
    p[0] = ArrayAccess(p[1], p[3], line=p.lineno(1))


def p_factor_member(p):
    """factor : IDENTIFIER ARROW IDENTIFIER
              | IDENTIFIER DOT IDENTIFIER"""
    p[0] = MemberAccess(Identifier(p[1], line=p.lineno(1)), p[3], arrow=(p[2] == "->"), line=p.lineno(1))


def p_factor_string(p):
    """factor : STRING
              | CHARACTER"""
    p[0] = StringLiteral(p[1], line=p.lineno(1))


def p_factor_group(p):
    """factor : LPAREN expression RPAREN"""
    p[0] = p[2]


def p_factor_cast(p):
    """factor : LPAREN type opt_stars RPAREN expression %prec CAST"""
    p[0] = CastExpression(p[2] + p[3], p[5], line=p.lineno(1))


def p_factor_sizeof(p):
    """factor : SIZEOF LPAREN type opt_stars RPAREN
              | SIZEOF LPAREN expression RPAREN"""
    operand = (p[3] + p[4]) if len(p) == 6 else p[3]
    p[0] = SizeofExpression(operand, line=p.lineno(1))


def p_factor_call(p):
    """factor : function_call"""
    p[0] = p[1]


# ------------------------------------------
# Empty production and error handling
# ------------------------------------------

def p_empty(p):
    """empty :"""
    p[0] = None


_PUNCT = {
    "SEMICOLON": ";", "COMMA": ",", "LPAREN": "(", "RPAREN": ")", "LBRACE": "{",
    "RBRACE": "}", "LBRACKET": "[", "RBRACKET": "]", "ASSIGN": "=", "PLUS": "+",
    "MINUS": "-", "TIMES": "*", "DIVIDE": "/", "MOD": "%", "EQ": "==", "NE": "!=",
    "LT": "<", "GT": ">", "LE": "<=", "GE": ">=", "AND": "&&", "OR": "||",
    "NOT": "!", "BIT_AND": "&", "BIT_OR": "|", "BIT_XOR": "^", "BIT_NOT": "~",
    "LSHIFT": "<<", "RSHIFT": ">>", "DOT": ".", "ARROW": "->", "COLON": ":",
    "QUESTION": "?", "INCREMENT": "++", "DECREMENT": "--",
}
_STATEMENT_STARTERS = {
    "INT", "FLOAT", "DOUBLE", "CHAR", "VOID", "LONG", "SHORT", "SIGNED", "UNSIGNED",
    "CONST", "STRUCT", "IF", "WHILE", "FOR", "RETURN", "BREAK", "CONTINUE", "RBRACE",
}

# Per-parse state; parse_with_recovery holds _LOCK while this is in use.
_ctx = None
_LOCK = threading.Lock()
MAX_DIAGNOSTICS = 25


class _RecoveringLexer:
    """Token stream with a push-back queue and position bookkeeping."""

    def __init__(self, source):
        self.source = source
        self.lexer = _base_lexer.clone()
        self.lexer.errors = []
        self.lexer.lineno = 1
        self.lexer.input(source)
        self.queue = []
        self.prev = None
        self.current = None

    def input(self, _data):  # parser.parse(lexer=...) may call this
        pass

    @property
    def lineno(self):
        return self.lexer.lineno

    @property
    def lexpos(self):
        return self.lexer.lexpos

    def token(self):
        if self.queue:
            tok = self.queue.pop(0)
        else:
            tok = self.lexer.token()
            if tok is not None:
                tok.endpos = self.lexer.lexpos
        self.prev = self.current
        if tok is not None:
            self.current = tok
        return tok


def _position(source, offset):
    line = source.count("\n", 0, offset) + 1
    column = offset - (source.rfind("\n", 0, offset) + 1) + 1
    return line, column


def _readable(name):
    return _PUNCT.get(name, name.lower())


def p_error(tok):
    ctx = _ctx
    if ctx is None:
        return None
    source = ctx["source"]
    stream = ctx["stream"]
    state = parser.statestack[-1]
    expected = sorted(k for k in parser.action.get(state, {}) if k not in ("error", "$end"))
    prev = stream.prev if tok is not None else stream.current
    if tok is not None and stream.queue and stream.queue[0] is tok:
        prev = stream.prev

    ctx["error_count"] += 1
    if len(ctx["diagnostics"]) >= MAX_DIAGNOSTICS:
        ctx["truncated"] = True
        return None

    key = (tok.lexpos if tok is not None else -1)
    can_insert = False
    if prev is not None and "SEMICOLON" in expected and key not in ctx["repaired"]:
        if tok is None:
            can_insert = True
        else:
            prev_line, _ = _position(source, getattr(prev, "endpos", prev.lexpos) - 1)
            tok_line, _ = _position(source, tok.lexpos)
            can_insert = tok_line > prev_line or tok.type in _STATEMENT_STARTERS

    if can_insert:
        ctx["repaired"].add(key)
        end = getattr(prev, "endpos", prev.lexpos + 1)
        line, column = _position(source, end)
        found = "end of input" if tok is None else repr(str(tok.value))
        ctx["diagnostics"].append({
            "kind": "syntax", "severity": "error", "line": line, "column": column,
            "offset": end,
            "message": f"Missing ';' before {found}.",
            "expected": [_readable(e) for e in expected][:12],
            "found": None if tok is None else str(tok.value),
            "recovery": "semicolon-inserted",
        })
        ctx["repairs"].append({
            "id": f"syn-semicolon-{end}", "kind": "insert-semicolon", "line": line, "column": column,
            "offset": end, "insert": ";",
            "description": f"Insert ';' after line {line}, column {column - 1}.",
        })
        synthetic = _make_token("SEMICOLON", ";", prev.lineno, end)
        if tok is not None:
            stream.queue.insert(0, tok)
        parser.errok()
        return synthetic

    if tok is None:
        line, column = _position(source, len(source))
        message = "Unexpected end of input"
        ctx["diagnostics"].append({
            "kind": "syntax", "severity": "error", "line": line, "column": column,
            "offset": len(source), "message": message + _expected_suffix(expected),
            "expected": [_readable(e) for e in expected][:12], "found": None,
            "recovery": "none",
        })
        return None

    line, column = _position(source, tok.lexpos)
    ctx["diagnostics"].append({
        "kind": "syntax", "severity": "error", "line": line, "column": column,
        "offset": tok.lexpos,
        "message": f"Unexpected {str(tok.value)!r}" + _expected_suffix(expected),
        "expected": [_readable(e) for e in expected][:12], "found": str(tok.value),
        "recovery": "panic-mode-skip",
    })
    return None


def _expected_suffix(expected):
    readable = [_readable(e) for e in expected]
    if not readable or len(readable) > 8:
        return "."
    return "; expected one of: " + ", ".join(readable) + "."


def _make_token(type_, value, lineno, lexpos):
    import ply.lex as lex
    tok = lex.LexToken()
    tok.type = type_
    tok.value = value
    tok.lineno = lineno
    tok.lexpos = lexpos
    tok.endpos = lexpos
    return tok


# ------------------------------------------
# Build parser
# ------------------------------------------

_debug = bool(os.environ.get("SECURECOMPILE_PARSER_DEBUG"))
parser = yacc.yacc(
    debug=_debug, debugfile="parser.out", write_tables=False,
    errorlog=yacc.PlyLogger(sys.stderr) if _debug else yacc.NullLogger(),
)


def parse_with_recovery(source):
    """Parse `source` and return AST plus structured diagnostics.

    Returns a dict: ast, diagnostics, repairs, status ('complete' | 'recovered' |
    'failed'), truncated. The input string is never modified.
    """
    global _ctx
    with _LOCK:
        stream = _RecoveringLexer(source)
        _ctx = {"source": source, "stream": stream, "diagnostics": [], "repairs": [],
                "repaired": set(), "error_count": 0, "truncated": False}
        try:
            try:
                ast = parser.parse(lexer=stream, tracking=True)
            except RecursionError:
                ast = None
                _ctx["diagnostics"].append({
                    "kind": "syntax", "severity": "error", "line": 1, "column": 1, "offset": 0,
                    "message": "Source nesting is too deep to parse.", "expected": [], "found": None,
                    "recovery": "none"})
            diagnostics = list(_ctx["diagnostics"])
            for err in stream.lexer.errors:
                line, column = _position(source, err["lexpos"])
                diagnostics.append({
                    "kind": "lexical", "severity": "error", "line": line, "column": column,
                    "offset": err["lexpos"], "message": f"Illegal character {err['char']!r}.",
                    "expected": [], "found": err["char"], "recovery": "character-skipped"})
            diagnostics.sort(key=lambda d: (d["line"], d["column"]))
            repairs = list(_ctx["repairs"])
            truncated = _ctx["truncated"]
        finally:
            _ctx = None
    if ast is None:
        status = "failed"
    elif diagnostics:
        status = "recovered"
    else:
        status = "complete"
    return {"ast": ast, "diagnostics": diagnostics, "repairs": repairs, "status": status,
            "truncated": truncated}
