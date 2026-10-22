"""Code normalisation and function segmentation shared by training and inference.

Keeping this in one module guarantees that the text a model sees at inference
time is produced exactly as it was during training.
"""
from __future__ import annotations

import re

MAX_FUNCTIONS = 200
MAX_FUNCTION_CHARS = 20_000

_TOKEN = re.compile(
    r'"(?:\\.|[^"\\\n])*"'          # string literal
    r"|'(?:\\.|[^'\\\n])*'"         # char literal
    r"|[A-Za-z_]\w*"                # identifier / keyword
    r"|\d+\.\d*(?:[eE][+-]?\d+)?|\.\d+|\d+"
    r"|->|\+\+|--|<<|>>|<=|>=|==|!=|&&|\|\||\+=|-=|\*=|/=|%="
    r"|[^\s]"
)
_FORMAT_SPEC = re.compile(r"%[-+ #0]*\d*(?:\.\d+)?(?:hh|h|ll|l|L|z|j|t)?[diouxXeEfFgGaAcspn%]")
# Identifiers that would leak the label in the Juliet test suite (function names such
# as CWE121_..._bad or goodG2B). They are replaced, never used as features.
_LEAKY_IDENTIFIER = re.compile(r"(?i)^(?:cwe\d+.*|.*bad.*|.*good.*)$")


def strip_comments(source: str) -> str:
    """Replace comments with spaces, keeping offsets and line numbers stable."""
    out = []
    i, n = 0, len(source)
    while i < n:
        ch = source[i]
        nxt = source[i + 1] if i + 1 < n else ""
        if ch == '"' or ch == "'":
            quote = ch
            out.append(ch)
            i += 1
            while i < n:
                out.append(source[i])
                if source[i] == "\\" and i + 1 < n:
                    out.append(source[i + 1])
                    i += 2
                    continue
                if source[i] == quote or source[i] == "\n":
                    i += 1
                    break
                i += 1
            continue
        if ch == "/" and nxt == "/":
            while i < n and source[i] != "\n":
                out.append(" ")
                i += 1
            continue
        if ch == "/" and nxt == "*":
            out.append("  ")
            i += 2
            while i < n and not (source[i] == "*" and i + 1 < n and source[i + 1] == "/"):
                out.append("\n" if source[i] == "\n" else " ")
                i += 1
            out.append("  ")
            i += 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)[: n + 2]


def normalize_code(source: str, function_names=()) -> str:
    """Comments removed, strings abstracted (format specifiers kept), label-leaking names replaced."""
    names = set(function_names)
    tokens = []
    for tok in _TOKEN.findall(strip_comments(source)):
        first = tok[0]
        if first == '"':
            tokens.append("STR")
            tokens.extend("FMT_" + spec[-1] for spec in _FORMAT_SPEC.findall(tok) if spec != "%%")
        elif first == "'":
            tokens.append("CHR")
        elif first.isalpha() or first == "_":
            if tok in names or _LEAKY_IDENTIFIER.match(tok):
                tokens.append("FUNC_OR_TAG")
            else:
                tokens.append(tok)
        else:
            tokens.append(tok)
    return " ".join(tokens)


def split_functions(source: str):
    """Return top-level function definitions as dicts with offsets and 1-based lines.

    Works on comment-masked text so braces in comments do not count. Returns an empty
    list when no function body is found (callers then treat the input as one scope).
    """
    code = strip_comments(source)
    n = len(code)
    functions = []
    depth = 0
    boundary = 0
    header_start = None
    i = 0
    line_start = True
    while i < n and len(functions) < MAX_FUNCTIONS:
        ch = code[i]
        if depth == 0 and line_start and ch == "#":
            while i < n and code[i] != "\n":
                if code[i] == "\\" and i + 1 < n and code[i + 1] == "\n":
                    i += 1
                i += 1
            boundary = i
            continue
        if ch == "\n":
            line_start = True
            i += 1
            continue
        if not ch.isspace():
            line_start = False
        if ch == '"' or ch == "'":
            quote = ch
            i += 1
            while i < n and code[i] != quote and code[i] != "\n":
                if code[i] == "\\":
                    i += 1
                i += 1
            i += 1
            continue
        if ch == "{":
            if depth == 0:
                header = code[boundary:i]
                header_start = boundary
                body_start = i
            depth += 1
        elif ch == "}":
            depth = max(depth - 1, 0)
            if depth == 0:
                header = code[header_start:body_start] if header_start is not None else ""
                match = re.search(r"([A-Za-z_]\w*)\s*\([^;{}]*\)\s*$", header.strip(), re.S)
                head_words = header.strip().split(None, 1)[:1]
                if match and head_words and head_words[0] not in {"struct", "union", "enum", "typedef"} \
                        and not re.match(r"\s*(?:if|for|while|switch)\b", header.strip()):
                    start = header_start + (len(header) - len(header.lstrip()))
                    end = i + 1
                    functions.append({
                        "name": match.group(1),
                        "start": start,
                        "end": end,
                        "start_line": source.count("\n", 0, start) + 1,
                        "end_line": source.count("\n", 0, end) + 1,
                        "text": source[start:end][:MAX_FUNCTION_CHARS],
                        "signature": " ".join(header.split())[:160],
                    })
                boundary = i + 1
                header_start = None
        elif ch == ";" and depth == 0:
            boundary = i + 1
        i += 1
    return functions


_C_KEYWORDS = {
    "auto", "break", "case", "char", "const", "continue", "default", "do", "double", "else", "enum",
    "extern", "float", "for", "goto", "if", "int", "long", "register", "return", "short", "signed",
    "sizeof", "static", "struct", "switch", "typedef", "union", "unsigned", "void", "volatile", "while",
    "STR", "CHR", "FUNC_OR_TAG",
}


def structure_tokens(normalized: str) -> str:
    """Lexer-derived structural view: identifiers become ID, called functions keep their name,
    numbers are bucketed by magnitude, keywords/operators/punctuation are kept as-is.

    This is *not* compiler IR; it only abstracts the token stream that the project's own lexer
    would produce, to test whether structure alone (without variable names) carries signal.
    """
    toks = normalized.split()
    out = []
    for i, tok in enumerate(toks):
        nxt = toks[i + 1] if i + 1 < len(toks) else ""
        head = tok[0]
        if head.isalpha() or head == "_":
            if tok in _C_KEYWORDS or tok.startswith("FMT_"):
                out.append(tok)
            elif nxt == "(":
                out.append("CALL_" + tok)
            else:
                out.append("ID")
        elif head.isdigit() or head == ".":
            if "." in tok:
                out.append("NUM_F")
            else:
                value = int(tok)
                out.append("NUM_0" if value == 0 else "NUM_1" if value == 1 else
                           "NUM_S" if value <= 20 else "NUM_M" if value <= 1000 else "NUM_L")
        else:
            out.append(tok)
    return " ".join(out)
