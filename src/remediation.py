"""Deterministic remediation proposals for SecureCompile findings.

Principles
- The submitted source is never modified: every proposal is a list of exact-offset edits
  against the original text, returned together with a diff.
- A fix is only proposed when the finding's own evidence (rule id + the code at its location)
  determines a well-defined rewrite. ML predictions alone never drive a repair.
- Where the right behaviour depends on intent (sizes, ownership, divisor policy ...) the result
  is ``review-required`` with guidance, not a guessed patch.
"""
from __future__ import annotations

import difflib
import hashlib
import re
from dataclasses import dataclass, field

from ml.features import split_functions

DETERMINISTIC = "deterministic"
WITH_ASSUMPTION = "deterministic-with-assumption"
REVIEW = "review-required"
UNAVAILABLE = "unavailable"


@dataclass
class Edit:
    start: int
    end: int
    replacement: str
    explanation: str
    finding_id: str | None = None
    rule_id: str | None = None


@dataclass
class FixProposal:
    finding_id: str | None
    rule_id: str | None
    kind: str
    summary: str
    edits: list = field(default_factory=list)
    assumptions: list = field(default_factory=list)
    guidance: str = ""
    guidance_snippet: str = ""
    reason: str = ""

    @property
    def available(self):
        return self.kind in (DETERMINISTIC, WITH_ASSUMPTION) and bool(self.edits)


# --------------------------------------------------------------------------- text helpers

def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def mask_source(source: str) -> str:
    """Blank out comments and the *contents* of string/char literals, preserving every offset."""
    out = list(source)
    i, n = 0, len(source)
    while i < n:
        ch = source[i]
        nxt = source[i + 1] if i + 1 < n else ""
        if ch == "/" and nxt == "/":
            while i < n and source[i] != "\n":
                out[i] = " "
                i += 1
        elif ch == "/" and nxt == "*":
            out[i] = out[i + 1] = " "
            i += 2
            while i < n and not (source[i] == "*" and i + 1 < n and source[i + 1] == "/"):
                if source[i] != "\n":
                    out[i] = " "
                i += 1
            if i < n:
                out[i] = " "
                if i + 1 < n:
                    out[i + 1] = " "
            i += 2
        elif ch in "\"'":
            quote = ch
            i += 1
            while i < n and source[i] != quote and source[i] != "\n":
                if source[i] == "\\" and i + 1 < n:
                    out[i] = " "
                    i += 1
                if source[i] != "\n":
                    out[i] = " "
                i += 1
            i += 1
        else:
            i += 1
    return "".join(out)


def line_of(source: str, offset: int) -> int:
    return source.count("\n", 0, offset) + 1


def parse_call(masked: str, name_start: int):
    """Return (open_paren, close_paren, [(arg_start, arg_end), ...]) for the call at ``name_start``."""
    match = re.compile(r"[A-Za-z_]\w*\s*\(").match(masked, name_start)
    if not match:
        return None
    open_idx = match.end() - 1
    depth, i, n = 0, open_idx, len(masked)
    args, arg_start = [], open_idx + 1
    while i < n:
        ch = masked[i]
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
            if depth == 0:
                if masked[arg_start:i].strip() or args:
                    args.append(_trim(masked, arg_start, i))
                return open_idx, i, args
        elif ch == "," and depth == 1:
            args.append(_trim(masked, arg_start, i))
            arg_start = i + 1
        elif ch == ";" and depth >= 1:
            return None  # unbalanced; refuse to guess
        i += 1
    return None


def _trim(text, start, end):
    while start < end and text[start].isspace():
        start += 1
    while end > start and text[end - 1].isspace():
        end -= 1
    return start, end


def locate_call(masked: str, source: str, finding: dict, name: str):
    """Find the start offset of ``name(`` for this finding (exact offset, else by line)."""
    loc = finding.get("location") or {}
    offset = loc.get("offset")
    if offset is not None and re.compile(rf"{re.escape(name)}\s*\(").match(masked, offset):
        return offset
    line = finding.get("line")
    if not line:
        return None
    starts = [0]
    for m in re.finditer("\n", source):
        starts.append(m.end())
    if line > len(starts):
        return None
    begin = starts[line - 1]
    end = starts[line] if line < len(starts) else len(source)
    matches = list(re.finditer(rf"\b{re.escape(name)}\s*\(", masked[begin:end]))
    if len(matches) != 1:
        return None  # ambiguous or absent: do not guess which call
    return begin + matches[0].start()


def is_statement(masked: str, call_start: int, close_idx: int) -> bool:
    before = masked[:call_start].rstrip()
    after = masked[close_idx + 1:].lstrip()
    if not after.startswith(";"):
        return False
    if not before:
        return True
    return before[-1] in ";{})" or re.search(r"\b(?:else|do)$", before) is not None


_TYPE_WORDS = r"(?:unsigned|signed|const|static|volatile|struct\s+\w+|int|long|short|char|float|double|size_t|void|\w+_t)"
_NOT_TYPES = {"return", "else", "case", "goto", "sizeof", "do", "if", "while", "for", "switch"}


def find_char_array(source, masked, name, use_offset):
    """Return (size_expr, reason) if ``name`` resolves to a visible fixed-size char array at ``use_offset``."""
    functions = split_functions(source)
    scope_start = 0
    for f in functions:
        if f["start"] <= use_offset <= f["end"]:
            scope_start = f["start"]
            header = masked[f["start"]: masked.find("{", f["start"])]
            if re.search(rf"\b{re.escape(name)}\b", header):
                return None, f"'{name}' is a function parameter (its size is not known here)."
            break
    window = masked[scope_start:use_offset]
    best = None  # (position, kind, size)
    array = re.compile(rf"\b(?:unsigned\s+|signed\s+)?char\s+(?:[^;(){{}}]*?,\s*)?{re.escape(name)}\s*\[\s*([^\]\n]+?)\s*\]\s*(?=[;=,])")
    for m in array.finditer(window):
        best = (m.start(), "array", m.group(1))
    other = re.compile(rf"\b({_TYPE_WORDS})\s+(?:[\w\s]*\s)?\**\s*{re.escape(name)}\s*(?=[;=,\[)])")
    for m in other.finditer(window):
        if m.group(1) in _NOT_TYPES:
            continue
        if best is None or m.start() > best[0]:
            kind = "array" if re.match(r"\s*\[", window[m.end():]) else "pointer-or-scalar"
            if kind == "pointer-or-scalar":
                best = (m.start(), kind, None)
    if best is None:
        return None, f"No visible declaration of '{name}' as a fixed-size char array."
    if best[1] != "array":
        return None, f"'{name}' is not declared as a char array here (sizeof would not give the buffer size)."
    return best[2], ""


def ensure_include(source: str, header: str):
    """Edit that adds ``#include <header>`` if missing; None if already present."""
    if re.search(rf"#\s*include\s*<{re.escape(header)}>", source):
        return None
    includes = list(re.finditer(r"^[ \t]*#\s*include[^\n]*\n?", source, re.M))
    if includes:
        last = includes[-1]
        text = last.group(0)
        prefix = "" if text.endswith("\n") else "\n"
        return Edit(last.end(), last.end(), f"{prefix}#include <{header}>\n",
                    f"Add #include <{header}>, which the replacement function needs.")
    return Edit(0, 0, f"#include <{header}>\n", f"Add #include <{header}>, which the replacement function needs.")


# --------------------------------------------------------------------------- strategies

def _review(finding, reason, guidance, snippet=""):
    return FixProposal(finding.get("id"), finding.get("rule_id"), REVIEW, "Developer review required",
                       reason=reason, guidance=guidance, guidance_snippet=snippet)


def _unavailable(finding, reason):
    return FixProposal(finding.get("id"), finding.get("rule_id"), UNAVAILABLE, "No automatic fix", reason=reason)


def _fix_gets(source, masked, finding):
    start = locate_call(masked, source, finding, "gets")
    call = parse_call(masked, start) if start is not None else None
    if not call:
        return _unavailable(finding, "Could not unambiguously locate the gets() call.")
    _, close, args = call
    if len(args) != 1 or not re.fullmatch(r"[A-Za-z_]\w*", source[args[0][0]:args[0][1]]):
        return _review(finding, "The gets() argument is not a plain variable name.",
                       "Replace gets(buf) with fgets(buf, <capacity of buf>, stdin) and handle a NULL return.")
    name = source[args[0][0]:args[0][1]]
    size, why = find_char_array(source, masked, name, start)
    if size is None:
        return _review(finding, why, f"Use fgets({name}, <capacity of {name}>, stdin); the capacity must come from the actual allocation.")
    original = source[start:close + 1]
    return FixProposal(finding["id"], finding["rule_id"], WITH_ASSUMPTION,
                       "Replace gets() with a size-limited fgets()",
                       edits=[Edit(start, close + 1, f"fgets({name}, sizeof({name}), stdin)",
                                   f"gets() cannot limit input length; fgets() reads at most sizeof({name}) - 1 characters.",
                                   finding["id"], finding["rule_id"])],
                       assumptions=[f"'{name}' is a char array in this scope, so sizeof({name}) is its capacity.",
                                    "fgets keeps the trailing newline (gets removed it) and returns NULL on end-of-file; "
                                    "the return value is not checked by this patch."])


_CONVERSION = re.compile(r"%(\*?)(\d*)(hh|h|ll|l|L|z|j|t)?([diouxXeEfFgGaAcspn%]|\[[^\]]*\])")


def _fix_scanf(source, masked, finding):
    start = locate_call(masked, source, finding, "scanf")
    call = parse_call(masked, start) if start is not None else None
    if not call:
        return _unavailable(finding, "Could not unambiguously locate the scanf() call.")
    _, close, args = call
    if not args or not source[args[0][0]:args[0][1]].startswith('"'):
        return _review(finding, "The scanf format is not a string literal.", "Add a field width to every %s conversion.")
    fmt_start, fmt_end = args[0]
    fmt = source[fmt_start:fmt_end]
    edits, assumptions = [], []
    arg_index = 1
    for m in _CONVERSION.finditer(fmt):
        if m.group(4) == "%":
            continue
        consumes = m.group(1) != "*"
        if m.group(4) == "s" and m.group(2) == "":
            if not consumes or arg_index >= len(args):
                return _review(finding, "A %s conversion has no matching destination argument.", "Check the format and arguments.")
            a_start, a_end = args[arg_index]
            dest = source[a_start:a_end]
            if not re.fullmatch(r"[A-Za-z_]\w*", dest):
                return _review(finding, f"Destination '{dest}' is not a plain variable name.",
                               "Use a field width of (buffer capacity - 1) for this %s.")
            size, why = find_char_array(source, masked, dest, start)
            if size is None or not re.fullmatch(r"\d+", size):
                return _review(finding, why or f"The size of '{dest}' is not an integer literal ({size}).",
                               f"Use %<capacity of {dest} minus 1>s; the width must be a literal in scanf.")
            width = int(size) - 1
            if width < 1:
                return _review(finding, f"'{dest}' has size {size}; no usable width.", "Enlarge the buffer first.")
            pos = fmt_start + m.start() + 1 + len(m.group(1))
            edits.append(Edit(pos, pos, str(width), f"Limit %s for '{dest}' to {width} characters, leaving room for the terminating NUL.",
                              finding["id"], finding["rule_id"]))
            assumptions.append(f"'{dest}' holds {size} bytes, so the width is {size} - 1 = {width}.")
        if consumes:
            arg_index += 1
    if not edits:
        return _unavailable(finding, "No unbounded %s conversion was found in the format literal.")
    return FixProposal(finding["id"], finding["rule_id"], WITH_ASSUMPTION,
                       "Add field widths to unbounded %s conversions", edits=edits, assumptions=assumptions)


def _fix_sprintf(source, masked, finding):
    start = locate_call(masked, source, finding, "sprintf")
    call = parse_call(masked, start) if start is not None else None
    if not call:
        return _unavailable(finding, "Could not unambiguously locate the sprintf() call.")
    open_idx, _, args = call
    if len(args) < 2 or not re.fullmatch(r"[A-Za-z_]\w*", source[args[0][0]:args[0][1]]):
        return _review(finding, "The destination is not a plain variable name.", "Use snprintf(dest, <capacity>, ...).")
    dest = source[args[0][0]:args[0][1]]
    size, why = find_char_array(source, masked, dest, start)
    if size is None:
        return _review(finding, why, f"Use snprintf({dest}, <capacity of {dest}>, ...).")
    edit = Edit(start, args[0][1], f"snprintf({dest}, sizeof({dest})",
                f"snprintf() takes the destination size, so output cannot exceed sizeof({dest}).",
                finding["id"], finding["rule_id"])
    return FixProposal(finding["id"], finding["rule_id"], WITH_ASSUMPTION,
                       "Replace sprintf() with snprintf()", edits=[edit],
                       assumptions=[f"'{dest}' is a char array in this scope.",
                                    "Output longer than the buffer is now truncated silently; the return value is not checked."])


def _fix_strcpy(source, masked, finding):
    start = locate_call(masked, source, finding, "strcpy")
    call = parse_call(masked, start) if start is not None else None
    if not call:
        return _unavailable(finding, "Could not unambiguously locate the strcpy() call.")
    _, close, args = call
    if len(args) != 2 or not is_statement(masked, start, close):
        return _review(finding, "strcpy() result is used or the call shape is unusual.",
                       "Copy with a bounded function and terminate the string explicitly.")
    dest = source[args[0][0]:args[0][1]]
    srcarg = source[args[1][0]:args[1][1]]
    if not re.fullmatch(r"[A-Za-z_]\w*", dest):
        return _review(finding, "The destination is not a plain variable name.", "Use a bounded copy with the real capacity.")
    size, why = find_char_array(source, masked, dest, start)
    if size is None:
        return _review(finding, why, f"Copy at most <capacity of {dest}> - 1 bytes and terminate.")
    edits = [Edit(start, close + 1, f'snprintf({dest}, sizeof({dest}), "%s", {srcarg})',
                  f"snprintf() writes at most sizeof({dest}) bytes and always NUL-terminates.",
                  finding["id"], finding["rule_id"])]
    inc = ensure_include(source, "stdio.h")
    if inc:
        inc.finding_id, inc.rule_id = finding["id"], finding["rule_id"]
        edits.append(inc)
    return FixProposal(finding["id"], finding["rule_id"], WITH_ASSUMPTION,
                       "Replace strcpy() with a bounded snprintf() copy", edits=edits,
                       assumptions=[f"'{dest}' is a char array in this scope.",
                                    "A source longer than the buffer is now truncated rather than overflowing; callers that relied on the full copy need review."])


def _fix_strcat(source, masked, finding):
    start = locate_call(masked, source, finding, "strcat")
    call = parse_call(masked, start) if start is not None else None
    if not call:
        return _unavailable(finding, "Could not unambiguously locate the strcat() call.")
    _, close, args = call
    if len(args) != 2 or not is_statement(masked, start, close):
        return _review(finding, "strcat() result is used or the call shape is unusual.", "Check remaining space before appending.")
    dest = source[args[0][0]:args[0][1]]
    srcarg = source[args[1][0]:args[1][1]]
    if not re.fullmatch(r"[A-Za-z_]\w*", dest):
        return _review(finding, "The destination is not a plain variable name.", "Check remaining space before appending.")
    size, why = find_char_array(source, masked, dest, start)
    if size is None:
        return _review(finding, why, f"Append at most <capacity of {dest}> - strlen({dest}) - 1 bytes.")
    edits = [Edit(start, close + 1, f"strncat({dest}, {srcarg}, sizeof({dest}) - strlen({dest}) - 1)",
                  f"strncat() with the remaining capacity ({dest} size minus current length minus the NUL) cannot overflow.",
                  finding["id"], finding["rule_id"])]
    inc = ensure_include(source, "string.h")
    if inc:
        inc.finding_id, inc.rule_id = finding["id"], finding["rule_id"]
        edits.append(inc)
    return FixProposal(finding["id"], finding["rule_id"], WITH_ASSUMPTION,
                       "Replace strcat() with a bounded strncat()", edits=edits,
                       assumptions=[f"'{dest}' is a char array in this scope and is already NUL-terminated.",
                                    "Appended text longer than the remaining space is truncated."])


def _fix_format_string(source, masked, finding):
    match = re.match(r"(\w+)\(\)", finding.get("message", ""))
    name = match.group(1) if match else None
    if name not in {"printf", "fprintf", "sprintf"}:
        return _unavailable(finding, "Unrecognised format-string call.")
    start = locate_call(masked, source, finding, name)
    call = parse_call(masked, start) if start is not None else None
    if not call:
        return _unavailable(finding, f"Could not unambiguously locate the {name}() call.")
    _, close, args = call
    index = 0 if name == "printf" else 1
    if len(args) != index + 1:
        return _review(finding, "The call passes extra arguments, so the non-literal format may be intentional.",
                       "Use a string literal as the format and pass user data only as arguments.")
    a_start, a_end = args[index]
    return FixProposal(finding["id"], finding["rule_id"], WITH_ASSUMPTION,
                       f'Print the value with a fixed "%s" format',
                       edits=[Edit(a_start, a_end, f'"%s", {source[a_start:a_end]}',
                                   "A literal format string prevents % directives in the data from being interpreted.",
                                   finding["id"], finding["rule_id"])],
                       assumptions=["The argument is meant to be printed as plain text, not used as a format with directives."])


def _fix_free_uninit(source, masked, finding):
    match = re.search(r"free\((\w+)\)", finding.get("message", ""))
    if not match:
        return _unavailable(finding, "Could not identify the pointer from the finding.")
    name = match.group(1)
    free_at = locate_call(masked, source, finding, "free")
    if free_at is None:
        return _unavailable(finding, "Could not unambiguously locate the free() call.")
    decl = None
    for m in re.finditer(rf"(\b[A-Za-z_][\w\s]*?\*+\s*{re.escape(name)})\s*;", masked[:free_at]):
        decl = m
    if decl is None:
        return _review(finding, f"No simple declaration of pointer '{name}' was found before the free().",
                       f"Initialise {name} to NULL or to a valid malloc/calloc result before it can be freed.")
    pos = decl.end(1)
    return FixProposal(finding["id"], finding["rule_id"], WITH_ASSUMPTION,
                       f"Initialise '{name}' to NULL",
                       edits=[Edit(pos, pos, " = NULL", f"free(NULL) is defined as a no-op, so {name} can no longer be an indeterminate pointer.",
                                   finding["id"], finding["rule_id"])],
                       assumptions=[f"This makes free({name}) safe but does not allocate memory; if {name} was meant to point to "
                                    "allocated data, the missing allocation is a logic error you still need to add."])


def _fix_double_free(source, masked, finding):
    match = re.search(r"free\((\w+)\)", finding.get("message", ""))
    if not match:
        return _unavailable(finding, "Could not identify the pointer from the finding.")
    name = match.group(1)
    pattern = re.compile(rf"\bfree\s*\(\s*{re.escape(name)}\s*\)\s*;")
    frees = list(pattern.finditer(masked))
    if len(frees) < 2:
        return _unavailable(finding, "The repeated free() calls were not found as simple statements.")
    first = frees[0]
    return FixProposal(finding["id"], finding["rule_id"], WITH_ASSUMPTION,
                       f"Set '{name}' to NULL after the first free()",
                       edits=[Edit(first.end(), first.end(), f" {name} = NULL;",
                                   f"A NULL pointer makes the later free({name}) a defined no-op.",
                                   finding["id"], finding["rule_id"])],
                       assumptions=[f"No other pointer aliases the same allocation, and {name} is not used between the two frees.",
                                    "The second free() is still redundant; consider removing it after reviewing control flow."])


def _fix_uninitialized(source, masked, finding):
    match = re.search(r"'(\w+)'", finding.get("message", ""))
    if not match:
        return _unavailable(finding, "Could not identify the variable from the finding.")
    name = match.group(1)
    line = finding.get("line") or 0
    upto = 0
    for _ in range(max(line - 1, 0)):
        upto = source.find("\n", upto) + 1
        if upto == 0:
            break
    decl = None
    for m in re.finditer(rf"\b((?:unsigned\s+|signed\s+|const\s+)*(?:int|long|short|char|float|double|size_t))\s+{re.escape(name)}\s*;", masked[:upto or len(masked)]):
        decl = m
    if decl is None:
        return _review(finding, f"No simple scalar declaration of '{name}' was found.", f"Give '{name}' a value that fits its purpose before use.")
    zero = "0.0" if re.search(r"float|double", decl.group(1)) else "0"
    pos = decl.end() - 1
    return FixProposal(finding["id"], finding["rule_id"], WITH_ASSUMPTION,
                       f"Initialise '{name}' to {zero}",
                       edits=[Edit(pos, pos, f" = {zero}", f"'{name}' now has a defined value when it is first read.",
                                   finding["id"], finding["rule_id"])],
                       assumptions=[f"{zero} is only a placeholder default. The correct starting value depends on what '{name}' represents; "
                                    "confirm it, because a wrong default can hide a logic error."])


_STRATEGIES = {
    "SC-MEM-001": _fix_gets,
    "SC-INPUT-001": _fix_scanf,
    "SC-MEM-004": _fix_sprintf,
    "SC-MEM-002": _fix_strcpy,
    "SC-MEM-003": _fix_strcat,
    "SC-INPUT-002": _fix_format_string,
    "SC-MEM-006": _fix_free_uninit,
    "SC-MEM-008": _fix_double_free,
    "SC-DATA-001": _fix_uninitialized,
}

_REVIEW_GUIDANCE = {
    "SC-ARITH-001": ("The correct behaviour when the divisor is zero (error, default value, skip) is a program decision.",
                     "Guard the operation, for example:\nif (divisor != 0) {\n    result = numerator / divisor;\n} else {\n    /* handle the error: report, return, or use a documented default */\n}"),
    "SC-ARITH-002": ("The correct behaviour when the modulus is zero is a program decision.",
                     "if (divisor != 0) {\n    result = numerator % divisor;\n} else {\n    /* handle the error */\n}"),
    "SC-ARITH-003": ("Overflow handling depends on the value ranges and types intended.",
                     "Use a wider type or check the operands first, e.g. if (a > INT_MAX - b) { /* handle overflow */ }"),
    "SC-MEM-005": ("The intended array length is not recorded in the code, so choosing one would be inventing a value.",
                   "Declare the variable as an array with the number of elements you actually need, e.g. int values[N];, and check every index against N."),
    "SC-MEM-007": ("Whether to check, allocate, or remove the dereference depends on the program's intent.",
                   "if (ptr != NULL) {\n    /* use *ptr */\n} else {\n    /* handle the missing object */\n}"),
    "SC-MEM-009": ("Fixing use-after-free needs ownership decisions (move the use before free, or extend the lifetime).",
                   "Move the access before free(), or do not free until the last use; set the pointer to NULL after free()."),
    "SC-MEM-010": ("Where to release memory depends on ownership across all return paths.",
                   "Call free(ptr) on every path that exits the pointer's lifetime, or document the ownership transfer."),
    "SC-CMD-001": ("Replacing a shell command depends on what it must do.",
                   "Prefer a direct API (e.g. exec* with an argument vector) and validate any externally supplied value against an allow-list."),
    "SC-RAND-001": ("Whether the sequence needs to be seeded or cryptographically secure depends on the use.",
                    "For simulations call srand() once at start-up; for security use an OS CSPRNG."),
    "SC-LOGIC-001": ("Whether the constant condition is intentional cannot be determined automatically.", ""),
    "SC-LOGIC-002": ("Whether the loop is meant to run forever cannot be determined automatically.", ""),
    "SC-LOGIC-003": ("Unreachable code may be dead code or a misplaced statement; only the author knows.", ""),
    "SC-LOGIC-004": ("Switch fall-through can be intentional.", ""),
}


def propose_fix(source: str, finding: dict, masked: str | None = None) -> FixProposal:
    """Propose a fix for one rule-backed finding. Never mutates ``source``."""
    if finding.get("origin") == "ml" or not finding.get("rule_id"):
        return _unavailable(finding, "This finding comes from the ML model only. A repair must be based on rule "
                                     "evidence and source context, not on a statistical category prediction.")
    masked = masked if masked is not None else mask_source(source)
    strategy = _STRATEGIES.get(finding["rule_id"])
    if strategy:
        try:
            return strategy(source, masked, finding)
        except Exception as exc:  # a remediation bug must never break the endpoint
            return _unavailable(finding, f"Fix generation failed ({type(exc).__name__}).")
    reason, snippet = _REVIEW_GUIDANCE.get(finding["rule_id"], ("No deterministic fix is defined for this rule.", ""))
    return _review(finding, reason, finding.get("suggestion", ""), snippet)


def propose_syntax_repair(repair: dict) -> Edit:
    return Edit(repair["offset"], repair["offset"], repair["insert"],
                f"Insert the missing '{repair['insert']}' at line {repair['line']}, column {repair['column']}.",
                finding_id=repair["id"], rule_id="SYNTAX")


# --------------------------------------------------------------------------- applying edits

def apply_edits(source: str, edits: list):
    """Apply non-overlapping edits to a *copy* of ``source``.

    Returns (new_source, applied, skipped). Overlapping edits are skipped, never merged guesswork.
    """
    ordered = sorted(edits, key=lambda e: (e.start, e.end))
    applied, skipped = [], []
    last_end = -1
    for edit in ordered:
        if edit.start < last_end or (applied and edit.start == applied[-1].start and edit.end == applied[-1].end
                                     and edit.replacement == applied[-1].replacement):
            skipped.append((edit, "overlaps or duplicates another edit"))
            continue
        applied.append(edit)
        last_end = max(last_end, edit.end)
    pieces, cursor = [], 0
    for edit in applied:
        pieces.append(source[cursor:edit.start])
        pieces.append(edit.replacement)
        cursor = edit.end
    pieces.append(source[cursor:])
    return "".join(pieces), applied, skipped


def unified_diff(original: str, proposed: str) -> str:
    return "".join(difflib.unified_diff(original.splitlines(keepends=True), proposed.splitlines(keepends=True),
                                        fromfile="original.c", tofile="proposed.c", n=2))


def describe_changes(source: str, applied: list):
    changes = []
    for edit in applied:
        line = line_of(source, edit.start)
        line_start = source.rfind("\n", 0, edit.start) + 1
        line_end = source.find("\n", edit.end)
        line_end = len(source) if line_end == -1 else line_end
        before = source[line_start:line_end]
        after = source[line_start:edit.start] + edit.replacement + source[edit.end:line_end]
        changes.append({"line": line, "before": before, "after": after, "explanation": edit.explanation,
                        "finding_id": edit.finding_id, "rule_id": edit.rule_id})
    return changes
