"""Conservative source-level checks used when the restricted AST parser cannot parse C.

This is a heuristic fallback, not a complete C compiler or proof of safety.
It intentionally accepts broad C syntax and reports only patterns it can recognize.
"""
from __future__ import annotations
import re


def _remove_comments(source: str) -> str:
    """Remove C comments while preserving quoted strings/chars and line numbers."""
    out = []
    i = 0
    state = "normal"
    while i < len(source):
        ch = source[i]
        nxt = source[i + 1] if i + 1 < len(source) else ""
        if state == "normal":
            if ch == '"':
                state = "string"; out.append(ch); i += 1; continue
            if ch == "'":
                state = "char"; out.append(ch); i += 1; continue
            if ch == "/" and nxt == "/":
                state = "line_comment"; out.extend("  "); i += 2; continue
            if ch == "/" and nxt == "*":
                state = "block_comment"; out.extend("  "); i += 2; continue
            out.append(ch); i += 1; continue
        if state in {"string", "char"}:
            out.append(ch)
            if ch == "\\" and i + 1 < len(source):
                out.append(source[i + 1]); i += 2; continue
            if (state == "string" and ch == '"') or (state == "char" and ch == "'"):
                state = "normal"
            i += 1; continue
        if state == "line_comment":
            if ch == "\n":
                out.append("\n"); state = "normal"
            else:
                out.append(" ")
            i += 1; continue
        if state == "block_comment":
            if ch == "*" and nxt == "/":
                out.extend("  "); i += 2; state = "normal"; continue
            out.append("\n" if ch == "\n" else " "); i += 1
    return "".join(out)


def _finding(rule_id, category, severity, confidence, message, explanation, suggestion, line):
    return {"rule_id": rule_id, "type": category, "severity": severity,
            "confidence": confidence, "message": message, "explanation": explanation,
            "suggestion": suggestion, "line": line}


def analyze_source(source: str) -> list[dict]:
    code = _remove_comments(source)
    findings = []

    def add_once(f):
        key = (f["rule_id"], f.get("line"))
        if not any((x["rule_id"], x.get("line")) == key for x in findings):
            findings.append(f)

    # Existing unsafe APIs: source fallback works even when full functions/headers are present.
    unsafe = {
        "gets": ("SC-MEM-001", "gets() has no destination-size limit.", "Replace gets() with fgets() and pass the actual buffer capacity."),
        "strcpy": ("SC-MEM-002", "strcpy() does not check destination capacity.", "Check buffer sizes and use a bounded copy with correct null termination."),
        "strcat": ("SC-MEM-003", "strcat() can overflow the destination buffer.", "Check remaining destination capacity before appending."),
        "sprintf": ("SC-MEM-004", "sprintf() writes without a destination-size limit.", "Use snprintf() with the actual destination capacity and check its return value."),
    }
    for name, (rid, explanation, suggestion) in unsafe.items():
        for m in re.finditer(rf"\b{ name }\s*\(", code):
            add_once(_finding(rid, "Potentially Unsafe Function", "HIGH", "MEDIUM",
                              f"Potentially unsafe function '{name}' detected.", explanation, suggestion,
                              code.count("\n", 0, m.start()) + 1))

    # scanf %s with no field width. Handles ordinary literal formats.
    for m in re.finditer(r'\bscanf\s*\(\s*("(?:\\.|[^"\\])*"|[^,\n]+)', code):
        fmt = m.group(1).strip()
        if fmt.startswith('"') and re.search(r"%(?!%)(?:\d+)?s", fmt) and not re.search(r"%(?!%)(?:\d+)s", fmt):
            add_once(_finding("SC-INPUT-001", "Unbounded String Input", "HIGH", "HIGH",
                              "scanf() contains a %s conversion without a width limit.",
                              "Input may exceed the destination buffer because the string conversion has no maximum width.",
                              "Specify a field width smaller than the destination buffer capacity and check scanf()'s return value.",
                              code.count("\n", 0, m.start()) + 1))

    # printf(userValue) / fprintf(stream, userValue) / sprintf(buf, userValue).
    for name, index in (("printf", 0), ("fprintf", 1), ("sprintf", 1)):
        for m in re.finditer(rf"\b{name}\s*\(([^;]*?)\)", code, re.S):
            args = m.group(1).split(",")
            if len(args) > index and not args[index].strip().startswith('"'):
                add_once(_finding("SC-INPUT-002", "Potential Format String Vulnerability", "HIGH", "MEDIUM",
                                  f"{name}() may use a non-literal format string.",
                                  "If the format argument is controlled by input, formatting directives may be interpreted.",
                                  'Use a fixed format string, for example printf("%s", value).',
                                  code.count("\n", 0, m.start()) + 1))

    for m in re.finditer(r"\b(?:system|popen)\s*\(", code):
        name = re.search(r"\b(system|popen)\s*\(", m.group(0)).group(1)
        add_once(_finding("SC-CMD-001", "Command Execution Risk", "MEDIUM", "MEDIUM",
                          f"Use of '{name}()' requires security review.",
                          "Shell command execution can be dangerous when command content includes untrusted data.",
                          "Avoid shell commands where possible; never concatenate untrusted input into a command.",
                          code.count("\n", 0, m.start()) + 1))

    # Scalar declaration followed by array indexing: common serious type/logic error.
    scalar_decl = re.compile(r"\b(?:char|short|int|long|float|double|unsigned|signed|bool)\s+(\w+)\s*(?:=\s*[^;]+)?;")
    for dm in scalar_decl.finditer(code):
        name = dm.group(1)
        # Skip a declaration that is visibly an array/pointer (regex captures only scalar form).
        use = re.search(rf"\b{re.escape(name)}\s*\[\s*[^\]]+\s*\]", code[dm.end():])
        if use:
            offset = dm.end() + use.start()
            add_once(_finding("SC-MEM-005", "Invalid Array Access", "HIGH", "HIGH",
                              f"'{name}' is declared as a scalar but later indexed like an array.",
                              "A scalar object cannot be indexed with []. This is invalid C and can lead to incorrect memory access if the declaration was intended to be an array.",
                              f"If multiple values are required, declare a correctly sized array such as int {name}[6]; and verify every index is in range.",
                              code.count("\n", 0, offset) + 1))

    # Pointer passed to free without a visible allocation/initialization before that free.
    ptr_decl = re.compile(r"\b(?:char|short|int|long|float|double|void|struct\s+\w+)\s*\*\s*(\w+)\s*(?:=\s*([^;]+))?;")
    for dm in ptr_decl.finditer(code):
        name, initializer = dm.group(1), (dm.group(2) or "").strip()
        if initializer and re.search(r"\b(?:malloc|calloc|realloc)\s*\(", initializer):
            continue
        fm = re.search(rf"\bfree\s*\(\s*{re.escape(name)}\s*\)", code[dm.end():])
        if not fm:
            continue
        before_free = code[dm.end():dm.end() + fm.start()]
        alloc = re.search(rf"\b{re.escape(name)}\s*=\s*(?:\([^;]*?\)\s*)?(?:malloc|calloc|realloc)\s*\(", before_free)
        if not alloc:
            offset = dm.end() + fm.start()
            add_once(_finding("SC-MEM-006", "Free Without Visible Allocation", "HIGH", "MEDIUM",
                              f"free({name}) is called, but no allocation for '{name}' is visible beforehand.",
                              "Freeing an uninitialized or non-allocated pointer has undefined behavior. This source-level check may not follow assignments across functions or complex control flow.",
                              f"Initialize {name} to NULL or assign it a valid malloc/calloc/realloc result before calling free(); only free pointers returned by allocation functions.",
                              code.count("\n", 0, offset) + 1))

    
    # Literal zero divisors.
    for m in re.finditer(r"(?:/|%)\s*0(?:\.0+)?\b", code):
        op = code[m.start()]
        is_mod = op == "%"
        add_once(_finding(
            "SC-ARITH-002" if is_mod else "SC-ARITH-001",
            "Modulo by Zero" if is_mod else "Division by Zero",
            "HIGH", "HIGH",
            "Modulo by zero detected." if is_mod else "Division by zero detected.",
            "The operation uses a literal zero divisor, which is invalid arithmetic in C.",
            "Check that the divisor is nonzero before performing the operation.",
            code.count("\n", 0, m.start()) + 1
        ))

    # Detect simple variables initialized to zero and used as divisors.
    zero_vars = set()
    for m in re.finditer(
        r"\b(?:int|float|double|long|short|unsigned)\s+(\w+)\s*=\s*0(?:\.0+)?\s*;",
        code
    ):
        zero_vars.add(m.group(1))

    for name in zero_vars:
        for m in re.finditer(rf"(?:/|%)\s*{re.escape(name)}\b", code):
            op = code[m.start()]
            is_mod = op == "%"
            add_once(_finding(
                "SC-ARITH-002" if is_mod else "SC-ARITH-001",
                "Modulo by Zero" if is_mod else "Division by Zero",
                "HIGH", "HIGH",
                f"{'Modulo' if is_mod else 'Division'} uses variable '{name}', initialized to zero.",
                "The divisor variable has a visible zero initializer. This heuristic does not track later assignments or complex control flow.",
                f"Ensure '{name}' is nonzero before performing the operation.",
                code.count("\n", 0, m.start()) + 1
            ))


    # A few recognizable signed-int boundary expressions. General integer-overflow
    # analysis requires type widths and value-range tracking, so this stays low confidence.
    for m in re.finditer(r"\b(?:INT_MAX|2147483647)\s*\+\s*1\b|\b(?:INT_MIN|-2147483648)\s*-\s*1\b", code):
        add_once(_finding("SC-ARITH-003", "Possible Signed Integer Overflow", "MEDIUM", "LOW",
                          "Expression appears to cross a common 32-bit signed-int boundary.",
                          "Signed integer overflow is undefined behavior in C. The exact result depends on the expression's types and integer widths, which this heuristic does not infer.",
                          "Check the destination type and bounds; use a wider type or validate the operation before performing it.",
                          code.count("\n", 0, m.start()) + 1))

    # rand() without a visible srand() is a low-confidence quality/security note, not always a bug.
    rand_match = re.search(r"\brand\s*\(", code)
    if rand_match and not re.search(r"\bsrand\s*\(", code):
        add_once(_finding("SC-RAND-001", "Predictable Pseudorandom Sequence", "LOW", "LOW",
                          "rand() is used without a visible srand() call.",
                          "The pseudorandom sequence may repeat between runs on common C library implementations. rand() is not suitable for security-sensitive randomness even when seeded.",
                          "For non-security simulation, seed once if repeatability is not wanted. For security-sensitive values, use an operating-system cryptographic random source.",
                          code.count("\n", 0, rand_match.start()) + 1))

    # Pointer and lifetime checks are intentionally conservative source heuristics.
    # They do not replace path-sensitive compiler analysis.
    # Double free and use-after-free: direct pointer-name patterns only.
    all_free_calls = list(re.finditer(r"\bfree\s*\(\s*(\w+)\s*\)", code))
    by_pointer = {}
    for fm in all_free_calls:
        by_pointer.setdefault(fm.group(1), []).append(fm)
    for name, calls in by_pointer.items():
        if len(calls) > 1:
            second = calls[1]
            add_once(_finding("SC-MEM-008", "Possible Double Free", "HIGH", "MEDIUM",
                              f"free({name}) appears more than once.",
                              "Calling free() repeatedly on the same allocation without an intervening new allocation can cause undefined behavior. This heuristic does not track branches or reassignment precisely.",
                              f"Ensure {name} is freed at most once for each allocation; set it to NULL after freeing and guard later cleanup paths.",
                              code.count("\n", 0, second.start()) + 1))
        first = calls[0]
        tail = code[first.end():]
        reassign = re.search(rf"\b{re.escape(name)}\s*=\s*(?!NULL\b|0\b)[^=]", tail)
        use = re.search(rf"(?:\*\s*{re.escape(name)}\b|\b{re.escape(name)}\s*(?:\[[^\]]+\]|->\s*\w+))", tail)
        if use and (not reassign or use.start() < reassign.start()):
            offset = first.end() + use.start()
            add_once(_finding("SC-MEM-009", "Possible Use After Free", "HIGH", "LOW",
                              f"'{name}' may be accessed after it is freed.",
                              "Using memory through a pointer after free() can access invalid memory. This source-level check does not fully model aliases or control flow.",
                              f"Do not use {name} after free(); set it to NULL after release and redesign ownership so the lifetime is clear.",
                              code.count("\n", 0, offset) + 1))

    # Direct null-pointer dereference, for simple visible NULL assignments.
    null_assignments = list(re.finditer(r"\b(\w+)\s*=\s*(?:NULL|0)\s*;", code))
    for nm in null_assignments:
        name = nm.group(1)
        tail = code[nm.end():]
        deref = re.search(rf"(?:\*\s*{re.escape(name)}\b|\b{re.escape(name)}\s*(?:\[[^\]]+\]|->\s*\w+))", tail)
        if deref:
            reassigned = re.search(rf"\b{re.escape(name)}\s*=\s*(?!NULL\b|0\b)[^=]", tail)
            if not reassigned or deref.start() < reassigned.start():
                offset = nm.end() + deref.start()
                add_once(_finding("SC-MEM-007", "Possible Null Pointer Dereference", "HIGH", "MEDIUM",
                                  f"'{name}' is dereferenced after being assigned NULL or 0.",
                                  "A null pointer does not refer to a valid object. Dereferencing it can crash or cause undefined behavior.",
                                  f"Check {name} against NULL before dereferencing it and ensure it points to a valid object.",
                                  code.count("\n", 0, offset) + 1))

    # Simple allocation leak heuristic: allocation assigned to a local pointer without visible free/return.
    alloc_re = re.compile(r"\b(?:\w+\s+)?\*\s*(\w+)\s*=\s*(?:\([^;]*?\)\s*)?(?:malloc|calloc|realloc)\s*\(")
    for am in alloc_re.finditer(code):
        name = am.group(1)
        # Limit the scan to the rest of this enclosing function-ish region.
        tail = code[am.end():]
        free_m = re.search(rf"\bfree\s*\(\s*{re.escape(name)}\s*\)", tail)
        return_m = re.search(rf"\breturn\s+{re.escape(name)}\s*;", tail)
        if not free_m and not return_m:
            add_once(_finding("SC-MEM-010", "Possible Memory Leak", "MEDIUM", "LOW",
                              f"Allocation assigned to '{name}' has no visible matching free().",
                              "Dynamically allocated memory should be released when ownership ends. This heuristic may miss frees in helper functions or other control-flow paths.",
                              f"Ensure every successful allocation assigned to {name} is released exactly once, or document and transfer ownership explicitly.",
                              code.count("\n", 0, am.start()) + 1))

    # Unmatched preprocessor conditional directives.
    pp_stack = []
    for line_no, line in enumerate(code.splitlines(), 1):
        directive = re.match(r"\s*#\s*(if|ifdef|ifndef|endif)\b", line)
        if not directive:
            continue
        kind = directive.group(1)
        if kind in {"if", "ifdef", "ifndef"}:
            pp_stack.append(line_no)
        elif pp_stack:
            pp_stack.pop()
        else:
            add_once(_finding("SC-PP-001", "Unmatched Preprocessor Directive", "HIGH", "HIGH",
                              "#endif has no matching #if, #ifdef or #ifndef.",
                              "Preprocessor conditional blocks must be properly nested and closed.",
                              "Add the matching opening directive or remove the unmatched #endif.", line_no))
    for opening_line in pp_stack:
        add_once(_finding("SC-PP-001", "Unclosed Preprocessor Conditional", "HIGH", "HIGH",
                          "Preprocessor conditional has no matching #endif.",
                          "An unclosed conditional-compilation block can prevent preprocessing from succeeding.",
                          "Add a matching #endif for this #if/#ifdef/#ifndef block.", opening_line))

    # Basic delimiter balance check after masking literals to reduce false positives.
    masked = list(code)
    quote = None
    escaped = False
    for i, ch in enumerate(code):
        if quote:
            masked[i] = " " if ch != "\n" else "\n"
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                quote = None
        elif ch in {"\"", "'"}:
            quote = ch
            masked[i] = " "
    masked_code = "".join(masked)
    pairs = {"(": ")", "[": "]", "{": "}"}
    closing = {v: k for k, v in pairs.items()}
    stack = []
    for pos, ch in enumerate(masked_code):
        if ch in pairs:
            stack.append((ch, pos))
        elif ch in closing:
            if stack and stack[-1][0] == closing[ch]:
                stack.pop()
            else:
                line_no = code.count("\n", 0, pos) + 1
                add_once(_finding("SC-SYN-001", "Unmatched Closing Delimiter", "HIGH", "HIGH",
                                  f"Closing delimiter '{ch}' has no matching opener.",
                                  "Parentheses, square brackets and braces must be correctly paired in C source.",
                                  f"Check the matching opening delimiter before line {line_no}.", line_no))
    for ch, pos in stack:
        line_no = code.count("\n", 0, pos) + 1
        add_once(_finding("SC-SYN-001", "Unclosed Delimiter", "HIGH", "HIGH",
                          f"Opening delimiter '{ch}' has no matching closing delimiter.",
                          "An unclosed grouping delimiter often causes a compiler syntax error or changes the structure of later code.",
                          f"Add the matching '{pairs[ch]}' and verify the surrounding block.", line_no))

    # Heuristic warning for a switch case that appears to fall through without break/return.
    for sm in re.finditer(r"\bswitch\s*\([^)]*\)\s*\{([\s\S]*?)\}", code):
        body = sm.group(1)
        cases = list(re.finditer(r"\b(?:case\s+[^:]+|default)\s*:", body))
        for idx, case in enumerate(cases[:-1]):
            segment_end = cases[idx + 1].start()
            segment = body[case.end():segment_end]
            if segment.strip() and not re.search(r"\b(?:break|return|goto)\b|/\*\s*fall\s*through\s*\*/", segment):
                line_no = code.count("\n", 0, sm.start(1) + case.start()) + 1
                add_once(_finding("SC-LOGIC-004", "Possible Switch Fall-through", "LOW", "LOW",
                                  "A switch case may fall through into the next case.",
                                  "Without break, return or another control transfer, execution can continue into the following case. Some programs intentionally use fall-through.",
                                  "Add break if fall-through is unintended, or document the intentional fall-through clearly.", line_no))

    # Simple unreachable-code heuristic after return in the same brace depth.
    depth = 0
    returned_depths = set()
    for line_no, line in enumerate(code.splitlines(), 1):
        stripped = line.strip()
        before = depth
        if before in returned_depths and stripped and stripped not in {"}", "};"} and not stripped.startswith("//"):
            if not re.match(r"^(?:else\b|case\b|default\s*:|})", stripped):
                add_once(_finding("SC-LOGIC-003", "Possible Unreachable Code", "LOW", "LOW",
                                  "Statement appears after an unconditional return in the same block.",
                                  "Statements after return are not executed along that path. This line-based heuristic may be confused by nested blocks or multiline constructs.",
                                  "Move the statement before the return or remove it if it is not needed.", line_no))
        if re.search(r"\breturn\b[^;]*;", stripped):
            returned_depths.add(before)
        # Opening/closing braces update approximate scope depth.
        depth += line.count("{") - line.count("}")
        depth = max(depth, 0)
        returned_depths = {d for d in returned_depths if d <= depth}

    return findings
