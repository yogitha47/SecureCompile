"""SecureCompile local web interface for the restricted-C static analyzer."""
from __future__ import annotations

import io
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from flask import Flask, jsonify, render_template, request, send_file

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))

from lexer import lexer  # noqa: E402
from parser import parser  # noqa: E402
from security_analyzer import SecurityAnalyzer  # noqa: E402
from source_analyzer import analyze_source  # noqa: E402

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024  # 1 MB source upload limit



def run_compiler_diagnostics(source: str):
    """Use Clang/GCC for syntax and type diagnostics when installed; never execute user code."""
    compiler = shutil.which("clang") or shutil.which("gcc") or shutil.which("cc")
    if not compiler:
        return {"available": False, "compiler": None, "diagnostics": [],
                "note": "No Clang/GCC frontend was found. Install Clang to enable compiler-level syntax and type diagnostics."}
    diagnostics = []
    try:
        with tempfile.TemporaryDirectory(prefix="securecompile_") as tmp:
            source_path = Path(tmp) / "submitted.c"
            source_path.write_text(source, encoding="utf-8")
            compiler_name = Path(compiler).name.lower()
            args = [compiler, "-fsyntax-only", "-Wall", "-Wextra", "-Wpedantic"]
            if "clang" in compiler_name:
                args += ["-fno-color-diagnostics"]
            args.append(str(source_path))
            completed = subprocess.run(args, capture_output=True, text=True, timeout=8, check=False)
            output = (completed.stderr or "") + (completed.stdout or "")
            pattern = re.compile(r"^(?:.*?):(\d+):(\d+):\s*(warning|error|fatal error|note):\s*(.*)$")
            for line in output.splitlines():
                match = pattern.match(line.strip())
                if not match:
                    continue
                line_number, column, kind, message = match.groups()
                kind = "error" if "error" in kind else kind
                diagnostics.append({"line": int(line_number), "column": int(column), "kind": kind,
                                    "message": message[:500],
                                    "explanation": ("The C compiler rejected this syntax or type usage." if kind == "error" else
                                                    "The compiler reports a possible correctness or portability issue." if kind == "warning" else
                                                    "Additional compiler context.")})
                if len(diagnostics) >= 60:
                    break
            return {"available": True, "compiler": Path(compiler).name,
                    "return_code": completed.returncode, "diagnostics": diagnostics,
                    "note": "Compiler diagnostics come from syntax-only checking. SecureCompile does not execute submitted code."}
    except subprocess.TimeoutExpired:
        return {"available": True, "compiler": Path(compiler).name, "diagnostics": [],
                "note": "Compiler syntax checking timed out; source-level checks still ran."}
    except (OSError, UnicodeError) as exc:
        return {"available": False, "compiler": Path(compiler).name, "diagnostics": [],
                "note": f"Compiler frontend could not run ({type(exc).__name__}); source-level checks still ran."}

def build_memory_summary(source: str):
    """Build an intentionally approximate pointer/lifetime overview from source text."""
    code = re.sub(r"/\*.*?\*/|//[^\n]*", " ", source, flags=re.S)
    entries = []
    pattern = re.compile(r"\b(?:char|short|int|long|float|double|void|struct\s+\w+)\s*\*\s*(\w+)\s*(?:=\s*([^;]+))?;")
    for match in pattern.finditer(code):
        name, init = match.group(1), (match.group(2) or "").strip()
        state = "uninitialized pointer"
        target = "unknown address"
        if re.search(r"\b(?:malloc|calloc|realloc)\s*\(", init):
            state, target = "heap allocation (visible)", "heap block"
        elif re.search(r"\bNULL\b|^0$", init):
            state, target = "null pointer", "no object"
        elif init:
            state, target = "initialized pointer (target unknown)", init[:80]
        frees = list(re.finditer(rf"\bfree\s*\(\s*{re.escape(name)}\s*\)", code))
        allocation_visible = bool(re.search(rf"\b{re.escape(name)}\s*=\s*(?:\([^;]*?\)\s*)?(?:malloc|calloc|realloc)\s*\(", code))
        if allocation_visible:
            state, target = "heap allocation (visible)", "heap block"
            if frees:
                state, target = "allocation and free both visible", "heap block released in source"
        elif frees and state == "uninitialized pointer":
            state, target = "uninitialized pointer passed to free", "unknown address (unsafe to free)"
        elif frees and state == "null pointer":
            state, target = "NULL passed to free (safe no-op)", "no object"
        elif frees:
            state, target = "free call visible; ownership unclear", "target needs manual review"
        entries.append({"name": name, "state": state, "target": target,
                        "decl_line": source.count("\n", 0, match.start()) + 1})
        if len(entries) >= 30:
            break
    return entries

def analyze_c_source(source: str):
    if not source or not source.strip():
        return {"ok": False, "error": "Paste or upload a C program first."}
    if len(source) > 100_000:
        return {"ok": False, "error": "Please keep source code under 100,000 characters."}

    findings = []
    parser_mode = "restricted AST + source-level checks"
    parse_note = None
    try:
        lexer.lineno = 1
        ast = parser.parse(source, lexer=lexer)
        if ast is not None:
            findings.extend(SecurityAnalyzer().analyze(ast))
        else:
            parser_mode = "source-level fallback"
            parse_note = (
                "The source uses syntax outside SecureCompile's restricted AST grammar. "
                "Source-level heuristic checks were run instead; some semantic checks may be unavailable."
            )
    except Exception as exc:
        app.logger.warning("Restricted parser could not process source (%s); using source-level checks", type(exc).__name__)
        parser_mode = "source-level fallback"
        parse_note = (
            "The restricted AST parser could not process this syntax. Source-level heuristic checks were run instead; "
            "this is not full compiler-grade C analysis."
        )

    # Always run source-level rules so common C constructs that the restricted parser
    # cannot represent (main, arrays, pointers, for-loops, headers) still get checked.
    findings.extend(analyze_source(source))

    # Merge duplicate reports produced by both engines.
    merged = []
    seen = set()
    for finding in findings:
        key = (finding.get("rule_id"), finding.get("line"), finding.get("message"))
        if key not in seen:
            seen.add(key)
            merged.append(finding)
    merged.sort(key=lambda item: (item.get("line") or 0, item.get("rule_id") or ""))

    counts = {
        "HIGH": sum(f.get("severity") == "HIGH" for f in merged),
        "MEDIUM": sum(f.get("severity") == "MEDIUM" for f in merged),
        "LOW": sum(f.get("severity") == "LOW" for f in merged),
    }
    compiler_result = run_compiler_diagnostics(source)
    return {
        "ok": True,
        "findings": merged,
        "total": len(merged),
        "counts": counts,
        "analysis_mode": parser_mode,
        "analysis_note": parse_note,
        "compiler": compiler_result,
        "memory_model": build_memory_summary(source),
    }


@app.get("/")
def index():
    return render_template("index.html")


@app.post("/api/analyze")
def api_analyze():
    source = request.form.get("code", "")
    uploaded = request.files.get("file")
    if uploaded and uploaded.filename:
        if not uploaded.filename.lower().endswith(".c"):
            return jsonify({"ok": False, "error": "Please upload a .c file."}), 400
        try:
            source = uploaded.read(100_001).decode("utf-8")
        except UnicodeDecodeError:
            return jsonify({"ok": False, "error": "The uploaded file must be UTF-8 text."}), 400
    result = analyze_c_source(source)
    status = 200 if result.get("ok") else 400
    if result.get("ok"):
        result["source"] = source
    return jsonify(result), status


@app.post("/api/report")
def download_report():
    payload = request.get_json(silent=True) or {}
    result = payload.get("result")
    if not isinstance(result, dict) or not result.get("ok"):
        return jsonify({"error": "Run a successful analysis before downloading a report."}), 400
    report = {
        "project": "SecureCompile",
        "report_note": "Heuristic static-analysis results. The restricted AST parser covers only a C subset; source-level fallback rules are not a full compiler or guarantee of security.",
        "analysis_mode": result.get("analysis_mode", "unknown"),
        "analysis_note": result.get("analysis_note"),
        "compiler": result.get("compiler", {}),
        "memory_model": result.get("memory_model", []),
        "total_findings": result.get("total", 0),
        "severity_counts": result.get("counts", {}),
        "findings": result.get("findings", []),
    }
    data = json.dumps(report, indent=2).encode("utf-8")
    return send_file(io.BytesIO(data), mimetype="application/json", as_attachment=True, download_name="securecompile_report.json")


if __name__ == "__main__":
    print("SecureCompile is starting at http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=False)
