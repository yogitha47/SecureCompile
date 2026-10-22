"""Optional external compiler front end (syntax-only; submitted code is never executed)."""
from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
from pathlib import Path

_DIAG = re.compile(r"^(?P<path>.*?):(?P<line>\d+):(?P<col>\d+):\s*(?P<kind>warning|error|fatal error|note):\s*(?P<msg>.*)$")
_TIMEOUT_SECONDS = 8
_MAX_DIAGNOSTICS = 60


def find_compiler():
    for name in ("clang", "gcc", "cc"):
        path = shutil.which(name)
        if path:
            return path
    return None


def compile_check(source: str, timeout: int = _TIMEOUT_SECONDS) -> dict:
    """Run ``<compiler> -fsyntax-only`` on ``source``.

    ``ran`` is True only if the compiler process actually completed. The result
    never claims diagnostics were produced when it did not run.
    """
    compiler = find_compiler()
    if not compiler:
        return {"available": False, "ran": False, "compiler": None, "diagnostics": [],
                "error_count": 0, "warning_count": 0,
                "note": "No Clang/GCC executable was found on PATH, so no compiler diagnostics were produced."}
    name = Path(compiler).name
    kind = "clang" if "clang" in name.lower() else "gcc"
    try:
        with tempfile.TemporaryDirectory(prefix="securecompile_") as tmp:
            source_path = Path(tmp) / "submitted.c"
            source_path.write_text(source, encoding="utf-8")
            args = [compiler, "-fsyntax-only", "-Wall", "-Wextra", "-Wpedantic"]
            args += ["-fno-color-diagnostics", "-ferror-limit=50"] if kind == "clang" else ["-fmax-errors=50"]
            args.append(str(source_path))
            completed = subprocess.run(args, capture_output=True, text=True, timeout=timeout,
                                       check=False, cwd=tmp, encoding="utf-8", errors="replace")
    except subprocess.TimeoutExpired:
        return {"available": True, "ran": False, "compiler": name, "diagnostics": [],
                "error_count": 0, "warning_count": 0,
                "note": f"{name} did not finish within {timeout}s; no compiler diagnostics were produced."}
    except (OSError, UnicodeError) as exc:
        return {"available": False, "ran": False, "compiler": name, "diagnostics": [],
                "error_count": 0, "warning_count": 0,
                "note": f"{name} could not be run ({type(exc).__name__})."}

    diagnostics = []
    errors = warnings = 0
    for line in ((completed.stderr or "") + (completed.stdout or "")).splitlines():
        match = _DIAG.match(line.strip())
        if not match or Path(match.group("path")).name != "submitted.c":
            continue
        level = match.group("kind")
        level = "error" if "error" in level else level
        if level == "error":
            errors += 1
        elif level == "warning":
            warnings += 1
        if len(diagnostics) < _MAX_DIAGNOSTICS:
            diagnostics.append({"kind": "compiler", "severity": level, "line": int(match.group("line")),
                                "column": int(match.group("col")), "message": match.group("msg")[:500],
                                "engine": "compiler"})
    return {"available": True, "ran": True, "compiler": name, "compiler_family": kind,
            "return_code": completed.returncode, "diagnostics": diagnostics,
            "error_count": errors, "warning_count": warnings,
            "note": f"Diagnostics come from {name} -fsyntax-only. SecureCompile does not execute submitted code."}
