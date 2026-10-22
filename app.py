"""SecureCompile local web interface: Flask routes over the analysis pipeline."""
from __future__ import annotations

import io
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, jsonify, render_template, request, send_file
from werkzeug.exceptions import HTTPException

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))

import fixer  # noqa: E402
import pipeline  # noqa: E402
from compiler import find_compiler  # noqa: E402

MAX_SOURCE_BYTES = 400_000  # UTF-8 bytes accepted per source; the pipeline also caps characters

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024  # 1 MB request limit
app.json.sort_keys = False

TOOL_VERSION = "2.0"


def _error(message, status=400, **extra):
    return jsonify({"ok": False, "error": message, **extra}), status


def _read_source():
    """Return (source, error_response). Accepts form field `code`, an uploaded `.c` file, or JSON {code}."""
    uploaded = request.files.get("file")
    if uploaded and uploaded.filename:
        if not uploaded.filename.lower().endswith((".c", ".h")):
            return None, _error("Please upload a .c file.")
        raw = uploaded.read(MAX_SOURCE_BYTES + 1)
        if len(raw) > MAX_SOURCE_BYTES:
            return None, _error("The uploaded file is too large.", 413)
        try:
            return raw.decode("utf-8"), None
        except UnicodeDecodeError:
            return None, _error("The uploaded file must be UTF-8 text.")
    if request.is_json:
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return None, _error("Request body must be a JSON object.")
        source = payload.get("code", payload.get("source"))
    else:
        source = request.form.get("code")
    if source is None:
        return None, _error("No source code was provided (expected field 'code').")
    if not isinstance(source, str):
        return None, _error("Source code must be text.")
    if len(source.encode("utf-8", errors="replace")) > MAX_SOURCE_BYTES:
        return None, _error("The source is too large.", 413)
    return source, None


def analyze_c_source(source, **options):
    """Backward-compatible wrapper returning an ``ok``/``error`` dict."""
    try:
        result = pipeline.analyze(source, **options)
    except pipeline.AnalysisInputError as exc:
        return {"ok": False, "error": str(exc)}
    result["source"] = source
    return result


@app.errorhandler(HTTPException)
def handle_http_error(exc):
    if request.path.startswith("/api/"):
        return _error(exc.description or exc.name, exc.code or 500)
    return exc


@app.errorhandler(Exception)
def handle_unexpected_error(exc):
    app.logger.exception("Unhandled error")
    if request.path.startswith("/api/"):
        return _error("Internal error while processing the request.", 500)
    return "Internal server error", 500


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/api/status")
def api_status():
    from ml import infer as ml_infer
    return jsonify({"ok": True, "version": TOOL_VERSION, "compiler": find_compiler() is not None,
                    "ml": ml_infer.model_status()})


@app.get("/api/evaluation")
def api_evaluation():
    """Measured evaluation results written by src/ml/evaluate.py (never hard-coded)."""
    path = ROOT / "reports" / "ml_evaluation.json"
    if not path.exists():
        return jsonify({"ok": True, "available": False,
                        "message": "No evaluation report yet. Run: python src/ml/evaluate.py"})
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return jsonify({"ok": True, "available": False, "message": "The evaluation report could not be read."})
    test = report["test"]
    summary = {name: {"micro_f1": test[name]["micro"]["f1"], "macro_f1": test[name]["macro_f1"],
                      "precision": test[name]["micro"]["precision"], "recall": test[name]["micro"]["recall"]}
               for name in ("rule_only", "ml_only", "hybrid")}
    return jsonify({"ok": True, "available": True, "dataset": report["dataset"],
                    "methodology": report["methodology"], "hybrid_policy": report["hybrid_policy"],
                    "summary": summary, "per_category": {name: test[name]["per_category"]
                                                         for name in ("rule_only", "ml_only", "hybrid")},
                    "test_samples": test["samples"], "ci": report["bootstrap_95ci_cluster_by_group"],
                    "localisation": report["rule_localisation"],
                    "sanity": {k: v for k, v in report["handwritten_cases_sanity"].items() if k != "cases"}})


@app.post("/api/analyze")
def api_analyze():
    source, error = _read_source()
    if error:
        return error
    result = analyze_c_source(source)
    status = 200 if result.get("ok") else 400
    return jsonify(result), status


def _fix_request():
    source, error = _read_source()
    if error:
        return None, None, error
    try:
        pipeline.validate_source(source)
    except pipeline.AnalysisInputError as exc:
        return None, None, _error(str(exc))
    finding_id = None
    if request.is_json:
        finding_id = (request.get_json(silent=True) or {}).get("finding_id")
    else:
        finding_id = request.form.get("finding_id")
    return source, finding_id, None


@app.post("/api/fix")
def api_fix():
    """Propose and validate a fix for one finding. The source is never modified server-side."""
    source, finding_id, error = _fix_request()
    if error:
        return error
    if not isinstance(finding_id, str) or not finding_id:
        return _error("A finding_id is required.")
    try:
        return jsonify(fixer.fix_finding(source, finding_id))
    except fixer.FixError as exc:
        return _error(str(exc), 404)


@app.post("/api/fix_all")
def api_fix_all():
    """Propose corrected code for the whole program, with a diff and validation."""
    source, _, error = _fix_request()
    if error:
        return error
    return jsonify(fixer.generate_corrected(source))


@app.post("/api/report")
def download_report():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return _error("Send a JSON body containing the analysed source.")
    source = payload.get("source")
    if not isinstance(source, str):
        return _error("Run a successful analysis before downloading a report.")
    result = analyze_c_source(source)  # re-analysed server-side; client-supplied results are not trusted
    if not result.get("ok"):
        return _error(result.get("error", "Analysis failed."))
    report = {
        "project": "SecureCompile",
        "tool_version": TOOL_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "report_note": ("Heuristic static-analysis results plus an optional ML model. Findings are leads for review; "
                        "a clean report is not a guarantee of security."),
        "source_sha256": result["source_sha256"],
        "source": source,
        "analysis_mode": result["analysis_mode"],
        "analysis_note": result["analysis_note"],
        "parse": result["parse"],
        "syntax_diagnostics": result["syntax_diagnostics"],
        "syntax_repairs": result["syntax_repairs"],
        "semantic_diagnostics": result["semantic_diagnostics"],
        "compiler": result["compiler"],
        "ml": result["ml"],
        "disagreements": result["disagreements"],
        "total_findings": result["total"],
        "severity_counts": result["counts"],
        "findings": result["findings"],
        "memory_model": result["memory_model"],
    }
    data = json.dumps(report, indent=2).encode("utf-8")
    return send_file(io.BytesIO(data), mimetype="application/json", as_attachment=True,
                     download_name="securecompile_report.json")


if __name__ == "__main__":
    print("SecureCompile is starting at http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=False)
