"""Inference for the trained SecureCompile multi-label classifier.

Nothing here trains or fabricates predictions: if no trained model file exists, or it
fails its integrity check, results carry ``status`` "unavailable"/"error" with a reason.
"""
from __future__ import annotations

import hashlib
import json
import threading
from pathlib import Path

from ml.features import normalize_code, split_functions, structure_tokens

ROOT = Path(__file__).resolve().parents[2]
MODEL_PATH = ROOT / "models" / "securecompile_ml.joblib"
META_PATH = ROOT / "models" / "securecompile_ml.json"
MAX_INPUT_CHARS = 200_000

_lock = threading.Lock()
_state = {"bundle": None, "meta": None, "error": None, "loaded": False}


class ModelUnavailable(RuntimeError):
    pass


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_model(force: bool = False):
    """Load and integrity-check the model once. Raises ModelUnavailable with a readable reason."""
    with _lock:
        if _state["loaded"] and not force:
            if _state["error"]:
                raise ModelUnavailable(_state["error"])
            return _state["bundle"], _state["meta"]
        _state.update(bundle=None, meta=None, error=None, loaded=True)
        try:
            if not MODEL_PATH.exists() or not META_PATH.exists():
                raise ModelUnavailable(
                    "No trained model found. Prepare data and train it with: "
                    "python src/ml/dataset.py download; python src/ml/dataset.py prepare; python src/ml/train.py")
            meta = json.loads(META_PATH.read_text(encoding="utf-8"))
            if _sha256(MODEL_PATH) != meta.get("model_sha256"):
                raise ModelUnavailable("Model file does not match its recorded SHA-256; refusing to load it.")
            import joblib  # imported lazily so the web app starts without scikit-learn installed
            bundle = joblib.load(MODEL_PATH)
            missing = {"labels", "vectorizers", "classifier", "thresholds"} - set(bundle)
            if missing:
                raise ModelUnavailable(f"Model bundle is incomplete (missing {sorted(missing)}).")
            _state.update(bundle=bundle, meta=meta)
            return bundle, meta
        except ModelUnavailable as exc:
            _state["error"] = str(exc)
            raise
        except Exception as exc:  # corrupt pickle, version mismatch, missing sklearn ...
            _state["error"] = f"Model could not be loaded ({type(exc).__name__}: {exc})"
            raise ModelUnavailable(_state["error"]) from exc


def model_status() -> dict:
    try:
        _, meta = load_model()
    except ModelUnavailable as exc:
        return {"available": False, "reason": str(exc)}
    return {"available": True, "name": meta.get("name"), "trained_at": meta.get("trained_at"),
            "feature_set": meta.get("feature_set"), "labels": meta.get("labels"),
            "validation_macro_f1": meta.get("validation_macro_f1"), "dataset": meta.get("dataset"),
            "caveat": meta.get("caveat")}


def _feature_matrix(bundle, normalized_docs):
    import scipy.sparse as sp
    parts = []
    for kind, vectorizer in bundle["vectorizers"].items():
        docs = normalized_docs if kind == "text" else [structure_tokens(d) for d in normalized_docs]
        parts.append(vectorizer.transform(docs))
    return sp.hstack(parts, format="csr") if len(parts) > 1 else parts[0]


def predict_normalized(normalized_docs):
    """Probabilities, shape (n_docs, n_labels), for already-normalised documents."""
    bundle, _ = load_model()
    return bundle["classifier"].predict_proba(_feature_matrix(bundle, normalized_docs))


def predict_source(source: str) -> dict:
    """Per-function category probabilities for a C source string."""
    if not isinstance(source, str) or not source.strip():
        return {"status": "error", "message": "Empty input: nothing for the ML model to score."}
    if len(source) > MAX_INPUT_CHARS:
        return {"status": "error", "message": "Input too large for ML inference."}
    try:
        bundle, meta = load_model()
    except ModelUnavailable as exc:
        return {"status": "unavailable", "message": str(exc)}

    labels, thresholds = bundle["labels"], bundle["thresholds"]
    functions = split_functions(source)
    if functions:
        scopes = [{"kind": "function", "name": f["name"], "start_line": f["start_line"],
                   "end_line": f["end_line"], "signature": f["signature"], "text": f["text"]}
                  for f in functions]
    else:
        total_lines = source.count("\n") + 1
        scopes = [{"kind": "file", "name": None, "start_line": 1, "end_line": total_lines,
                   "signature": "", "text": source}]
    docs = [normalize_code(s["text"], function_names=[s["name"]] if s["name"] else []) for s in scopes]
    try:
        probs = predict_normalized(docs)
    except Exception as exc:
        return {"status": "error", "message": f"ML inference failed ({type(exc).__name__})."}

    for scope, row in zip(scopes, probs):
        del scope["text"]
        scope["probabilities"] = {c: round(float(p), 4) for c, p in zip(labels, row)}
        scope["predicted"] = [c for c, p in zip(labels, row) if p >= thresholds[c]]
    return {
        "status": "ok",
        "model": {"name": meta.get("name"), "trained_at": meta.get("trained_at"),
                  "feature_set": meta.get("feature_set"),
                  "validation_macro_f1": meta.get("validation_macro_f1"),
                  "dataset": (meta.get("dataset") or {}).get("name"), "caveat": meta.get("caveat")},
        "thresholds": thresholds,
        "scopes": scopes,
        "scope_note": ("Predictions are per function (or per file if no function was found); "
                       "they do not identify a specific line."),
    }
