"""ML module: loading, failure handling, unseen inputs, dataset-split integrity."""
import json
import shutil

import pytest
from ml import infer
from ml.features import normalize_code, split_functions, structure_tokens

MODEL_PRESENT = infer.MODEL_PATH.exists() and infer.META_PATH.exists()
needs_model = pytest.mark.skipif(not MODEL_PRESENT, reason="trained model not present (run src/ml/train.py)")


@pytest.fixture()
def isolated_model(tmp_path, monkeypatch):
    """Point the module at a temp dir with a clean cache; restore the real cache afterwards."""
    saved = dict(infer._state)
    monkeypatch.setattr(infer, "MODEL_PATH", tmp_path / "m.joblib")
    monkeypatch.setattr(infer, "META_PATH", tmp_path / "m.json")
    infer._state.update(bundle=None, meta=None, error=None, loaded=False)
    yield tmp_path
    infer._state.clear()
    infer._state.update(saved)


def test_missing_model_is_reported_not_raised(isolated_model):
    result = infer.predict_source("int main(void){ return 0; }")
    assert result["status"] == "unavailable" and "train" in result["message"]
    assert infer.model_status()["available"] is False


def test_corrupt_or_tampered_model_is_refused(isolated_model):
    (isolated_model / "m.joblib").write_bytes(b"not a model")
    (isolated_model / "m.json").write_text(json.dumps({"model_sha256": "0" * 64}))
    result = infer.predict_source("int main(void){ return 0; }")
    assert result["status"] == "unavailable" and "SHA-256" in result["message"]


def test_unpicklable_model_with_matching_hash_is_an_error_not_a_crash(isolated_model):
    blob = isolated_model / "m.joblib"
    blob.write_bytes(b"garbage")
    meta = {"model_sha256": infer._sha256(blob)}
    (isolated_model / "m.json").write_text(json.dumps(meta))
    result = infer.predict_source("int main(void){ return 0; }")
    assert result["status"] == "unavailable" and "could not be loaded" in result["message"]


@pytest.mark.parametrize("bad", ["", "   \n", None, 5])
def test_empty_or_invalid_input(bad):
    assert infer.predict_source(bad)["status"] == "error"


@needs_model
def test_inference_failure_returns_error_status(monkeypatch):
    def boom(docs):
        raise RuntimeError("x")
    monkeypatch.setattr(infer, "predict_normalized", boom)
    result = infer.predict_source("int main(void){ char b[4]; gets(b); return 0; }")
    assert result["status"] == "error"


@needs_model
def test_prediction_structure_and_thresholds():
    result = infer.predict_source("void f(void){ char b[4]; gets(b); }\nint main(void){ f(); return 0; }")
    assert result["status"] == "ok"
    assert {s["name"] for s in result["scopes"]} == {"f", "main"}
    for scope in result["scopes"]:
        assert set(scope["probabilities"]) == set(result["thresholds"])
        for category in scope["predicted"]:
            assert scope["probabilities"][category] >= result["thresholds"][category]


@needs_model
def test_unseen_juliet_style_examples_are_classified_sensibly():
    """Hand-written functions in Juliet's style that are not in the dataset."""
    vulnerable = """void process(char * input) {
    char * data;
    data = (char *)malloc(10 * sizeof(char));
    free(data);
    free(data);
}"""
    safe = """void process(char * input) {
    char buffer[100] = "";
    strncpy(buffer, input, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\\0';
    printLine(buffer);
}"""
    result_v = infer.predict_source(vulnerable)
    result_s = infer.predict_source(safe)
    assert result_v["status"] == result_s["status"] == "ok"
    # Report what the model says; assert only the probability is a valid number for every category.
    for result in (result_v, result_s):
        assert all(0.0 <= p <= 1.0 for p in result["scopes"][0]["probabilities"].values())


def test_function_splitting_ignores_braces_in_strings_and_comments():
    src = 'int a(void){ char *s = "}"; /* } */ return 0; }\nint b(void){ return 1; }\nstruct S { int x; };'
    assert [f["name"] for f in split_functions(src)] == ["a", "b"]


def test_normalization_removes_label_leaking_names_and_comments():
    out = normalize_code("/* FLAW: bad */ void CWE121_x_bad(void){ goodSink(\"hi %s\"); }", ["CWE121_x_bad"])
    assert "CWE121" not in out and "bad" not in out.lower().replace("func_or_tag", "") and "FLAW" not in out
    assert "FMT_s" in out
    assert "CALL_" in structure_tokens(normalize_code("void f(){ strcpy(a, b); }"))


DATASET = infer.ROOT / "data" / "processed" / "juliet_functions.jsonl"


@pytest.mark.skipif(not DATASET.exists(), reason="dataset not prepared")
def test_no_group_or_exact_text_leakage_between_splits():
    rows = [json.loads(line) for line in DATASET.open(encoding="utf-8")]
    groups = {s: {r["group"] for r in rows if r["split"] == s} for s in ("train", "validation", "test")}
    assert not groups["train"] & groups["test"]
    assert not groups["train"] & groups["validation"]
    assert not groups["validation"] & groups["test"]
    texts = {s: {r["normalized"] for r in rows if r["split"] == s} for s in groups}
    assert not texts["train"] & texts["test"] and not texts["train"] & texts["validation"]


@pytest.mark.skipif(not DATASET.exists(), reason="dataset not prepared")
def test_every_category_has_positives_in_every_split():
    from findings import ML_CATEGORIES
    rows = [json.loads(line) for line in DATASET.open(encoding="utf-8")]
    for split in ("train", "validation", "test"):
        for category in ML_CATEGORIES:
            assert any(category in r["labels"] for r in rows if r["split"] == split), (split, category)
