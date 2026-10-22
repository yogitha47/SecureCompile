"""Flask routes: valid and invalid requests, report serialization."""
import io
import json

import pytest

from app import app

PROGRAM = "#include <stdio.h>\nint main(void){ char b[8]; gets(b); return 0; }\n"


@pytest.fixture()
def client():
    app.config["TESTING"] = True
    return app.test_client()


def test_index_page_loads(client):
    response = client.get("/")
    assert response.status_code == 200 and b"SecureCompile" in response.data


def test_analyze_form_post(client):
    response = client.post("/api/analyze", data={"code": PROGRAM})
    body = response.get_json()
    assert response.status_code == 200 and body["ok"]
    assert body["findings"][0]["rule_id"] == "SC-MEM-001"
    assert "syntax_diagnostics" in body and "ml" in body and "compiler" in body


def test_analyze_json_post(client):
    response = client.post("/api/analyze", json={"code": PROGRAM})
    assert response.status_code == 200 and response.get_json()["total"] >= 1


def test_analyze_file_upload(client):
    data = {"file": (io.BytesIO(PROGRAM.encode()), "prog.c")}
    response = client.post("/api/analyze", data=data, content_type="multipart/form-data")
    assert response.status_code == 200 and response.get_json()["ok"]


def test_upload_rejects_wrong_extension_and_bad_encoding(client):
    bad_ext = client.post("/api/analyze", data={"file": (io.BytesIO(b"int x;"), "x.txt")}, content_type="multipart/form-data")
    bad_enc = client.post("/api/analyze", data={"file": (io.BytesIO(b"\xff\xfe\x00bad"), "x.c")}, content_type="multipart/form-data")
    assert bad_ext.status_code == 400 and bad_enc.status_code == 400


@pytest.mark.parametrize("payload", [{"code": ""}, {"code": "   \n"}, {}])
def test_empty_or_missing_code_is_a_400_with_message(client, payload):
    response = client.post("/api/analyze", data=payload)
    assert response.status_code == 400 and response.get_json()["error"]


def test_non_text_json_code_is_rejected(client):
    assert client.post("/api/analyze", json={"code": 5}).status_code == 400
    assert client.post("/api/analyze", json=[1, 2]).status_code == 400


def test_oversized_request_is_413_json(client):
    response = client.post("/api/analyze", data={"code": "x" * 2_000_000})
    assert response.status_code == 413 and response.get_json()["ok"] is False


def test_source_over_character_limit_is_400(client):
    response = client.post("/api/analyze", json={"code": "int a;\n" * 20_000})
    assert response.status_code in (400, 413)


def test_unknown_api_route_and_wrong_method_return_json(client):
    assert client.get("/api/nope").get_json()["ok"] is False
    assert client.get("/api/analyze").status_code == 405


def test_status_endpoint_reports_ml_and_compiler_state(client):
    body = client.get("/api/status").get_json()
    assert body["ok"] and "available" in body["ml"] and isinstance(body["compiler"], bool)


def test_report_download_is_valid_json_with_evidence_and_locations(client):
    response = client.post("/api/report", json={"source": PROGRAM})
    assert response.status_code == 200
    assert "attachment" in response.headers["Content-Disposition"]
    report = json.loads(response.data)
    assert report["project"] == "SecureCompile" and report["source"] == PROGRAM
    finding = report["findings"][0]
    assert finding["evidence"]["snippet"] and finding["location"]["line"] == 2
    assert finding["engines"] and "uncertainty" in finding
    assert "syntax_diagnostics" in report and "ml" in report and report["source_sha256"]


def test_report_requires_source(client):
    assert client.post("/api/report", json={}).status_code == 400
    assert client.post("/api/report", data="not json", content_type="text/plain").status_code == 400


def test_report_does_not_trust_client_supplied_results(client):
    response = client.post("/api/report", json={"source": PROGRAM, "result": {"ok": True, "findings": ["forged"]}})
    assert "forged" not in response.data.decode()


def test_fix_endpoints(client):
    analysis = client.post("/api/analyze", json={"code": PROGRAM}).get_json()
    fid = analysis["findings"][0]["id"]
    one = client.post("/api/fix", json={"code": PROGRAM, "finding_id": fid}).get_json()
    assert one["changed"] and "fgets(b, sizeof(b), stdin)" in one["proposed_source"]
    assert one["validation"]["checks"]
    everything = client.post("/api/fix_all", json={"code": PROGRAM}).get_json()
    assert everything["changed"] and everything["original_sha256"]


def test_fix_endpoint_validation(client):
    assert client.post("/api/fix", json={"code": PROGRAM}).status_code == 400
    assert client.post("/api/fix", json={"code": PROGRAM, "finding_id": "f-bad"}).status_code == 404
    assert client.post("/api/fix", json={"code": "", "finding_id": "f-x"}).status_code == 400
    assert client.post("/api/fix_all", json={"code": ""}).status_code == 400


def test_ml_failure_does_not_break_the_analyze_route(client, monkeypatch):
    import pipeline

    def boom(source):
        raise RuntimeError("model exploded")

    monkeypatch.setattr(pipeline.ml_infer, "predict_source", boom)
    response = client.post("/api/analyze", json={"code": PROGRAM})
    body = response.get_json()
    assert response.status_code == 200 and body["ml"]["status"] == "error"
    assert body["total"] >= 1  # rule-based results are still returned
