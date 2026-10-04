"""Evidence exports keep reproducible metadata while omitting secrets."""

from __future__ import annotations

import json

import requests

from websec.evidence import evidence_bundle, snapshot_response
from websec.findings import CheckResult, Severity
from websec.report import to_dict
from websec.scanner import ScanReport


def test_response_snapshot_redacts_cookie_authorization_url_and_body():
    response = requests.Response()
    response.url = (
        "https://user:password@example.com/reset/Abc123456789012345678901234"
        "?token=PRIVATE_QUERY&mode=full"
    )
    response.status_code = 302
    response.headers.update({
        "Content-Security-Policy": "script-src 'nonce-NONCE_SECRET' https://cdn.example/x.js?key=PRIVATE_KEY",
        "Set-Cookie": "session=PRIVATE_COOKIE; HttpOnly; Secure; SameSite=Lax; Path=/",
        "Location": "https://example.com/account?token=PRIVATE_LOCATION",
        "Authorization": "Bearer PRIVATE_AUTH",
        "Access-Control-Allow-Origin": "https://other.example",
        "Vary": "Origin, PRIVATE_AUTH",
    })
    response._content = b"PRIVATE_BODY"
    response.websec_observed_at = "2026-10-04T10:00:00Z"
    observation = snapshot_response(
        response, purpose="api_credentialed_cors",
        request_headers={"Origin": "https://other.example", "Authorization": "Bearer PRIVATE_AUTH"},
        credential_mode="bearer",
        redact_values=["PRIVATE_AUTH"],
    )
    encoded = json.dumps(observation)
    for secret in (
        "PRIVATE_QUERY", "PRIVATE_COOKIE", "PRIVATE_LOCATION", "PRIVATE_AUTH",
        "PRIVATE_BODY", "NONCE_SECRET", "PRIVATE_KEY", "user:password",
    ):
        assert secret not in encoded
    assert observation["observed_at"] == "2026-10-04T10:00:00Z"
    assert observation["status_code"] == 302
    assert observation["method"] == "GET"
    assert observation["response_headers"]["Set-Cookie"] == [
        "session=[REDACTED]; Secure; HttpOnly; SameSite=Lax; Path=/"
    ]
    assert "Authorization" not in observation["request_headers"]
    assert observation["response_headers"]["Vary"] == "Origin, [OTHER REDACTED]"


def test_bundle_maps_findings_to_response_and_web_export(monkeypatch):
    response = requests.Response()
    response.url = "https://example.com/account?session=PRIVATE"
    response.status_code = 200
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.websec_observed_at = "2026-10-04T10:00:00Z"
    check = CheckResult(category="HTTP Security Headers")
    check.add("frame", "Thiếu X-Frame-Options", Severity.MEDIUM, "Missing")
    page = ScanReport(
        url=response.url, final_url=response.url, status_code=200,
        results=[check], observations=[snapshot_response(response, purpose="page")],
    )
    report = ScanReport(
        url="https://example.com/", final_url="https://example.com/",
        status_code=200, pages=[page], max_pages=1,
    )
    bundle = evidence_bundle(ScanReport.from_dict(to_dict(report)))
    html = bundle["surfaces"][1]
    assert html["findings"][0]["response_ids"] == ["r1"]
    assert html["findings"][0]["finding_index"] == 1
    assert html["responses"][0]["observed_at"] == "2026-10-04T10:00:00Z"
    assert "PRIVATE" not in json.dumps(bundle)

    from app import app
    from websec import storage

    monkeypatch.setattr(storage, "get_report", lambda scan_id: report if scan_id == 7 else None)
    client = app.test_client()
    exported = client.get("/scan/7/evidence.json")
    assert exported.status_code == 200
    assert exported.json["format"] == "websec-evidence-v1"
    assert exported.headers["Cache-Control"] == "no-store"
    assert "attachment; filename=websec-evidence-7.json" in exported.headers[
        "Content-Disposition"
    ]
    assert client.get("/scan/8/evidence.json").status_code == 404
