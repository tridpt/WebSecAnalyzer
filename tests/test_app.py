"""The local UI renders reports and rejects forged form submissions."""

from __future__ import annotations

import time

import app as web_app

from websec.findings import CheckResult, Severity
from websec.scanner import ScanReport


def _report():
    result = CheckResult(category="HTTP Security Headers")
    result.add("csp", "Thiếu CSP", Severity.HIGH, "Cần hạn chế script.")
    page = ScanReport(
        url="https://example.com/",
        final_url="https://example.com/",
        status_code=200,
        results=[result],
    )
    return ScanReport(
        url="https://example.com/",
        final_url="https://example.com/",
        status_code=200,
        pages=[page],
        max_pages=20,
    )


def test_post_requires_valid_csrf(monkeypatch):
    client = web_app.app.test_client()
    client.get("/")
    monkeypatch.setattr(web_app, "scan", lambda *args, **kwargs: _report())
    response = client.post("/", data={"url": "https://example.com", "owns": "on"})
    assert response.status_code == 400


def test_openapi_preview_requires_csrf_and_owner_confirmation(monkeypatch):
    client = web_app.app.test_client()
    home = client.get("/").get_data(as_text=True)
    assert 'id="openapi-preview-button"' in home
    assert 'id="openapi-route-picker"' in home
    with client.session_transaction() as user_session:
        csrf_token = user_session["csrf_token"]
    calls = []

    def fake_preview(url, path, *, allow_private):
        calls.append((url, path, allow_private))
        return {"routes": [{"method": "GET", "path": "/api/users/{id}",
                            "auth_declared": True, "parameters": ["id"]}],
                "total_get": 1, "eligible_get": 1, "limit": 1}

    monkeypatch.setattr(web_app, "preview_openapi", fake_preview)
    data = {"url": "https://example.com", "openapi_path": "/openapi.json",
            "owns": "on", "api_auth_secret": "MUST_NOT_GO_TO_PREVIEW"}
    assert client.post("/openapi/preview", data=data).status_code == 400
    assert client.post("/openapi/preview", data={
        **data, "csrf_token": csrf_token, "owns": "",
    }).status_code == 400
    assert calls == []
    response = client.post("/openapi/preview", data={**data, "csrf_token": csrf_token})
    assert response.status_code == 200
    assert response.json["routes"][0]["path"] == "/api/users/{id}"
    assert response.headers["Cache-Control"] == "no-store"
    assert "MUST_NOT_GO_TO_PREVIEW" not in response.get_data(as_text=True)
    assert calls == [("https://example.com", "/openapi.json", False)]


def test_scan_report_and_export_render(monkeypatch):
    client = web_app.app.test_client()
    client.get("/")
    with client.session_transaction() as user_session:
        csrf_token = user_session["csrf_token"]
    options_seen = []
    report = _report()
    report.api_requested = 1
    report.api_discovered = 1
    report.openapi_status = "loaded"
    report.api_routes = [{"method": "GET", "path": "/api/health", "auth_declared": False}]
    report.api_endpoints = [ScanReport(
        url="https://example.com/api/health",
        final_url="https://example.com/api/health",
        status_code=200,
        results=[CheckResult(category="API Access")],
    )]

    def fake_scan(*args, **kwargs):
        options_seen.append(kwargs)
        return report

    monkeypatch.setattr(web_app, "scan", fake_scan)
    monkeypatch.setattr(web_app.storage, "save_report", lambda report: 7)
    monkeypatch.setattr(web_app.storage, "get_report", lambda scan_id: report)
    monkeypatch.setattr(web_app.storage, "previous_scan_id", lambda url, scan_id: None)
    monkeypatch.setattr(web_app.storage, "score_trend", lambda url: [])

    response = client.post(
        "/",
        data={
            "url": "https://example.com", "owns": "on", "csrf_token": csrf_token,
            "openapi_path": "/openapi.json",
            "api_paths": "/api/health\nprivate /api/account",
            "api_auth_mode": "bearer",
            "api_auth_secret": "WEB_FORM_SECRET_DO_NOT_SAVE",
            "api_second_auth_mode": "cookie",
            "api_second_auth_secret": "session=SECOND_WEB_SECRET_DO_NOT_SAVE",
            "api_compare_fields": "/api/account /user/id",
            "js_discovery": "on",
        },
    )
    assert response.status_code == 302
    assert "WEB_FORM_SECRET_DO_NOT_SAVE" not in str(response.headers)
    assert "SECOND_WEB_SECRET_DO_NOT_SAVE" not in str(response.headers)
    job_url = response.headers["Location"]
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        state = client.get(job_url + "/status").json
        if state["status"] == "done":
            break
        time.sleep(0.01)
    assert state["status"] == "done"
    assert options_seen[0]["openapi_path"] == "/openapi.json"
    assert options_seen[0]["api_paths"] == ["/api/health", "private /api/account"]
    assert options_seen[0]["api_credential"].headers()["Authorization"] == (
        "Bearer WEB_FORM_SECRET_DO_NOT_SAVE"
    )
    assert options_seen[0]["api_second_credential"].headers()["Cookie"] == (
        "session=SECOND_WEB_SECRET_DO_NOT_SAVE"
    )
    assert options_seen[0]["api_compare_fields"] == ["/api/account /user/id"]
    assert options_seen[0]["js_discovery"] is True
    with client.session_transaction() as user_session:
        assert "WEB_FORM_SECRET_DO_NOT_SAVE" not in str(dict(user_session))
        assert "SECOND_WEB_SECRET_DO_NOT_SAVE" not in str(dict(user_session))
    page = client.get(state["report_url"]).get_data(as_text=True)
    assert "WEB_FORM_SECRET_DO_NOT_SAVE" not in page
    assert "SECOND_WEB_SECRET_DO_NOT_SAVE" not in page
    assert "Kết quả kiểm tra" in page
    assert "Kết quả theo từng trang" in page
    assert "Thiếu CSP" in page
    assert "1</strong> mức cao" in page
    assert "Tải JSON" in page
    assert "Phạm vi của điểm số" in page
    assert "Đã liệt kê 1 thao tác" in page
    assert "Endpoint API đã kiểm tra" in page

    export = client.get("/scan/7/export")
    assert export.status_code == 200
    assert "attachment; filename=websec-report-7.html" in export.headers["Content-Disposition"]
    html = export.get_data(as_text=True)
    assert "Thiếu CSP" in html
    assert "--surface:#111c2e" in html  # styles are embedded for offline viewing
    json_export = client.get("/scan/7/json")
    assert json_export.status_code == 200
    assert "WEB_FORM_SECRET_DO_NOT_SAVE" not in json_export.get_data(as_text=True)
    assert "SECOND_WEB_SECRET_DO_NOT_SAVE" not in json_export.get_data(as_text=True)
    assert json_export.json["pages"][0]["categories"][0]["findings"][0]["check"] == "csp"
    assert json_export.json["coverage"]["api_endpoints_checked"] == 1
    assert "attachment; filename=websec-report-7.json" in json_export.headers["Content-Disposition"]
    compare = client.get("/compare?old=6&new=7")
    assert compare.status_code == 200
    assert "Lỗi mới" in compare.get_data(as_text=True)


def test_invalid_test_account_input_is_not_echoed():
    client = web_app.app.test_client()
    client.get("/")
    with client.session_transaction() as user_session:
        csrf_token = user_session["csrf_token"]
    secret = "Cookie: session=WEB_FORM_SECRET_DO_NOT_ECHO"
    response = client.post("/", data={
        "url": "https://example.com", "owns": "on", "csrf_token": csrf_token,
        "api_paths": "private /api/account", "api_auth_mode": "cookie",
        "api_auth_secret": secret,
    })
    assert response.status_code == 200
    assert secret not in response.get_data(as_text=True)
    assert "WEB_FORM_SECRET_DO_NOT_ECHO" not in response.get_data(as_text=True)


def test_cancel_running_job(monkeypatch):
    def slow_scan(*args, control, **kwargs):
        while True:
            control.wait(0.1)

    monkeypatch.setattr(web_app, "scan", slow_scan)
    client = web_app.app.test_client()
    client.get("/")
    with client.session_transaction() as user_session:
        csrf_token = user_session["csrf_token"]
    response = client.post("/", data={
        "url": "localhost:12345", "owns": "on", "csrf_token": csrf_token,
    })
    assert response.status_code == 302
    job_url = response.headers["Location"]
    cancelled = client.post(job_url + "/cancel", data={"csrf_token": csrf_token})
    assert cancelled.status_code == 302
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        state = client.get(job_url + "/status").json
        if state["status"] != "running":
            break
        time.sleep(0.01)
    assert state["status"] == "cancelled"
