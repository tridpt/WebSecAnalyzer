"""Exploitation context appears in reports without turning signals into claims."""

from __future__ import annotations

import app as web_app

from websec.compare import compare_reports
from websec.findings import CheckResult, Severity
from websec.report import render_text, to_dict
from websec.scanner import ScanReport


def _report(*, with_issue: bool) -> ScanReport:
    result = CheckResult(category="Cookie Flags")
    if with_issue:
        result.add(
            "cookie-httponly", "Cookie phiên thiếu HttpOnly", Severity.MEDIUM,
            "Cookie không có cờ HttpOnly.", "Thêm HttpOnly.",
        )
    return ScanReport(
        "https://owned.test/", "https://owned.test/", 200,
        results=[result] if with_issue else [],
    )


def test_impacts_are_specific_and_conditional_while_info_has_none():
    examples = [
        ("Content Security Policy", "csp-missing", "XSS"),
        ("Cookie Flags", "cookie-httponly", "XSS"),
        ("API Access", "api-auth-missing", "mã HTTP 2xx"),
        ("HTML Resource Security", "external-script-no-sri", "bên thứ ba"),
        ("API CORS Credentialed", "cors-bearer-cross-origin", "đã có Bearer token"),
        ("JavaScript Libraries", "lib-jquery", "xác minh phiên bản thật"),
        ("npm Lockfile / OSV", "npm:jquery@1.0:GHSA-test", "advisory"),
    ]
    for category, check, expected in examples:
        result = CheckResult(category=category)
        result.add(check, "Phát hiện", Severity.MEDIUM, "Chi tiết.")
        assert expected in result.findings[0].impact
    result = CheckResult(category="Content Security Policy")
    result.add("csp-ok", "CSP ổn", Severity.INFO, "Không thấy lỗi.")
    assert result.findings[0].impact == ""


def test_impact_round_trip_legacy_json_text_and_comparison():
    current = _report(with_issue=True)
    impact = current.results[0].findings[0].impact
    assert "XSS" in impact and "Nếu" in impact
    data = to_dict(current)
    assert data["categories"][0]["findings"][0]["impact"] == impact
    del data["categories"][0]["findings"][0]["impact"]
    restored = ScanReport.from_dict(data)
    assert restored.results[0].findings[0].impact == impact
    assert f"Nếu không sửa: {impact}" in render_text(restored, use_color=False)
    comparison = compare_reports(_report(with_issue=False), restored)
    assert comparison["new_issues"][0]["impact"] == impact


def test_web_history_html_export_json_and_comparison_show_impact(monkeypatch):
    old = _report(with_issue=False)
    new = _report(with_issue=True)
    monkeypatch.setattr(web_app.storage, "get_report", lambda scan_id: {1: old, 2: new}.get(scan_id))
    monkeypatch.setattr(web_app.storage, "list_waivers", lambda: [])
    monkeypatch.setattr(web_app.storage, "score_trend", lambda _url: [])
    monkeypatch.setattr(web_app.storage, "previous_scan_id", lambda _url, _id: None)
    client = web_app.app.test_client()
    for path in ("/scan/2", "/scan/2/export", "/compare?old=1&new=2"):
        response = client.get(path)
        assert response.status_code == 200
        assert "Nếu không sửa:" in response.get_data(as_text=True)
    assert "XSS" in client.get("/scan/2/json").json["categories"][0]["findings"][0]["impact"]
