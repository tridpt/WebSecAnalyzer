"""CI policy uses a saved report and preserves JSON output on policy failure."""

from __future__ import annotations

import json

import main as cli
import requests

from websec.compare import compare_reports, new_high_issues
from websec.findings import CheckResult, Severity
from websec.report import render_json
from websec.scope import missing_baseline_scope
from websec.scanner import ScanReport
from websec.waivers import Waiver, finding_refs, waiver_payload
from dataclasses import replace
from datetime import datetime, timedelta, timezone


def _report(severity: Severity | None, *, url: str = "https://owned.test/") -> ScanReport:
    result = CheckResult(category="Content Security Policy")
    if severity is not None:
        result.add(
            "csp-inline", "CSP chứa unsafe-inline", severity,
            "Script nội tuyến được cho phép.",
        )
    page = ScanReport(url=url, final_url=url, status_code=200, results=[result])
    return ScanReport(url=url, final_url=url, status_code=200, pages=[page])


def test_new_high_includes_promoted_severity():
    changed = new_high_issues(_report(Severity.MEDIUM), _report(Severity.HIGH))
    assert len(changed) == 1
    assert changed[0]["check"] == "csp-inline"
    assert new_high_issues(_report(Severity.HIGH), _report(Severity.HIGH)) == []


def test_comparison_does_not_call_an_unchecked_url_fixed():
    old = _report(None)
    result = CheckResult(category="API Response Headers")
    result.add("api-nosniff", "Thiếu nosniff", Severity.LOW, "Header thiếu.")
    endpoint = ScanReport(
        "https://owned.test/api/private", "https://owned.test/api/private",
        200, results=[result],
    )
    old.api_endpoints = [endpoint]
    new = _report(None)
    comparison = compare_reports(old, new)
    assert comparison["scope_changed"] is True
    assert comparison["fixed_issues"] == []
    assert comparison["not_rechecked_count"] == 1
    new.api_endpoints = [ScanReport(endpoint.url, endpoint.final_url, 200)]
    comparison = compare_reports(old, new)
    assert comparison["scope_changed"] is False
    assert len(comparison["fixed_issues"]) == 1


def test_cli_fails_on_new_high_but_writes_current_json(tmp_path, monkeypatch, capsys):
    baseline = tmp_path / "baseline.json"
    baseline.write_text(render_json(_report(None)), encoding="utf-8")
    monkeypatch.setattr(cli, "scan", lambda *args, **kwargs: _report(Severity.HIGH))

    code = cli.main([
        "https://owned.test/", "--yes-i-own-this", "--json",
        "--fail-on-new-high", str(baseline),
    ])
    captured = capsys.readouterr()
    assert code == 3
    assert json.loads(captured.out)["pages"][0]["categories"][0]["findings"][0]["severity"] == "HIGH"
    assert "CI gate failed: 1 new high" in captured.err


def test_cli_passes_existing_high(tmp_path, monkeypatch, capsys):
    baseline = tmp_path / "baseline.json"
    baseline.write_text(render_json(_report(Severity.HIGH)), encoding="utf-8")
    monkeypatch.setattr(cli, "scan", lambda *args, **kwargs: _report(Severity.HIGH))

    code = cli.main([
        "https://owned.test/", "--yes-i-own-this", "--json",
        "--fail-on-new-high", str(baseline),
    ])
    captured = capsys.readouterr()
    assert code == 0
    assert json.loads(captured.out)["url"] == "https://owned.test/"
    assert "CI gate passed" in captured.err


def test_cli_rejects_invalid_or_other_site_baseline(tmp_path, monkeypatch, capsys):
    baseline = tmp_path / "baseline.json"
    baseline.write_text("{}", encoding="utf-8")
    calls = []
    monkeypatch.setattr(cli, "scan", lambda *args, **kwargs: calls.append(1))
    code = cli.main([
        "https://owned.test/", "--yes-i-own-this",
        "--fail-on-new-high", str(baseline),
    ])
    assert code == 2
    assert calls == []
    assert "JSON WebSecAnalyzer" in capsys.readouterr().err

    baseline.write_text(render_json(_report(None, url="https://other.test/")), encoding="utf-8")
    monkeypatch.setattr(cli, "scan", lambda *args, **kwargs: _report(None))
    code = cli.main([
        "https://owned.test/", "--yes-i-own-this",
        "--fail-on-new-high", str(baseline),
    ])
    assert code == 2
    assert "does not match" in capsys.readouterr().err


def test_cli_reports_connection_error_as_scan_failure(monkeypatch, capsys):
    def fail(*args, **kwargs):
        raise requests.ConnectionError("offline")

    monkeypatch.setattr(cli, "scan", fail)
    code = cli.main(["https://owned.test/", "--yes-i-own-this"])
    assert code == 1
    error = capsys.readouterr().err
    assert "Request failed: offline" in error
    assert "lockfile" not in error


def test_cli_passes_selected_api_scope_to_scan(monkeypatch, capsys):
    options_seen = []

    def fake_scan(*args, **kwargs):
        options_seen.append(kwargs)
        return _report(None)

    monkeypatch.setattr(cli, "scan", fake_scan)
    code = cli.main([
        "https://owned.test/", "--yes-i-own-this", "--json",
        "--openapi-path", "/openapi.json",
        "--api-url", "/api/health",
        "--api-private-url", "/api/account",
    ])
    assert code == 0
    assert options_seen[0]["openapi_path"] == "/openapi.json"
    assert options_seen[0]["api_paths"] == ["/api/health", "private /api/account"]
    assert json.loads(capsys.readouterr().out)["coverage"]["api_endpoints_checked"] == 0


def test_cli_reads_test_account_from_environment_without_printing_it(monkeypatch, capsys):
    secret = "session=CLI_SECRET_DO_NOT_PRINT"
    second_secret = "SECOND_CLI_SECRET_DO_NOT_PRINT"
    monkeypatch.setenv("WEBSEC_TEST_COOKIE", secret)
    monkeypatch.setenv("WEBSEC_TEST_BEARER_B", second_secret)
    options_seen = []

    def fake_scan(*args, **kwargs):
        options_seen.append(kwargs)
        return _report(None)

    monkeypatch.setattr(cli, "scan", fake_scan)
    code = cli.main([
        "https://owned.test/", "--yes-i-own-this", "--json",
        "--api-private-url", "/api/account",
        "--auth-cookie-env", "WEBSEC_TEST_COOKIE",
        "--auth-second-bearer-env", "WEBSEC_TEST_BEARER_B",
        "--api-compare-field", "/api/account /user/id",
    ])
    captured = capsys.readouterr()
    assert code == 0
    assert options_seen[0]["api_credential"].headers()["Cookie"] == secret
    assert options_seen[0]["api_second_credential"].headers()["Authorization"] == (
        f"Bearer {second_secret}"
    )
    assert options_seen[0]["api_compare_fields"] == ["/api/account /user/id"]
    assert secret not in captured.out + captured.err
    assert second_secret not in captured.out + captured.err
    assert "WEBSEC_TEST_COOKIE" not in captured.out + captured.err


def test_ci_fails_when_baseline_api_is_skipped_even_without_new_high(tmp_path, monkeypatch, capsys):
    baseline_report = _report(None)
    baseline_report.api_endpoints = [ScanReport(
        "https://owned.test/api/health", "https://owned.test/api/health", 200,
    )]
    baseline = tmp_path / "baseline.json"
    baseline.write_text(render_json(baseline_report), encoding="utf-8")
    current = _report(None)
    current.api_requested = 1
    current.api_skipped = 1
    current.api_skipped_paths = ["/api/health"]
    monkeypatch.setattr(cli, "scan", lambda *args, **kwargs: current)
    code = cli.main([
        "https://owned.test/", "--yes-i-own-this", "--json",
        "--fail-on-new-high", str(baseline),
    ])
    captured = capsys.readouterr()
    assert code == 3
    assert "api: https://owned.test/api/health" in captured.err
    emitted = json.loads(captured.out)
    assert emitted["coverage"]["checked_urls"]["api"] == []
    assert emitted["ci_gate"]["status"] == "failed"
    assert emitted["ci_gate"]["missing_scope"][0]["surface"] == "api"
    assert missing_baseline_scope(baseline_report, current)[0]["surface"] == "api"


def test_scope_gate_tracks_requested_and_final_urls_but_allows_growth():
    old = _report(None)
    old.pages.append(ScanReport("https://owned.test/a", "https://owned.test/b", 200))
    new = _report(None)
    new.pages.append(ScanReport("https://owned.test/a", "https://owned.test/c", 200))
    assert missing_baseline_scope(old, new) == [{
        "surface": "html", "requested_url": "https://owned.test/a",
        "final_url": "https://owned.test/b",
    }]
    new.pages.append(ScanReport("https://owned.test/a", "https://owned.test/b", 200))
    assert missing_baseline_scope(old, new) == []


def test_scope_gate_rejects_api_auth_expectation_downgrade():
    old = _report(None)
    endpoint = ScanReport(
        "https://owned.test/api/account", "https://owned.test/api/account", 200,
        api_expect_auth=True,
    )
    old.api_endpoints = [endpoint]
    new = _report(None)
    new.api_endpoints = [ScanReport(
        endpoint.url, endpoint.final_url, 200, api_expect_auth=False,
    )]
    missing = missing_baseline_scope(old, new)
    assert len(missing) == 1
    assert missing[0]["surface"] == "api"
    assert missing[0]["expects_authentication"] is True
    new.api_endpoints[0].api_expect_auth = True
    assert missing_baseline_scope(old, new) == []


def test_ci_keeps_selected_api_paths_even_if_baseline_probe_was_skipped():
    old = _report(None)
    old.api_selected_paths = ["/api/users/42"]
    old.api_requested = 1
    new = _report(None)
    missing = missing_baseline_scope(old, new)
    assert missing == [{
        "surface": "api_selected", "requested_url": "/api/users/42",
        "final_url": "/api/users/42",
    }]
    new.api_selected_paths = ["/api/users/42"]
    new.api_skipped_paths = ["/api/users/42"]
    assert missing_baseline_scope(old, new) == missing
    new.api_skipped_paths = []
    assert missing_baseline_scope(old, new) == []
    restored = ScanReport.from_dict(json.loads(render_json(old)))
    assert restored.api_selected_paths == ["/api/users/42"]


def test_ci_rejects_lost_authenticated_api_check(tmp_path, monkeypatch, capsys):
    endpoint_url = "https://owned.test/api/account"
    baseline_report = _report(None)
    baseline_report.api_endpoints = [ScanReport(
        endpoint_url, endpoint_url, 401,
        api_expect_auth=True, api_auth_status_code=200,
    )]
    baseline = tmp_path / "baseline.json"
    baseline.write_text(render_json(baseline_report), encoding="utf-8")
    current = _report(None)
    current.api_endpoints = [ScanReport(
        endpoint_url, endpoint_url, 401,
        api_expect_auth=True, api_auth_status_code=None,
    )]
    monkeypatch.setattr(cli, "scan", lambda *args, **kwargs: current)
    args = [
        "https://owned.test/", "--yes-i-own-this", "--json",
        "--fail-on-new-high", str(baseline),
    ]

    for status in (None, 401, 403):
        current.api_endpoints[0].api_auth_status_code = status
        assert cli.main(args) == 3
        emitted = json.loads(capsys.readouterr().out)
        assert emitted["ci_gate"]["status"] == "failed"
        assert emitted["ci_gate"]["missing_scope"][0]["authenticated_status_code"] == 200

    current.api_endpoints[0].api_auth_status_code = 200
    assert cli.main(args) == 0
    assert json.loads(capsys.readouterr().out)["ci_gate"]["status"] == "passed"


def test_ci_rejects_lost_cross_account_field_scope():
    endpoint_url = "https://owned.test/api/account"
    old = _report(None)
    old.api_endpoints = [ScanReport(
        endpoint_url, endpoint_url, 401, api_expect_auth=True,
        api_auth_status_code=200, api_second_auth_status_code=200,
        api_compared_pointers=["/user/id"],
    )]
    new = _report(None)
    new.api_endpoints = [ScanReport(
        endpoint_url, endpoint_url, 401, api_expect_auth=True,
        api_auth_status_code=200, api_second_auth_status_code=200,
        api_compared_pointers=[],
    )]
    assert missing_baseline_scope(old, new)[0]["compared_pointers"] == ["/user/id"]
    new.api_endpoints[0].api_compared_pointers = ["/user/id", "/user/name"]
    assert missing_baseline_scope(old, new) == []


def test_ci_rejects_lost_cors_probe_coverage_but_accepts_changed_status():
    endpoint_url = "https://owned.test/api/account"
    old = _report(None)
    old.api_endpoints = [ScanReport(
        endpoint_url, endpoint_url, 401,
        api_cors_preflight_status_code=204,
        api_cors_credentialed_status_code=200,
    )]
    new = _report(None)
    new.api_endpoints = [ScanReport(endpoint_url, endpoint_url, 401)]
    missing = missing_baseline_scope(old, new)
    assert missing[0]["cors_preflight_status_code"] == 204
    assert missing[0]["cors_credentialed_status_code"] == 200
    new.api_endpoints[0].api_cors_preflight_status_code = 403
    assert missing_baseline_scope(old, new)
    new.api_endpoints[0].api_cors_credentialed_status_code = 403
    assert missing_baseline_scope(old, new) == []


def test_ci_requires_completed_browser_cors_probe_when_in_baseline():
    endpoint_url = "https://owned.test/api/account"
    old = _report(None)
    old.api_endpoints = [ScanReport(
        endpoint_url, endpoint_url, 401, api_cors_browser_outcome="readable",
    )]
    new = _report(None)
    new.api_endpoints = [ScanReport(
        endpoint_url, endpoint_url, 401, api_cors_browser_outcome="inconclusive",
    )]
    assert missing_baseline_scope(old, new)[0]["cors_browser_outcome"] == "readable"
    new.api_endpoints[0].api_cors_browser_outcome = "blocked"
    assert missing_baseline_scope(old, new) == []


def test_ci_active_exception_expires_and_never_overrides_scope(tmp_path, monkeypatch, capsys):
    baseline = tmp_path / "baseline.json"
    baseline.write_text(render_json(_report(None)), encoding="utf-8")
    current = _report(Severity.HIGH)
    ref = next(item for item in finding_refs(current) if item.finding.severity == Severity.HIGH)
    today = datetime.now(timezone.utc).date()
    waiver = Waiver.from_finding(ref, "Đã xác minh cấu hình tạm thời", (today + timedelta(days=1)).isoformat())
    exceptions = tmp_path / "exceptions.json"
    exceptions.write_text(json.dumps(waiver_payload([waiver])), encoding="utf-8")
    monkeypatch.setattr(cli, "scan", lambda *args, **kwargs: current)
    args = [
        "https://owned.test/", "--yes-i-own-this", "--json",
        "--fail-on-new-high", str(baseline), "--waivers", str(exceptions),
    ]
    assert cli.main(args) == 0
    captured = capsys.readouterr()
    assert "1 active exception" in captured.err
    emitted = json.loads(captured.out)
    assert emitted["pages"][0]["categories"][0]["findings"][0]["severity"] == "HIGH"
    assert emitted["ci_gate"]["status"] == "passed"
    assert emitted["ci_gate"]["applied_exceptions"][0]["reason"] == waiver.reason

    expired = replace(waiver, expires_on=(today - timedelta(days=1)).isoformat())
    exceptions.write_text(json.dumps(waiver_payload([expired])), encoding="utf-8")
    assert cli.main(args) == 3
    assert "1 new high" in capsys.readouterr().err

    current.api_endpoints = []
    old_with_api = _report(None)
    old_with_api.api_endpoints = [ScanReport(
        "https://owned.test/api/health", "https://owned.test/api/health", 200,
    )]
    baseline.write_text(render_json(old_with_api), encoding="utf-8")
    exceptions.write_text(json.dumps(waiver_payload([waiver])), encoding="utf-8")
    assert cli.main(args) == 3
    assert "baseline URL/API" in capsys.readouterr().err
