"""Tests for JavaScript library detection and CVE lookup."""

from __future__ import annotations

from conftest import FakeResponse

from websec.findings import Severity
from websec.libraries import check_libraries
from websec.osv import Advisory


def _html(*srcs: str) -> str:
    tags = "".join(f'<script src="{s}"></script>' for s in srcs)
    return f"<html><head>{tags}</head></html>"


def test_no_scripts_reports_info():
    result = check_libraries(FakeResponse(text="<html></html>"), use_osv=False)
    assert len(result.findings) == 1
    assert result.findings[0].severity == Severity.INFO


def test_outdated_library_offline_is_high():
    html = _html("/static/jquery-3.4.1.min.js")
    result = check_libraries(FakeResponse(text=html), use_osv=False)
    jq = next(f for f in result.findings if f.check == "lib-jquery")
    assert jq.severity == Severity.HIGH
    assert "3.4.1" in jq.detail


def test_current_library_offline_is_info():
    html = _html("/static/jquery-3.6.0.min.js")
    result = check_libraries(FakeResponse(text=html), use_osv=False)
    jq = next(f for f in result.findings if f.check == "lib-jquery")
    assert jq.severity == Severity.INFO


def test_all_loaded_versions_are_checked():
    html = _html("/a/jquery-3.4.1.js", "/b/jquery-3.6.0.js")
    result = check_libraries(FakeResponse(text=html), use_osv=False)
    jq = [f for f in result.findings if f.check == "lib-jquery"]
    assert len(jq) == 2
    assert {f.severity for f in jq} == {Severity.HIGH, Severity.INFO}


def test_query_string_version_is_detected():
    html = _html("/assets/jquery.min.js?ver=3.4.1")
    result = check_libraries(FakeResponse(text=html), use_osv=False)
    assert any(f.severity == Severity.HIGH for f in result.findings)


def test_osv_advisories_become_high_findings(monkeypatch):
    def fake_query(package, version, timeout=10.0):
        assert package == "jquery"
        return [
            Advisory(id="GHSA-test-0001", summary="XSS in jQuery", severity="6.1")
        ]

    monkeypatch.setattr("websec.libraries.query_npm", fake_query)
    html = _html("/static/jquery-3.4.1.min.js")
    result = check_libraries(FakeResponse(text=html), use_osv=True)
    adv = [f for f in result.findings if "GHSA-test-0001" in f.title]
    assert adv and adv[0].severity == Severity.HIGH
    assert "osv.dev/vulnerability/GHSA-test-0001" in adv[0].recommendation


def test_osv_no_advisories_falls_back_to_info(monkeypatch):
    monkeypatch.setattr(
        "websec.libraries.query_npm", lambda *a, **k: []
    )
    html = _html("/static/jquery-3.6.0.min.js")
    result = check_libraries(FakeResponse(text=html), use_osv=True)
    jq = next(f for f in result.findings if f.check == "lib-jquery")
    assert jq.severity == Severity.INFO
    assert "OSV" in jq.detail


def test_osv_failure_does_not_claim_clear_result(monkeypatch):
    monkeypatch.setattr("websec.libraries.query_npm", lambda *a, **k: None)
    result = check_libraries(
        FakeResponse(text=_html("/jquery-3.6.0.js")), use_osv=True
    )
    assert "chưa tra được OSV" in result.findings[0].detail


def test_osv_lookup_cache_reused_across_pages(monkeypatch):
    calls = []

    def lookup(package, version):
        calls.append((package, version))
        return []

    monkeypatch.setattr("websec.libraries.query_npm", lookup)
    cache = {}
    response = FakeResponse(text=_html("/jquery-3.6.0.js"))
    check_libraries(response, advisory_cache=cache)
    check_libraries(response, advisory_cache=cache)
    assert calls == [("jquery", "3.6.0")]
