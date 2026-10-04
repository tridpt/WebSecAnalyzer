"""Tests for HTTP security header checks."""

from __future__ import annotations

from conftest import FakeResponse

from websec.findings import Severity
from websec.headers import check_headers
from websec.policies import check_csp

# A fully-hardened set of response headers.
_SECURE_HEADERS = {
    "Content-Security-Policy": "default-src 'self'",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=()",
}


def _checks(result):
    return {f.check for f in result.findings}


def test_missing_all_headers_flags_each():
    result = check_headers(FakeResponse(headers={}))
    checks = _checks(result)
    assert "strict-transport-security" in checks
    assert "x-frame-options" in checks


def test_missing_csp_is_high_severity():
    result = check_csp(FakeResponse(headers={}))
    csp = next(f for f in result.findings if f.check == "csp-missing")
    assert csp.severity == Severity.HIGH


def test_hsts_is_not_required_on_plain_http():
    response = FakeResponse(headers={})
    response.url = "http://localhost:8809/"
    checks = _checks(check_headers(response))
    assert "strict-transport-security" not in checks
    assert "x-content-type-options" in checks


def test_secure_headers_produce_only_info():
    result = check_headers(FakeResponse(headers=dict(_SECURE_HEADERS)))
    assert all(f.severity == Severity.INFO for f in result.findings)


def test_case_insensitive_header_matching():
    # Lowercase header keys should still be recognized as present.
    lowered = {k.lower(): v for k, v in _SECURE_HEADERS.items()}
    result = check_headers(FakeResponse(headers=lowered))
    assert all(f.severity == Severity.INFO for f in result.findings)


def test_weak_csp_is_flagged():
    headers = dict(_SECURE_HEADERS)
    headers["Content-Security-Policy"] = "default-src 'self' 'unsafe-inline'"
    result = check_csp(FakeResponse(headers=headers))
    weak = [f for f in result.findings if f.check == "csp-inline"]
    assert weak and weak[0].severity == Severity.MEDIUM


def test_frame_ancestors_satisfies_clickjacking_check():
    headers = dict(_SECURE_HEADERS)
    headers.pop("X-Frame-Options")
    headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'"
    result = check_headers(FakeResponse(headers=headers))
    assert "x-frame-options" not in _checks(result)


def test_short_hsts_is_flagged():
    headers = dict(_SECURE_HEADERS)
    headers["Strict-Transport-Security"] = "max-age=3600"
    result = check_headers(FakeResponse(headers=headers))
    assert any(f.check == "strict-transport-security" for f in result.findings)


def test_leaky_server_header_flagged():
    headers = dict(_SECURE_HEADERS)
    headers["Server"] = "nginx/1.18.0"
    result = check_headers(FakeResponse(headers=headers))
    leaks = [f for f in result.findings if f.check == "server"]
    assert leaks and leaks[0].severity == Severity.LOW
