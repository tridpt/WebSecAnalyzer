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
    headers["Server"] = "nginx/1.18.0 token=PRIVATE"
    result = check_headers(FakeResponse(headers=headers))
    leaks = [f for f in result.findings if f.check == "server"]
    assert leaks and leaks[0].severity == Severity.LOW
    assert "PRIVATE" not in leaks[0].detail


def test_nosniff_requires_exact_value():
    headers = dict(_SECURE_HEADERS)
    headers["X-Content-Type-Options"] = "nosniff, nosniff"
    finding = next(f for f in check_headers(FakeResponse(headers=headers)).findings
                   if f.check == "x-content-type-options")
    assert finding.severity == Severity.MEDIUM
    assert "nosniff, nosniff" in finding.evidence
    headers["X-Content-Type-Options"] = "  NoSniff  "
    assert "x-content-type-options" not in _checks(check_headers(FakeResponse(headers=headers)))


def test_xfo_invalid_but_valid_csp_frame_ancestors_is_lower_risk():
    headers = dict(_SECURE_HEADERS)
    headers["X-Frame-Options"] = "ALLOW-FROM https://other.test"
    invalid = next(f for f in check_headers(FakeResponse(headers=headers)).findings
                   if f.check == "x-frame-options")
    assert invalid.severity == Severity.MEDIUM
    headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'self'"
    fallback = next(f for f in check_headers(FakeResponse(headers=headers)).findings
                    if f.check == "x-frame-options")
    assert fallback.severity == Severity.LOW


def test_broad_frame_ancestors_overrides_valid_xfo_and_report_only_does_not_count():
    headers = dict(_SECURE_HEADERS)
    headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors *"
    assert "frame-ancestors" in _checks(check_headers(FakeResponse(headers=headers)))
    headers["Content-Security-Policy"] = "default-src 'self'"
    headers.pop("X-Frame-Options")
    headers["Content-Security-Policy-Report-Only"] = "frame-ancestors 'none'"
    assert "x-frame-options" in _checks(check_headers(FakeResponse(headers=headers)))
    headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors https://trusted.test"
    assert "x-frame-options" not in _checks(check_headers(FakeResponse(headers=headers)))
    headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors javascript:"
    assert "frame-ancestors" in _checks(check_headers(FakeResponse(headers=headers)))


def test_referrer_policy_uses_last_recognized_value():
    headers = dict(_SECURE_HEADERS)
    headers["Referrer-Policy"] = "no-referrer, unsafe-url"
    weak = next(f for f in check_headers(FakeResponse(headers=headers)).findings
                if f.check == "referrer-policy")
    assert weak.severity == Severity.MEDIUM
    headers["Referrer-Policy"] = "unsafe-url, no-referrer"
    assert "referrer-policy" not in _checks(check_headers(FakeResponse(headers=headers)))
    headers["Referrer-Policy"] = "not-a-policy"
    assert "referrer-policy" in _checks(check_headers(FakeResponse(headers=headers)))


def test_permissions_policy_flags_malformed_and_broad_but_accepts_scoped():
    headers = dict(_SECURE_HEADERS)
    headers["Permissions-Policy"] = 'camera=*, geolocation=(self), microphone=("https://trusted.test")'
    result = check_headers(FakeResponse(headers=headers))
    assert "permissions-policy-broad" in _checks(result)
    assert "permissions-policy-invalid" not in _checks(result)
    headers["Permissions-Policy"] = 'camera=("https://trusted.test/path?token=PRIVATE")'
    invalid = next(f for f in check_headers(FakeResponse(headers=headers)).findings
                   if f.check == "permissions-policy-invalid")
    assert "PRIVATE" not in invalid.evidence
    headers["Permissions-Policy"] = 'camera=(), microphone=(self), geolocation=("https://trusted.test")'
    assert all(f.severity == Severity.INFO for f in check_headers(FakeResponse(headers=headers)).findings)


def test_hsts_zero_duplicate_and_malformed_max_age_are_not_treated_as_valid():
    headers = dict(_SECURE_HEADERS)
    for value in ("max-age=0", "max-age=31536000; max-age=31536000", "max-age=bogus", ""):
        headers["Strict-Transport-Security"] = value
        finding = next(f for f in check_headers(FakeResponse(headers=headers)).findings
                       if f.check == "strict-transport-security")
        assert finding.severity == Severity.HIGH
    headers["Strict-Transport-Security"] = "max-age=3600"
    finding = next(f for f in check_headers(FakeResponse(headers=headers)).findings
                   if f.check == "strict-transport-security")
    assert finding.severity == Severity.MEDIUM
