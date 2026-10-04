"""Tests for cookie flag checks."""

from __future__ import annotations

from conftest import FakeResponse

from websec.cookies import check_cookies
from websec.findings import Severity


def _titles(result):
    return [f.title for f in result.findings]


def test_no_cookies_is_info_only():
    result = check_cookies(FakeResponse(set_cookies=[]))
    assert len(result.findings) == 1
    assert result.findings[0].severity == Severity.INFO


def test_insecure_cookie_flags_all_three():
    result = check_cookies(FakeResponse(set_cookies=["sid=abc; Path=/"]))
    checks = {f.check for f in result.findings}
    assert checks == {"cookie-httponly", "cookie-secure", "cookie-samesite"}


def test_secure_cookie_has_no_findings():
    cookie = "sid=abc; Path=/; HttpOnly; Secure; SameSite=Lax"
    result = check_cookies(FakeResponse(set_cookies=[cookie]))
    assert all(f.severity == Severity.INFO for f in result.findings)


def test_missing_samesite_only():
    cookie = "sid=abc; HttpOnly; Secure"
    result = check_cookies(FakeResponse(set_cookies=[cookie]))
    checks = {f.check for f in result.findings}
    assert checks == {"cookie-samesite"}


def test_flag_detection_is_case_insensitive():
    cookie = "sid=abc; httponly; SECURE; samesite=strict"
    result = check_cookies(FakeResponse(set_cookies=[cookie]))
    assert all(f.severity == Severity.INFO for f in result.findings)


def test_multiple_cookies_each_checked():
    cookies = ["a=1", "b=2; HttpOnly; Secure; SameSite=Lax"]
    result = check_cookies(FakeResponse(set_cookies=cookies))
    # Cookie 'a' missing all three -> its name appears in findings.
    assert any("'a'" in f.title for f in result.findings)
