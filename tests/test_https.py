"""HTTPS redirect and legacy-protocol checks."""

from __future__ import annotations

import ssl

from websec.fetch import RequestPacer
from websec.findings import CheckResult, Severity
from websec.https_redirect import check_https_redirect
from websec.tls import _check_legacy_tls


class _Response:
    def __init__(self, status: int, location: str | None = None):
        self.status_code = status
        self.headers = {"Location": location} if location else {}
        self.is_redirect = 300 <= status < 400
        self.closed = False

    def close(self):
        self.closed = True


class _Session:
    def __init__(self, response):
        self.response = response
        self.urls = []

    def get(self, url, **kwargs):
        self.urls.append(url)
        assert kwargs["allow_redirects"] is False
        return self.response


def _redirect_result(response):
    session = _Session(response)
    result = check_https_redirect(
        session, "https://example.com/path", timeout=1, allow_private=True,
        pacer=RequestPacer(min_interval=0),
    )
    assert session.urls == ["http://example.com/"]
    assert response.closed
    return result


def test_http_redirect_to_same_host_is_clear():
    result = _redirect_result(_Response(301, "https://example.com/"))
    assert result.score == 100


def test_http_content_is_high_severity():
    result = _redirect_result(_Response(200))
    assert result.findings[0].severity == Severity.HIGH


def test_http_forbidden_without_redirect_is_medium():
    result = _redirect_result(_Response(403))
    assert result.findings[0].severity == Severity.MEDIUM


def test_redirect_to_other_host_does_not_pass():
    result = _redirect_result(_Response(302, "https://elsewhere.example/"))
    assert result.findings[0].severity == Severity.MEDIUM


def test_legacy_tls_reports_accepted_and_uncertain(monkeypatch):
    def fake_probe(host, port, version, timeout):
        return True if version == ssl.TLSVersion.TLSv1 else None

    monkeypatch.setattr("websec.tls._accepts_legacy_tls", fake_probe)
    result = CheckResult(category="TLS/SSL Configuration")
    _check_legacy_tls(result, "example.com", 443, 1)
    assert any(f.severity == Severity.HIGH and "TLS 1.0" in f.title for f in result.findings)
    assert any("Chưa kiểm tra" in f.title for f in result.findings)
