"""Target boundaries for the scanner's network requests."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

import pytest

from websec.scanner import scan
from websec.targets import InvalidTarget, normalize_target


def test_rejects_private_addresses_by_default():
    with pytest.raises(InvalidTarget, match="nội bộ"):
        normalize_target("http://192.168.1.10:8080/")
    assert normalize_target("http://192.168.1.10:8080/", allow_private=True) == (
        "http://192.168.1.10:8080/"
    )


@pytest.mark.parametrize(
    ("entered", "expected"),
    [
        ("localhost:3000", "http://localhost:3000"),
        ("127.0.0.1:8000", "http://127.0.0.1:8000"),
        ("[::1]:8080", "http://[::1]:8080"),
    ],
)
def test_loopback_is_allowed_and_defaults_to_http(entered, expected):
    assert normalize_target(entered) == expected


def test_other_hostname_resolving_to_loopback_is_blocked(monkeypatch):
    monkeypatch.setattr(
        "websec.targets.socket.getaddrinfo",
        lambda host, port, *, type: [(None, None, None, None, ("127.0.0.1", port))],
    )
    with pytest.raises(InvalidTarget, match="nội bộ"):
        normalize_target("https://other.example/")


@pytest.mark.parametrize(
    "url", ["file:///etc/passwd", "https://user:pass@example.com", "https://x:0"]
)
def test_rejects_invalid_targets(url):
    with pytest.raises(InvalidTarget):
        normalize_target(url, allow_private=True)


def test_public_redirect_to_private_is_stopped_before_second_request(monkeypatch):
    def fake_dns(host, port, *, type):
        address = "93.184.215.14" if host == "public.example" else "127.0.0.1"
        return [(None, None, None, None, (address, port))]

    class Redirect:
        is_redirect = True
        headers = {"Location": "http://127.0.0.1/admin"}
        url = "https://public.example/"

        def close(self):
            pass

    class Session:
        def __init__(self):
            self.headers = {}
            self.calls = 0

        def close(self):
            pass

        def get(self, url, **kwargs):
            self.calls += 1
            assert self.calls == 1
            return Redirect()

    instance = Session()
    monkeypatch.setattr("websec.targets.socket.getaddrinfo", fake_dns)
    monkeypatch.setattr("websec.scanner.requests.Session", lambda: instance)

    with pytest.raises(InvalidTarget, match="localhost"):
        scan("https://public.example/", use_osv=False)
    assert instance.calls == 1


def test_response_larger_than_limit_is_rejected(monkeypatch):
    class LargeResponse:
        is_redirect = False
        headers = {}
        url = "http://127.0.0.1/"

        def iter_content(self, chunk_size):
            yield b"x" * 1_000_001

        def close(self):
            pass

    class Session:
        def __init__(self):
            self.headers = {}

        def close(self):
            pass

        def get(self, url, **kwargs):
            return LargeResponse()

    monkeypatch.setattr("websec.scanner.requests.Session", Session)
    with pytest.raises(InvalidTarget, match="1 MB"):
        scan("http://127.0.0.1/", use_osv=False, allow_private=True)


def test_real_local_response_produces_report():
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            body = b'<html><script src="/jquery-3.4.1.min.js"></script></html>'
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Set-Cookie", "sid=abc; Path=/")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        report = scan(
            f"localhost:{server.server_port}/",
            use_osv=False,
        )
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)

    assert report.status_code == 200
    assert report.url.startswith("http://localhost:")
    assert report.checked_categories == 7
    assert report.issue_counts["HIGH"] >= 1
    assert len(report.pages) == 1
    cookie_findings = next(r for r in report.pages[0].results if r.category == "Cookie Flags")
    assert {f.check for f in cookie_findings.findings} == {
        "cookie-httponly", "cookie-secure", "cookie-samesite"
    }
