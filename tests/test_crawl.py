"""End-to-end crawl behavior against a local, disposable HTTP website."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

import pytest

from websec.fetch import RequestPacer
from websec.fetch import OutOfScope, fetch
from websec.report import to_dict
from websec.scanner import ScanReport, scan
from websec.targets import InvalidTarget


def test_crawl_links_sitemap_limit_scores_and_roundtrip(monkeypatch):
    seen_paths: list[str] = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            seen_paths.append(self.path)
            if self.path == "/":
                body = (
                    '<html><a href="/about#team">About</a>'
                    '<a href="/missing">Missing</a>'
                    '<a href="/logout">Logout</a>'
                    '<a href="https://outside.example/private">Outside</a></html>'
                ).encode()
                content_type = "text/html"
            elif self.path == "/sitemap.xml":
                body = (
                    '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
                    f'<url><loc>http://localhost:{self.server.server_port}/hidden</loc></url>'
                    '<url><loc>https://outside.example/</loc></url>'
                    '</urlset>'
                ).encode()
                content_type = "application/xml"
            elif self.path == "/about":
                body = b"<html>About</html>"
                content_type = "text/html"
            elif self.path == "/hidden":
                body = b"<html>Hidden</html>"
                content_type = "text/html"
            else:
                self.send_response(404)
                self.end_headers()
                return

            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            if self.path == "/about":
                self.send_header("Content-Security-Policy", "default-src 'self'")
                self.send_header("Strict-Transport-Security", "max-age=31536000")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("X-Frame-Options", "DENY")
                self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
                self.send_header("Permissions-Policy", "geolocation=()")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = Thread(target=server.serve_forever, daemon=True)
    worker.start()
    monkeypatch.setattr(
        "websec.scanner.RequestPacer",
        lambda **kwargs: RequestPacer(min_interval=0, **kwargs),
    )
    try:
        report = scan(
            f"localhost:{server.server_port}", use_osv=False, max_pages=3
        )
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)

    assert [page.final_url.rsplit("/", 1)[-1] for page in report.pages] == [
        "", "about", "hidden"
    ]
    assert "/logout" not in seen_paths
    assert "/missing" in seen_paths
    assert report.skipped_urls >= 1
    assert report.overall_score == min(report.page_score(page) for page in report.pages)
    assert report.page_score(report.pages[1]) > report.page_score(report.pages[0])

    restored = ScanReport.from_dict(to_dict(report))
    assert len(restored.pages) == 3
    assert restored.overall_score == report.overall_score
    assert restored.pages[1].final_url == report.pages[1].final_url


def test_page_limit_is_bounded():
    with pytest.raises(InvalidTarget, match="1 đến 30"):
        scan("localhost:8000", max_pages=31)


def test_json_root_is_not_counted_as_an_html_page():
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"ok": true}')

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        report = scan(f"localhost:{server.server_port}/", use_osv=False, max_pages=1)
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)
    assert report.pages == []
    assert to_dict(report)["coverage"]["checked_urls"]["html"] == []


def test_initial_redirect_to_unrelated_host_is_blocked(monkeypatch):
    class Redirect:
        is_redirect = True
        headers = {"Location": "https://unrelated.example/"}

        def close(self):
            pass

    class Session:
        def __init__(self):
            self.calls = 0

        def get(self, url, **kwargs):
            self.calls += 1
            return Redirect()

    session = Session()
    monkeypatch.setattr(
        "websec.targets.socket.getaddrinfo",
        lambda host, port, *, type: [(None, None, None, None, ("93.184.215.14", port))],
    )
    with pytest.raises(OutOfScope, match="tên miền khác"):
        fetch(
            session, "https://owned.example/", timeout=1, allow_private=False,
            pacer=RequestPacer(min_interval=0), initial_host="owned.example",
        )
    assert session.calls == 1


def test_request_pacer_spaces_requests(monkeypatch):
    clock = [100.0]
    sleeps = []

    def sleep(seconds):
        sleeps.append(seconds)
        clock[0] += seconds

    monkeypatch.setattr("websec.fetch.time.monotonic", lambda: clock[0])
    monkeypatch.setattr("websec.fetch.time.sleep", sleep)
    pacer = RequestPacer(min_interval=0.35)
    pacer.wait()
    pacer.wait()
    assert sleeps == [pytest.approx(0.35)]


def test_crawler_ignores_state_changing_query_links():
    from websec.crawler import extract_links

    found = extract_links(
        '<a href="/?action=delete">Delete</a><a href="/safe">Safe</a>',
        "https://example.com/", ("https", "example.com", 443),
    )
    assert found == ["https://example.com/safe"]
