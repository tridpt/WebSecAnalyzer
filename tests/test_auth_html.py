"""Selected HTML pages are fetched with a disposable test session only."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

import pytest

from websec.api import parse_api_credential, validate_api_auth_transport
from websec.auth_html import parse_auth_html_paths
from websec.compare import compare_reports
from websec.evidence import evidence_bundle
from websec.fetch import RequestPacer
from websec.report import render_json, to_dict
from websec.scanner import ScanReport, scan
from websec.scope import missing_baseline_scope
from websec.targets import InvalidTarget


def test_selected_html_uses_session_without_crawling_or_saving_secrets(monkeypatch):
    secret = "AUTH_HTML_TEST_SECRET_49822"
    requests_seen: list[tuple[str, str | None]] = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            cookie = self.headers.get("Cookie")
            requests_seen.append((self.path, cookie))
            if self.path == "/sitemap.xml":
                self.send_response(404)
                self.end_headers()
                return
            if self.path in {"/private", "/redirect"} and cookie != f"session={secret}":
                self.send_response(302)
                self.send_header("Location", "/signin")
                self.end_headers()
                return
            if self.path == "/redirect":
                self.send_response(302)
                self.send_header("Location", "https://outside.example/")
                self.end_headers()
                return
            body = (
                b'<html><a href="/not-selected">Do not follow</a></html>'
                if self.path == "/private" else b"<html>OK</html>"
            )
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            if self.path == "/private":
                self.send_header("Content-Security-Policy", f"default-src 'self'; report-uri /{secret}")
                self.send_header("Set-Cookie", f"session={secret}; HttpOnly; SameSite=Lax")
            self.send_header("Content-Length", str(len(body)))
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
            f"localhost:{server.server_port}", use_osv=False, max_pages=4,
            auth_html_paths=["/private", "/redirect", "/same"],
            api_credential=parse_api_credential("cookie", f"session={secret}"),
        )
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)

    assert report.auth_page_selected_paths == ["/private", "/redirect", "/same"]
    assert len(report.auth_pages) == 2
    assert report.auth_pages[0].auth_verified is True
    assert report.auth_pages[0].auth_anonymous_status_code == 302
    assert report.auth_pages[1].auth_verified is False
    assert report.auth_page_unverified_paths == ["/same"]
    assert report.auth_page_skipped_paths == ["/redirect"]
    assert len(report.pages) + len(report.auth_pages) <= report.max_pages
    assert ("/private", None) in requests_seen
    assert ("/private", f"session={secret}") in requests_seen
    assert ("/redirect", f"session={secret}") in requests_seen
    assert not any(path == "/not-selected" for path, _cookie in requests_seen)
    assert not any(cookie and path in {"/", "/sitemap.xml"} for path, cookie in requests_seen)
    for exported in (render_json(report), str(evidence_bundle(report))):
        assert secret not in exported
    assert report.overall_score == min(
        report.page_score(page) for page in report.pages + report.auth_pages
    )

    restored = ScanReport.from_dict(to_dict(report))
    assert restored.auth_pages[0].auth_verified is True
    assert restored.auth_page_selected_paths == ["/private", "/redirect", "/same"]
    missing = ScanReport.from_dict(to_dict(report))
    missing.auth_pages = []
    missing.auth_page_skipped_paths = ["/private", "/redirect", "/same"]
    assert any(item["surface"] == "auth_html" for item in missing_baseline_scope(report, missing))
    downgraded = ScanReport.from_dict(to_dict(report))
    downgraded.auth_pages[0].auth_verified = False
    downgraded.auth_pages[0].results = []
    assert any(item["surface"] == "auth_html" for item in missing_baseline_scope(report, downgraded))
    assert compare_reports(report, downgraded)["not_rechecked_count"] > 0

    import app as web_app
    monkeypatch.setattr(web_app.storage, "get_report", lambda _scan_id: report)
    monkeypatch.setattr(web_app.storage, "list_waivers", lambda: [])
    monkeypatch.setattr(web_app.storage, "score_trend", lambda _url: [])
    monkeypatch.setattr(web_app.storage, "previous_scan_id", lambda _url, _id: None)
    html = web_app.app.test_client().get("/scan/99").get_data(as_text=True)
    assert "Trang HTML với phiên thử nghiệm" in html
    assert "Chưa xác minh được quyền truy cập sau đăng nhập" in html
    assert secret not in html


def test_authenticated_html_requires_safe_explicit_paths_and_transport():
    for path in ("https://outside.example/private", "//outside.example/private",
                 "/logout", "/private?token=x", "/%2e%2e/admin"):
        with pytest.raises(InvalidTarget):
            parse_auth_html_paths([path])
    with pytest.raises(InvalidTarget, match="tối đa 10"):
        parse_auth_html_paths([f"/page-{index}" for index in range(11)])
    with pytest.raises(InvalidTarget, match="cần HTTPS"):
        validate_api_auth_transport("http://example.com/private", "93.184.215.14")
    with pytest.raises(InvalidTarget, match="cần Cookie"):
        scan("localhost:8000", auth_html_paths=["/private"])
