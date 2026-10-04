"""Optional browser discovery stays within the normal crawl and network limits."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from types import SimpleNamespace

import pytest

from websec.fetch import RequestPacer
from websec.control import ScanControl
from websec.js_discovery import BrowserDiscoveryUnavailable, JsLinkDiscoverer, safe_script_url
from websec.network import DNSChanged, PinnedDNS
from websec.report import to_dict
from websec.scanner import ScanReport, scan
from websec.scope import missing_baseline_scope


def test_only_static_same_origin_scripts_are_allowed():
    site = ("https", "example.com", 443)
    assert safe_script_url("https://example.com/assets/app.js?v=1", site)
    assert safe_script_url("https://example.com/assets/route.mjs", site)
    assert not safe_script_url("https://elsewhere.example/app.js", site)
    assert not safe_script_url("https://example.com/api/account", site)
    assert not safe_script_url("https://example.com/logout/app.js", site)
    assert not safe_script_url("https://example.com/logout.js", site)
    assert not safe_script_url("https://example.com/app.js?action=delete", site)
    assert not safe_script_url("https://user:pass@example.com/app.js", site)


def test_script_fetch_dns_change_is_kept_as_fatal(monkeypatch):
    control = ScanControl(30)
    discoverer = JsLinkDiscoverer(
        dns=PinnedDNS(allow_private=False, control=control),
        pacer=RequestPacer(min_interval=0), control=control, timeout=2,
        allow_private=False, site_origin=("https", "example.com", 443),
        user_agent="test",
    )
    document = SimpleNamespace(url="https://example.com/", headers={}, content=b"")
    discoverer.document = document
    request = SimpleNamespace(
        method="GET", resource_type="script", url="https://example.com/app.js",
    )
    aborted = []
    route = SimpleNamespace(request=request, abort=lambda: aborted.append(True))

    def changed(*_args, **_kwargs):
        raise DNSChanged("changed")

    monkeypatch.setattr("websec.js_discovery.fetch", changed)
    try:
        discoverer._route(route)
        assert aborted == [True]
        assert isinstance(discoverer.fatal, DNSChanged)
    finally:
        discoverer.close()


def test_real_browser_discovers_spa_link_without_calling_page_api(monkeypatch):
    pytest.importorskip("playwright.sync_api")
    seen: list[str] = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append(self.path)
            if self.path == "/":
                body = b'<html><body><script src="/app.js"></script></body></html>'
                content_type = "text/html"
            elif self.path == "/app.js":
                body = (
                    'document.body.insertAdjacentHTML("beforeend", '
                    '"<a href=\'/spa-only\'>SPA</a><a href=\'/logout\'>Unsafe</a>");'
                    'fetch("/api/private").catch(() => {});'
                    'navigator.sendBeacon("/write", "x");'
                    f'new WebSocket("ws://localhost:{self.server.server_port}/socket");'
                ).encode()
                content_type = "text/javascript"
            elif self.path == "/spa-only":
                body = b"<html><body>SPA route</body></html>"
                content_type = "text/html"
            else:
                self.send_response(404)
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            seen.append(self.path)
            self.send_response(204)
            self.end_headers()

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
        url = f"localhost:{server.server_port}"
        basic = scan(url, use_osv=False, max_pages=3, max_seconds=30)
        rendered = scan(
            url, use_osv=False, max_pages=3, max_seconds=30, js_discovery=True,
        )
        limited = scan(
            url, use_osv=False, max_pages=1, max_seconds=30, js_discovery=True,
        )
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)

    if rendered.js_discovery_status == "unavailable":
        pytest.skip("Edge, Chrome or Chromium is not installed on this runner")
    assert rendered.js_discovery_status == "completed"
    assert len(basic.pages) == 1
    assert [page.final_url.rsplit("/", 1)[-1] for page in rendered.pages] == [
        "", "spa-only",
    ]
    assert rendered.js_discovered_urls == 1
    assert "/api/private" not in seen
    assert "/logout" not in seen
    assert "/write" not in seen
    assert "/socket" not in seen
    assert seen.count("/app.js") == 2
    assert len(limited.pages) == 1
    assert limited.skipped_urls >= 1
    assert to_dict(rendered)["coverage"]["js_discovery_status"] == "completed"
    assert ScanReport.from_dict(to_dict(rendered)).js_discovered_urls == 1


def test_unavailable_browser_keeps_static_crawl_and_ci_locks_completed_probe(monkeypatch):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            body = b"<html><body>static</body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = Thread(target=server.serve_forever, daemon=True)
    worker.start()

    def unavailable(_self):
        raise BrowserDiscoveryUnavailable("No browser")

    monkeypatch.setattr(JsLinkDiscoverer, "start", unavailable)
    monkeypatch.setattr(
        "websec.scanner.RequestPacer",
        lambda **kwargs: RequestPacer(min_interval=0, **kwargs),
    )
    try:
        report = scan(
            f"localhost:{server.server_port}", use_osv=False,
            max_pages=1, js_discovery=True,
        )
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)
    assert report.js_discovery_status == "unavailable"
    assert len(report.pages) == 1
    old = ScanReport.from_dict(to_dict(report))
    old.js_discovery_status = "completed"
    assert any(item["surface"] == "js_discovery"
               for item in missing_baseline_scope(old, report))
