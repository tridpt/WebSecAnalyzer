"""Browser CORS checks use real browser policy and a pinned, header-only bridge."""

from __future__ import annotations

import importlib.util
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from types import SimpleNamespace

import pytest

import websec.browser_cors as browser_cors
import websec.scanner as scanner_module
from websec.api import parse_api_credential
from websec.browser_cors import (
    BrowserCorsVerifier, check_browser_cors, parse_cookie_attributes,
    validate_browser_options,
)
from websec.control import ScanControl
from websec.fetch import RequestPacer
from websec.network import PinnedDNS
from websec.network import DNSChanged
from websec.report import render_json, to_dict
from websec.scanner import ScanReport, scan
from websec.targets import InvalidTarget


def _has_browser() -> bool:
    if not importlib.util.find_spec("playwright") or not importlib.util.find_spec("cryptography"):
        return False
    if os.name == "nt":
        return any(Path(path).exists() for path in (
            r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
            r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        ))
    from playwright.sync_api import sync_playwright
    with sync_playwright() as playwright:
        return Path(playwright.chromium.executable_path).exists()


browser_required = pytest.mark.skipif(not _has_browser(), reason="No local Playwright browser")


def test_browser_cookie_attributes_require_an_explicit_single_cookie():
    credential = parse_api_credential("cookie", "session=SECRET")
    assert parse_cookie_attributes("SameSite=None; Secure; HttpOnly; Path=/api").evidence == (
        "SameSite=None; Secure=có; Path=/api; thuộc tính do người dùng khai báo"
    )
    for value in (
        None, "SameSite=None; Path=/", "SameSite=unknown; Path=/",
        "SameSite=Lax; Path=//evil", "SameSite=Lax; Path=/; Domain=other.test",
    ):
        with pytest.raises(InvalidTarget):
            validate_browser_options(True, credential, value)
    with pytest.raises(InvalidTarget, match="một cặp Cookie"):
        validate_browser_options(
            True, parse_api_credential("cookie", "a=1; b=2"),
            "SameSite=None; Secure; Path=/",
        )
    assert validate_browser_options(False, credential, None) is None
    with pytest.raises(InvalidTarget, match="phiên tài khoản A"):
        validate_browser_options(True, None, None)


@browser_required
def test_real_browser_cookie_samesite_and_cors_with_header_only_bridge(monkeypatch):
    secret = "session=BROWSER_COOKIE_SECRET"
    seen: list[tuple[str, str | None, str | None]] = []
    cors_allowed = True
    dns_changed = False

    def fake_target_fetch(_session, url, **kwargs):
        nonlocal cors_allowed, dns_changed
        if dns_changed:
            raise DNSChanged("changed")
        headers = kwargs["request_headers"]
        seen.append((kwargs["method"], headers.get("Cookie"), headers.get("Origin")))
        cors = {
            "Access-Control-Allow-Origin": headers["Origin"],
            "Access-Control-Allow-Credentials": "true",
        } if cors_allowed else {}
        return SimpleNamespace(
            status_code=200 if headers.get("Cookie") == secret else 401,
            headers=cors, is_redirect=False,
        )

    monkeypatch.setattr(browser_cors, "fetch", fake_target_fetch)
    control = ScanControl(max_seconds=60)
    verifier = BrowserCorsVerifier(
        dns=PinnedDNS(allow_private=False, control=control),
        pacer=RequestPacer(min_interval=0, max_requests=10), control=control,
        timeout=5, allow_private=False, site_origin=("https", "owned.test", 443),
        initial_loopback=False,
        credential=parse_api_credential("cookie", secret),
        cookie_attributes=parse_cookie_attributes("SameSite=None; Secure; Path=/api"),
    )
    try:
        verifier.start("https")
        allowed = verifier.verify("https://owned.test/api/account")
        finding, outcome = check_browser_cors(allowed)
        assert outcome == "readable"
        assert allowed.credential_sent and allowed.readable and allowed.get_status == 200
        assert finding.findings[0].check == "cors-browser-cookie-readable"

        verifier.cookie_attributes = parse_cookie_attributes("SameSite=Lax; Path=/api")
        omitted = verifier.verify("https://owned.test/api/account")
        assert check_browser_cors(omitted)[1] == "cookie_not_sent"
        assert not omitted.credential_sent and omitted.get_status == 401

        verifier.cookie_attributes = parse_cookie_attributes("SameSite=None; Secure; Path=/api")
        cors_allowed = False
        blocked = verifier.verify("https://owned.test/api/account")
        assert check_browser_cors(blocked)[1] == "blocked"
        assert blocked.credential_sent and not blocked.readable
        dns_changed = True
        with pytest.raises(DNSChanged):
            verifier.verify("https://owned.test/api/account")
    finally:
        verifier.close()
    assert seen[0][1] == secret and seen[1][1] is None and seen[2][1] == secret
    assert secret not in repr(finding)
    assert "BROWSER_COOKIE_SECRET" not in repr(allowed)


@browser_required
def test_scan_browser_bearer_only_selected_private_get_and_redacts_secret(monkeypatch):
    monkeypatch.setattr(
        scanner_module, "RequestPacer",
        lambda **kwargs: RequestPacer(min_interval=0, **kwargs),
    )
    seen: list[tuple[str, str, str | None, str | None]] = []

    class Handler(BaseHTTPRequestHandler):
        def do_OPTIONS(self):
            seen.append((self.command, self.path, self.headers.get("Authorization"), self.headers.get("Origin")))
            self.send_response(204)
            self.send_header("Access-Control-Allow-Origin", self.headers.get("Origin", ""))
            self.send_header("Access-Control-Allow-Credentials", "true")
            self.send_header("Access-Control-Allow-Methods", "GET")
            self.send_header("Access-Control-Allow-Headers", "authorization")
            self.end_headers()

        def do_GET(self):
            seen.append((self.command, self.path, self.headers.get("Authorization"), self.headers.get("Origin")))
            if self.path == "/":
                status, body, content_type = 200, b"<html>Home</html>", "text/html"
            else:
                status = 200 if self.headers.get("Authorization") == "Bearer BROWSER_TOKEN_SECRET" else 401
                body, content_type = b"BODY_SECRET_NOT_SAVED", "application/json"
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            if self.headers.get("Origin"):
                self.send_header("Access-Control-Allow-Origin", self.headers["Origin"])
                self.send_header("Access-Control-Allow-Credentials", "true")
            self.end_headers()
            try:
                self.wfile.write(body)
            except OSError:
                pass

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = Thread(target=server.serve_forever, daemon=True)
    worker.start()
    outcome: dict[str, object] = {}

    def run_scan():
        try:
            outcome["report"] = scan(
                f"localhost:{server.server_port}/", max_pages=1, use_osv=False,
                api_paths=["private /api/private", "/api/public"],
                api_credential=parse_api_credential("bearer", "BROWSER_TOKEN_SECRET"),
                browser_cors=True,
            )
        except Exception as exc:
            outcome["error"] = exc

    scan_worker = Thread(target=run_scan, daemon=True)
    try:
        scan_worker.start()
        scan_worker.join(timeout=60)
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)
    assert not scan_worker.is_alive()
    if "error" in outcome:
        raise outcome["error"]
    report = outcome["report"]
    endpoints = {item.url.rsplit("/", 1)[-1]: item for item in report.api_endpoints}
    assert endpoints["private"].api_cors_browser_outcome == "readable"
    assert endpoints["public"].api_cors_browser_outcome is None
    assert [item for item in seen if item[1] == "/api/public" and item[2]] == []
    assert any(
        method == "OPTIONS" and path == "/api/private" and authorization is None
        for method, path, authorization, _ in seen
    )
    assert to_dict(report)["coverage"]["api_cors_browser_checked"] == 1
    serialized = render_json(report)
    assert "BROWSER_TOKEN_SECRET" not in serialized
    assert "BODY_SECRET_NOT_SAVED" not in serialized
    restored = ScanReport.from_dict(json.loads(serialized))
    assert restored.api_endpoints[0].api_cors_browser_outcome == "readable"
