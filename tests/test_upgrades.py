"""Focused tests for policy evidence, lockfiles, cancellation and diffing."""

from __future__ import annotations

import json
import socket
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

import pytest

from conftest import FakeResponse
from websec.compare import compare_reports
from websec.control import ScanControl, ScanStopped
from websec.cookies import check_cookies
from websec.findings import CheckResult, Severity
from websec.lockfiles import check_lockfile, parse_lockfile
from websec.network import PinnedDNS, guarded_session
from websec.policies import (
    AUDIT_ORIGIN, check_cors, check_cors_credentialed,
    check_cors_preflight, check_csp,
)
from websec.scanner import ScanReport, scan
from websec.targets import InvalidTarget


def test_csp_and_cors_show_header_evidence():
    policy = "default-src 'self'; script-src 'self' 'unsafe-inline' 'nonce-secret123'; object-src 'none'"
    csp = check_csp(FakeResponse(headers={"Content-Security-Policy": policy}))
    assert any(f.check == "csp-inline" and f.severity == Severity.LOW for f in csp.findings)
    assert all("secret123" not in f.evidence for f in csp.findings)
    assert "Content-Security-Policy:" in csp.findings[0].evidence

    probe = FakeResponse(headers={
        "Access-Control-Allow-Origin": AUDIT_ORIGIN,
        "Access-Control-Allow-Credentials": "true",
    })
    cors = check_cors(FakeResponse(), probe)
    finding = next(f for f in cors.findings if f.check == "cors-reflection")
    assert finding.severity == Severity.MEDIUM
    assert "Access-Control-Allow-Origin:" in finding.evidence
    assert "allowlist" in finding.recommendation

    wildcard = check_cors(
        FakeResponse(),
        FakeResponse(headers={"Access-Control-Allow-Origin": "*"}),
    )
    wildcard_finding = next(f for f in wildcard.findings if f.check == "cors-wildcard")
    assert "Request Origin" in wildcard_finding.evidence
    assert "Access-Control-Allow-Origin: *" in wildcard_finding.evidence


def test_cors_preflight_and_test_session_findings_require_matching_browser_headers():
    def response(status: int, headers: dict[str, str]):
        return type("Response", (), {"status_code": status, "headers": headers})()

    allowed = response(204, {
        "Access-Control-Allow-Origin": AUDIT_ORIGIN,
        "Access-Control-Allow-Methods": "GET, OPTIONS",
        "Access-Control-Allow-Headers": "authorization",
        "Access-Control-Allow-Credentials": "true",
        "Vary": "Origin",
    })
    preflight = check_cors_preflight(allowed, requested_header="authorization")
    assert preflight.findings[0].check == "cors-preflight-allows"
    assert "OPTIONS HTTP 204" in preflight.findings[0].evidence
    assert "Access-Control-Allow-Headers: authorization" in preflight.findings[0].evidence

    credentialed = response(200, {
        "Access-Control-Allow-Origin": AUDIT_ORIGIN,
        "Access-Control-Allow-Credentials": "true",
        "Vary": "Origin",
    })
    cookie = check_cors_credentialed(credentialed, mode="cookie")
    assert cookie.findings[0].check == "cors-cookie-cross-origin"
    assert cookie.findings[0].severity == Severity.HIGH
    assert cookie.findings[0].verification.value == "suspected"
    assert "GET với phiên cookie HTTP 200" in cookie.findings[0].evidence

    bearer = check_cors_credentialed(credentialed, mode="bearer", preflight=allowed)
    assert bearer.findings[0].check == "cors-bearer-cross-origin"
    assert bearer.findings[0].severity == Severity.MEDIUM
    denied = response(403, credentialed.headers)
    assert check_cors_credentialed(denied, mode="cookie").findings[0].verification.value == "inconclusive"
    wildcard = response(200, {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Credentials": "true",
    })
    assert check_cors_credentialed(wildcard, mode="cookie").findings[0].check == "cors-credentialed-blocked"
    missing_acac = response(200, {"Access-Control-Allow-Origin": AUDIT_ORIGIN})
    assert check_cors_credentialed(missing_acac, mode="cookie").findings[0].check == "cors-credentialed-blocked"
    blocked_preflight = response(204, {
        "Access-Control-Allow-Origin": AUDIT_ORIGIN,
        "Access-Control-Allow-Methods": "GET",
        "Access-Control-Allow-Credentials": "true",
    })
    assert check_cors_credentialed(
        credentialed, mode="bearer", preflight=blocked_preflight,
    ).findings[0].check == "cors-credentialed-preflight-blocked"
    assert check_cors_credentialed(
        credentialed, mode="bearer",
    ).findings[0].check == "cors-credentialed-preflight-inconclusive"
    no_vary = response(204, {
        "Access-Control-Allow-Origin": AUDIT_ORIGIN,
        "Access-Control-Allow-Methods": "GET",
    })
    assert "cors-preflight-vary" in {
        finding.check for finding in check_cors_preflight(no_vary).findings
    }
    echoed_secret = response(200, {
        "Access-Control-Allow-Origin": "BEARER_SECRET",
        "Access-Control-Allow-Credentials": "BEARER_SECRET",
        "Vary": "Origin, BEARER_SECRET",
    })
    assert "BEARER_SECRET" not in repr(check_cors_credentialed(
        echoed_secret, mode="bearer", preflight=allowed,
    ))


def test_cookie_evidence_redacts_value_and_checks_prefix():
    result = check_cookies(FakeResponse(set_cookies=[
        "__Host-session=secret-token; HttpOnly; SameSite=None; Path=/; Domain=example.com"
    ]))
    assert "cookie-host-prefix" in {f.check for f in result.findings}
    assert "cookie-samesite-none" in {f.check for f in result.findings}
    assert all("secret-token" not in f.evidence for f in result.findings)
    assert all("Set-Cookie:" in f.evidence for f in result.findings)


def test_package_lock_and_pnpm_versions_are_exact(monkeypatch):
    npm = json.dumps({"lockfileVersion": 3, "packages": {
        "": {"name": "owner"},
        "node_modules/@scope/tool": {"version": "1.2.3"},
        "node_modules/foo": {"version": "2.0.1"},
        "node_modules/link": {"version": "file:../link"},
    }}).encode()
    assert parse_lockfile("package-lock.json", npm) == [
        ("@scope/tool", "1.2.3"), ("foo", "2.0.1"),
    ]
    pnpm = b"lockfileVersion: '9.0'\npackages:\n  '@scope/tool@1.2.3': {}\n  'foo@2.0.1(peer@1.0.0)': {}\n  '/legacy/3.0.0': {}\n"
    assert parse_lockfile("pnpm-lock.yaml", pnpm) == [
        ("@scope/tool", "1.2.3"), ("foo", "2.0.1"), ("legacy", "3.0.0"),
    ]
    calls = []

    class Reply:
        def raise_for_status(self):
            pass

        def json(self):
            return {"results": [{"vulns": [{"id": "GHSA-test"}]}, {"vulns": []}]}

    def post(url, json, timeout):
        calls.append(json)
        return Reply()

    monkeypatch.setattr("websec.lockfiles.requests.post", post)
    result = check_lockfile("package-lock.json", parse_lockfile("package-lock.json", npm), use_osv=True)
    assert calls[0]["queries"][0]["version"] == "1.2.3"
    assert any(f.check.endswith(":GHSA-test") for f in result.findings)


def test_lockfile_rejects_oversize_or_wrong_name():
    with pytest.raises(InvalidTarget, match="2 MB"):
        parse_lockfile("package-lock.json", b"x" * 2_000_001)
    with pytest.raises(InvalidTarget, match="Chỉ nhận"):
        parse_lockfile("package.json", b"{}")


def test_pinned_dns_preserves_host_and_rejects_rebinding(monkeypatch):
    hosts = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            hosts.append(self.headers.get("Host"))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = Thread(target=server.serve_forever, daemon=True)
    worker.start()
    original = socket.getaddrinfo
    current = ["127.0.0.1"]

    def fake_dns(host, port, *args, **kwargs):
        if host == "owned.test":
            return original(current[0], port, *args, **kwargs)
        return original(host, port, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", fake_dns)
    dns = PinnedDNS(allow_private=True)
    session = guarded_session(dns)
    try:
        url = f"http://owned.test:{server.server_port}/"
        assert session.get(url).status_code == 200
        assert hosts == [f"owned.test:{server.server_port}"]
        current[0] = "127.0.0.2"
        with pytest.raises(InvalidTarget, match="DNS.*thay đổi"):
            session.get(url)
    finally:
        session.close()
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)


def test_scan_control_and_comparison():
    control = ScanControl(max_seconds=1, started_at=time.monotonic() - 2)
    with pytest.raises(ScanStopped, match="hết thời gian"):
        control.check()
    cancelled = ScanControl(max_seconds=10)
    cancelled.cancelled.set()
    with pytest.raises(ScanStopped, match="hủy"):
        cancelled.wait(1)

    old_result = CheckResult(category="CSP")
    old_result.add("csp-missing", "Thiếu CSP", Severity.HIGH, "old")
    new_result = CheckResult(category="CSP")
    new_result.add("csp-inline", "Inline script", Severity.MEDIUM, "new")
    old = ScanReport("https://owned.test", "https://owned.test", 200, results=[old_result])
    new = ScanReport("https://owned.test", "https://owned.test", 200, results=[new_result])
    difference = compare_reports(old, new)
    assert [f["check"] for f in difference["new_issues"]] == ["csp-inline"]
    assert [f["check"] for f in difference["fixed_issues"]] == ["csp-missing"]


def test_scanner_uses_lockfile_and_policy_checks():
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Access-Control-Allow-Origin", self.headers.get("Origin", ""))
            self.send_header("Access-Control-Allow-Credentials", "true")
            self.end_headers()
            self.wfile.write(b"<html><script src='/jquery-3.4.1.js'></script></html>")

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        lockfile = ("package-lock.json", json.dumps({
            "lockfileVersion": 3,
            "packages": {"node_modules/jquery": {"version": "3.4.1"}},
        }).encode())
        report = scan(
            f"localhost:{server.server_port}", max_pages=1,
            use_osv=False, lockfile=lockfile,
        )
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)
    assert "npm Lockfile / OSV" in {r.category for r in report.results}
    categories = {r.category: r for r in report.pages[0].results}
    assert {"Content Security Policy", "CORS", "Cookie Flags"} <= categories.keys()
    assert "JavaScript Libraries" not in categories
    assert any(f.check == "cors-reflection" for f in categories["CORS"].findings)


def test_total_deadline_stops_slow_server():
    class SlowHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            time.sleep(1.5)
            try:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")
            except OSError:
                pass

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), SlowHandler)
    worker = Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        with pytest.raises(ScanStopped, match="hết thời gian"):
            scan(f"localhost:{server.server_port}", max_pages=1,
                 max_seconds=1, use_osv=False)
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)
