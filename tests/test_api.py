"""Optional API scope stays explicit, bounded, and header-only."""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from types import SimpleNamespace

import pytest
import requests

import websec.scanner as scanner_module
from websec.compare import new_high_issues
from websec.api import (
    check_api_cross_account, parse_api_credential, parse_api_targets,
    parse_comparison_fields, parse_openapi, selectable_get_routes,
    validate_api_auth_transport, validate_openapi_path,
)
from websec.network import DNSChanged
from websec.fetch import RequestPacer
from websec.policies import AUDIT_ORIGIN
from websec.api_preview import preview_openapi
from websec.report import render_json, render_text, to_dict
from websec.scanner import ScanReport, scan
from websec.targets import InvalidTarget


def test_api_target_validation_and_openapi_metadata():
    targets = parse_api_targets(["/api/health", "private /api/account", "/api/health"])
    assert [(target.path, target.expect_auth) for target in targets] == [
        ("/api/health", False), ("/api/account", True),
    ]
    for path in ["https://elsewhere.test/api", "//elsewhere.test/api", "/api/x?q=secret",
                 "/api/{id}", "/api/delete/1", "/api/%64elete/1", "/api/%2e%2e/x",
                 "/api/%0aheader"]:
        with pytest.raises(InvalidTarget):
            parse_api_targets([path])
    with pytest.raises(InvalidTarget, match="tối đa 10"):
        parse_api_targets([f"/api/{n}" for n in range(11)])
    assert validate_openapi_path("/openapi.json") == "/openapi.json"
    with pytest.raises(InvalidTarget):
        validate_openapi_path("https://elsewhere.test/openapi.json")

    routes, total, auth_paths = parse_openapi(json.dumps({
        "openapi": "3.1.0",
        "security": [{"Bearer": []}],
        "paths": {
            "/api/private": {"get": {"responses": {"200": {}}}},
            "/api/public": {"get": {"security": []}},
        },
    }).encode(), {"/api/private", "/api/public"})
    assert total == 2
    assert [(route["path"], route["auth_declared"]) for route in routes] == [
        ("/api/private", True), ("/api/public", False),
    ]
    assert auth_paths == {"/api/private"}

    paths = {f"/api/public/{n}": {"get": {}} for n in range(100)}
    paths["/api/users/{id}"] = {"get": {"security": [{"Bearer": []}]}}
    routes, total, auth_paths = parse_openapi(
        json.dumps({"openapi": "3.1.0", "paths": paths}).encode(),
        {"/api/users/42"},
    )
    assert len(routes) == 100 and total == 101
    assert auth_paths == {"/api/users/42"}
    _, _, auth_paths = parse_openapi(json.dumps({
        "openapi": "3.1.0", "security": [{"Bearer": []}],
        "paths": {
            "/api/{id}": {"get": {}},
            "/api/health": {"get": {"security": []}},
        },
    }).encode(), {"/api/health"})
    assert auth_paths == set()
    optional_security = json.dumps({
        "openapi": "3.1.0", "paths": {
            "/api/optional": {"get": {"security": [{"Bearer": []}, {}]}},
        },
    }).encode()
    routes, _, auth_paths = parse_openapi(optional_security, {"/api/optional"})
    assert routes[0]["auth_declared"] is False and auth_paths == set()
    assert selectable_get_routes(optional_security)[0][0]["auth_declared"] is False
    with pytest.raises(InvalidTarget, match="OpenAPI"):
        parse_openapi(b'{"paths": {}}')


def test_openapi_picker_only_offers_safe_get_routes():
    spec = json.dumps({
        "openapi": "3.1.0", "security": [{"Bearer": []}],
        "paths": {
            "/api/users/{id}": {"get": {}},
            "/api/public": {"get": {"security": []}},
            "/api/delete": {"get": {}},
            "/api/search": {"get": {"parameters": [
                {"name": "q", "in": "query", "required": True},
            ]}},
            "/api/write": {"post": {}},
        },
    }).encode()
    routes, total_get, eligible_get = selectable_get_routes(spec)
    assert total_get == 4 and eligible_get == 2
    assert routes == [
        {"method": "GET", "path": "/api/users/{id}",
         "auth_declared": True, "parameters": ["id"]},
        {"method": "GET", "path": "/api/public",
         "auth_declared": False, "parameters": []},
    ]
    many = json.dumps({
        "openapi": "3.1.0",
        "paths": {f"/api/{n}": {"get": {}} for n in range(105)},
    }).encode()
    routes, total_get, eligible_get = selectable_get_routes(many)
    assert len(routes) == 100 and total_get == eligible_get == 105


def test_openapi_preview_only_reads_site_and_spec_on_same_origin():
    seen: list[tuple[str, str | None, str | None]] = []
    spec = json.dumps({
        "openapi": "3.1.0", "paths": {
            "/api/users/{id}": {"get": {"security": [{"Bearer": []}]}},
            "/api/write": {"post": {}},
        },
    }).encode()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append((self.path, self.headers.get("Cookie"),
                         self.headers.get("Authorization")))
            if self.path == "/redirect.json":
                self.send_response(302)
                self.send_header("Location", "http://127.0.0.1:1/escape")
                self.end_headers()
                return
            body = spec if self.path == "/openapi.json" else b"<html>Home</html>"
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        result = preview_openapi(f"localhost:{server.server_port}/", "/openapi.json")
        with pytest.raises(InvalidTarget):
            preview_openapi(f"localhost:{server.server_port}/", "/redirect.json")
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)
    assert result["total_get"] == 1
    assert result["routes"][0]["path"] == "/api/users/{id}"
    assert [path for path, _, _ in seen] == [
        "/", "/openapi.json", "/", "/redirect.json",
    ]
    assert all(cookie is None and auth is None for _, cookie, auth in seen)


def test_test_account_credential_validation_never_echoes_secret():
    cookie = parse_api_credential("cookie", "session=very-secret")
    assert cookie.headers()["Cookie"] == "session=very-secret"
    assert "very-secret" not in repr(cookie)
    bearer = parse_api_credential("bearer", "Bearer abc.def")
    assert bearer.headers()["Authorization"] == "Bearer abc.def"
    for mode, secret in [
        ("cookie", "session=x\r\nHost: evil.test"),
        ("bearer", "a b"),
        ("cookie", "Cookie: session=x"),
        ("none", "session=x"),
    ]:
        with pytest.raises(InvalidTarget) as error:
            parse_api_credential(mode, secret)
        assert secret not in str(error.value)


def test_test_account_requires_https_except_actual_loopback():
    validate_api_auth_transport("https://owned.test/", "203.0.113.1")
    validate_api_auth_transport("http://localhost:8000/", "127.0.0.1")
    for url, ip in [
        ("http://owned.test/", "203.0.113.1"),
        ("http://localhost:8000/", "203.0.113.1"),
    ]:
        with pytest.raises(InvalidTarget, match="HTTPS"):
            validate_api_auth_transport(url, ip)


def test_comparison_fields_require_explicit_private_endpoint_and_safe_pointer():
    targets = parse_api_targets(["private /api/account", "/api/public"])
    assert parse_comparison_fields([
        "/api/account /user/id", "/api/account /user/id",
        "/api/account /data/a~1b",
    ], targets) == {"/api/account": ["/user/id", "/data/a~1b"]}
    for line in [
        "/api/public /user/id", "/api/unknown /user/id",
        "/api/account user/id", "/api/account /user/~2bad",
        "/api/account /user//id", "/api/account /user/id extra",
    ]:
        with pytest.raises(InvalidTarget):
            parse_comparison_fields([line], targets)
    with pytest.raises(InvalidTarget, match="tối đa 20"):
        parse_comparison_fields(
            [f"/api/account /field/{index}" for index in range(21)], targets
        )


def test_cross_account_json_comparison_never_includes_values():
    target = parse_api_targets(["private /api/account"])[0]
    a = SimpleNamespace(
        status_code=200, headers={"Content-Type": "application/json"},
        content=b'{"user":{"id":"PRIVATE_VALUE","name":"Alice"}}',
    )
    b = SimpleNamespace(
        status_code=200, headers={"Content-Type": "application/json"},
        content=b'{"user":{"id":"PRIVATE_VALUE","name":"Bob"}}',
    )
    result, checked = check_api_cross_account(
        a, b, target, ["/user/id", "/user/name", "/user/missing"]
    )
    assert checked == ["/user/id", "/user/name"]
    assert [finding.check for finding in result.findings] == [
        "api-cross-account-equal", "api-cross-account-distinct",
        "api-cross-account-inconclusive",
    ]
    assert result.findings[0].severity.name == "HIGH"
    assert "PRIVATE_VALUE" not in repr(result)
    assert "Alice" not in repr(result) and "Bob" not in repr(result)

    both = SimpleNamespace(
        status_code=200, headers={"Content-Type": "application/json"},
        content=b'{"user":{"id":"SAME_PRIVATE_VALUE","alias":"SAME_PRIVATE_VALUE"}}',
    )
    equal_result, _ = check_api_cross_account(
        both, both, target, ["/user/id", "/user/alias"]
    )
    old = ScanReport("https://owned.test/", "https://owned.test/", 200)
    new = ScanReport("https://owned.test/", "https://owned.test/", 200)
    new.api_endpoints = [ScanReport(
        "https://owned.test/api/account", "https://owned.test/api/account", 200,
        results=[equal_result],
    )]
    issues = new_high_issues(old, new)
    assert len(issues) == 2
    assert len({issue["fingerprint"] for issue in issues}) == 2


def test_two_accounts_only_read_selected_private_json_and_never_save_body():
    seen: list[tuple[str, str | None]] = []
    first_cookie = "session=FIRST_SECRET"
    second_cookie = "session=SECOND_SECRET"

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            cookie = self.headers.get("Cookie")
            seen.append((self.path, cookie))
            if self.path == "/api/account":
                status = 200 if cookie in {first_cookie, second_cookie} else 401
                user_id = "FIRST_PRIVATE_ID" if cookie == first_cookie else "SECOND_PRIVATE_ID"
                body = json.dumps({"user": {"id": user_id}, "secret": "BODY_NEVER_SAVE"}).encode()
                content_type = "application/json"
            elif self.path == "/api/public":
                status, body, content_type = 200, b'{"public":true}', "application/json"
            else:
                status, body, content_type = 200, b"<html>Home</html>", "text/html"
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Set-Cookie", "response=COOKIE_NEVER_SAVE; Path=/")
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
    try:
        report = scan(
            f"localhost:{server.server_port}/", use_osv=False, max_pages=1,
            api_paths=["private /api/account", "/api/public"],
            api_credential=parse_api_credential("cookie", first_cookie),
            api_second_credential=parse_api_credential("cookie", second_cookie),
            api_compare_fields=["/api/account /user/id"],
        )
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)

    endpoints = {item.url.rsplit("/", 1)[-1]: item for item in report.api_endpoints}
    account = endpoints["account"]
    assert account.status_code == 401
    assert account.api_auth_status_code == 200
    assert account.api_second_auth_status_code == 200
    assert account.api_compared_pointers == ["/user/id"]
    assert endpoints["public"].api_second_auth_status_code is None
    assert [path for path, cookie in seen if cookie == first_cookie] == [
        "/api/account", "/api/account",
    ]
    assert [path for path, cookie in seen if cookie == second_cookie] == ["/api/account"]
    assert all(cookie is None for path, cookie in seen if path == "/api/public")
    assert any(
        finding.check == "api-cross-account-distinct"
        for result in account.results for finding in result.findings
    )
    serialized = render_json(report)
    for private in (
        "FIRST_SECRET", "SECOND_SECRET", "FIRST_PRIVATE_ID", "SECOND_PRIVATE_ID",
        "BODY_NEVER_SAVE", "COOKIE_NEVER_SAVE",
    ):
        assert private not in serialized
    assert to_dict(report)["coverage"]["api_cross_account_checked"] == 1
    restored = ScanReport.from_dict(json.loads(serialized))
    assert restored.api_endpoints[0].api_compared_pointers == ["/user/id"]


def test_test_account_probes_only_private_gets_and_never_saves_secret():
    seen: list[tuple[str, str | None, str | None, str | None]] = []
    secret = "test_session=TOP_SECRET_TOKEN"
    body_secret = "PRIVATE_BODY_NEVER_PERSIST"

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append((
                self.path, self.headers.get("Cookie"),
                self.headers.get("Authorization"), self.headers.get("Origin"),
            ))
            if self.path == "/openapi.json":
                body = json.dumps({"openapi": "3.1.0", "paths": {
                    "/api/declared": {"get": {"security": [{"Bearer": []}]}},
                }}).encode()
                status, content_type = 200, "application/json"
            elif self.path in {"/api/private", "/api/declared"}:
                body = body_secret.encode()
                status, content_type = (200 if self.headers.get("Cookie") == secret else 401), "application/json"
            elif self.path == "/api/public":
                body = b'{"public": true}'
                status, content_type = 200, "application/json"
            elif self.path == "/api/redirect":
                self.send_response(302)
                self.send_header("Location", "http://127.0.0.1:1/escape")
                self.end_headers()
                return
            else:
                body = b"<html>Home</html>"
                status, content_type = 200, "text/html"
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Set-Cookie", "response_secret=NEVER_PERSIST; Path=/")
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
    try:
        report = scan(
            f"localhost:{server.server_port}/", use_osv=False, max_pages=1,
            openapi_path="/openapi.json",
            api_paths=[
                "private /api/private", "/api/declared", "/api/public",
                "private /api/redirect",
            ],
            api_credential=parse_api_credential("cookie", secret),
        )
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)

    assert report.api_auth_mode == "cookie"
    assert report.api_auth_requested == 3
    assert report.api_auth_skipped_paths == []
    endpoints = {item.url.rsplit("/", 1)[-1]: item for item in report.api_endpoints}
    assert endpoints["private"].status_code == 401
    assert endpoints["private"].api_auth_status_code == 200
    assert endpoints["declared"].api_auth_status_code == 200
    assert endpoints["public"].api_auth_status_code is None
    assert endpoints["redirect"].api_auth_status_code == 302
    assert all(path != "/escape" for path, *_ in seen)
    assert [path for path, cookie, _, _ in seen if cookie == secret] == [
        "/api/private", "/api/private", "/api/declared", "/api/declared",
        "/api/redirect", "/api/redirect",
    ]
    assert all(
        authorization is None for _, _, authorization, _ in seen
    )
    assert all(
        cookie is None for path, cookie, _, _ in seen
        if path.startswith("/api/") and path != "/api/private"
        and path != "/api/declared" and path != "/api/redirect"
    )
    assert any(
        finding.check == "api-auth-boundary"
        for result in endpoints["private"].results for finding in result.findings
    )
    serialized = render_json(report)
    assert "TOP_SECRET_TOKEN" not in serialized
    assert body_secret not in serialized
    assert "NEVER_PERSIST" not in serialized
    assert to_dict(report)["coverage"]["api_authenticated_checked"] == 3
    assert ScanReport.from_dict(json.loads(serialized)).api_endpoints[0].api_auth_status_code == 200


@pytest.mark.parametrize("mode", ["cookie", "bearer"])
def test_api_cors_preflight_and_private_session_stay_in_selected_scope(mode, monkeypatch):
    monkeypatch.setattr(
        scanner_module, "RequestPacer",
        lambda **kwargs: RequestPacer(min_interval=0, **kwargs),
    )
    secret = "test_session=COOKIE_SECRET" if mode == "cookie" else "BEARER_SECRET"
    seen: list[dict[str, str | None]] = []

    class Handler(BaseHTTPRequestHandler):
        def record(self):
            seen.append({
                "method": self.command, "path": self.path,
                "origin": self.headers.get("Origin"),
                "cookie": self.headers.get("Cookie"),
                "authorization": self.headers.get("Authorization"),
                "request_method": self.headers.get("Access-Control-Request-Method"),
                "request_headers": self.headers.get("Access-Control-Request-Headers"),
            })

        def do_OPTIONS(self):
            self.record()
            self.send_response(204)
            self.send_header("Access-Control-Allow-Origin", AUDIT_ORIGIN)
            self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "authorization")
            self.send_header("Access-Control-Allow-Credentials", "true")
            self.send_header("Vary", "Origin")
            self.end_headers()

        def do_GET(self):
            self.record()
            if self.path == "/api/redirect":
                self.send_response(302)
                self.send_header("Location", "http://127.0.0.1:1/escape")
                self.end_headers()
                return
            has_session = (
                self.headers.get("Cookie") == secret if mode == "cookie"
                else self.headers.get("Authorization") == f"Bearer {secret}"
            )
            status = 200 if self.path != "/api/private" or has_session else 401
            body = b"BODY_NEVER_SAVE" if self.path.startswith("/api/") else b"<html>Home</html>"
            self.send_response(status)
            self.send_header("Content-Type", "application/json" if self.path.startswith("/api/") else "text/html")
            self.send_header("Set-Cookie", "response=SERVER_COOKIE_SECRET; Path=/")
            if self.headers.get("Origin"):
                self.send_header("Access-Control-Allow-Origin", AUDIT_ORIGIN)
                self.send_header("Access-Control-Allow-Credentials", "true")
                if has_session:
                    self.send_header("Vary", f"Origin, {secret}")
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
    try:
        report = scan(
            f"localhost:{server.server_port}/", use_osv=False, max_pages=1,
            api_paths=["private /api/private", "/api/public", "private /api/redirect"],
            api_credential=parse_api_credential(mode, secret),
        )
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)

    options = [item for item in seen if item["method"] == "OPTIONS"]
    assert {item["path"] for item in options} == {
        "/api/private", "/api/public", "/api/redirect",
    }
    assert all(item["origin"] == AUDIT_ORIGIN and item["request_method"] == "GET" for item in options)
    assert all(item["cookie"] is None and item["authorization"] is None for item in options)
    assert all(
        item["request_headers"] == (
            "authorization" if mode == "bearer" and item["path"] != "/api/public" else None
        ) for item in options
    )
    credentialed = [
        item for item in seen if item["cookie"] == secret
        or item["authorization"] == f"Bearer {secret}"
    ]
    assert len(credentialed) == 4
    assert {item["path"] for item in credentialed} == {"/api/private", "/api/redirect"}
    assert sum(item["origin"] == AUDIT_ORIGIN for item in credentialed) == 2
    assert not any(item["path"] == "/escape" for item in seen)
    endpoints = {item.url.rsplit("/", 1)[-1]: item for item in report.api_endpoints}
    private = endpoints["private"]
    assert private.api_cors_preflight_status_code == 204
    assert private.api_cors_credentialed_status_code == 200
    assert endpoints["public"].api_cors_credentialed_status_code is None
    assert endpoints["redirect"].api_cors_credentialed_status_code == 302
    checks = {
        finding.check for result in private.results for finding in result.findings
    }
    assert ("cors-cookie-cross-origin" if mode == "cookie" else "cors-bearer-cross-origin") in checks
    serialized = render_json(report)
    assert secret not in serialized
    assert "BODY_NEVER_SAVE" not in serialized
    assert "SERVER_COOKIE_SECRET" not in serialized
    coverage = to_dict(report)["coverage"]
    assert coverage["api_cors_preflight_checked"] == 3
    assert coverage["api_cors_credentialed_checked"] == 2
    restored = ScanReport.from_dict(json.loads(serialized))
    assert restored.api_endpoints[0].api_cors_preflight_status_code == 204
    assert restored.api_endpoints[0].api_cors_credentialed_status_code == 200


def test_request_budget_covers_ten_private_api_cors_probes(monkeypatch):
    monkeypatch.setattr(
        scanner_module, "RequestPacer",
        lambda **kwargs: RequestPacer(min_interval=0, **kwargs),
    )

    class Handler(BaseHTTPRequestHandler):
        def do_OPTIONS(self):
            self.send_response(204)
            self.end_headers()

        def do_GET(self):
            self.send_response(200 if self.path == "/" or self.headers.get("Cookie") else 401)
            self.send_header("Content-Type", "text/html" if self.path == "/" else "application/json")
            self.end_headers()
            try:
                self.wfile.write(b"<html></html>" if self.path == "/" else b"{}")
            except OSError:
                pass

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        report = scan(
            f"localhost:{server.server_port}/", use_osv=False, max_pages=1,
            api_paths=[f"private /api/item/{index}" for index in range(10)],
            api_credential=parse_api_credential("cookie", "session=TEST"),
        )
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)
    assert len(report.api_endpoints) == 10
    assert report.api_skipped_paths == []
    assert all(endpoint.api_auth_status_code == 200 for endpoint in report.api_endpoints)
    assert all(endpoint.api_cors_preflight_status_code == 204 for endpoint in report.api_endpoints)
    assert all(endpoint.api_cors_credentialed_status_code == 200 for endpoint in report.api_endpoints)


def test_scan_discovers_api_but_only_probes_selected_path(monkeypatch):
    seen: list[tuple[str, str | None, str | None]] = []
    secret = "MAIL_CONTENT_MUST_NOT_BE_STORED"

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append((self.path, self.headers.get("Origin"), self.headers.get("Cookie")))
            if self.path == "/":
                body = b"<html>Site</html>"
                content_type = "text/html"
            elif self.path == "/openapi.json":
                body = json.dumps({"openapi": "3.1.0", "paths": {
                    "/api/private": {"get": {"security": [{"Bearer": []}]}},
                    "/api/other": {"get": {}},
                }}).encode()
                content_type = "application/json"
            elif self.path == "/api/private":
                body = secret.encode()
                content_type = "application/json"
            else:
                self.send_response(404)
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Set-Cookie", "sid=secret-cookie; Path=/")
            if self.headers.get("Origin"):
                self.send_header("Access-Control-Allow-Origin", "*")
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
    try:
        report = scan(
            f"localhost:{server.server_port}/", use_osv=False, max_pages=1,
            openapi_path="/openapi.json", api_paths=["/api/private"],
        )
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)

    assert report.openapi_status == "loaded"
    assert report.api_discovered == 2
    assert report.api_requested == 1
    assert report.api_selected_paths == ["/api/private"]
    assert len(report.api_endpoints) == 1
    assert report.api_endpoints[0].api_expect_auth is True
    assert "/api/other" not in [path for path, _, _ in seen]
    assert [path for path, _, _ in seen].count("/api/private") == 2
    assert all(cookie is None for path, _, cookie in seen if path == "/api/private")
    results = {result.category: result for result in report.api_endpoints[0].results}
    assert any(f.check == "api-auth-missing" for f in results["API Access"].findings)
    assert any(f.check == "cors-wildcard" for f in results["CORS"].findings)
    serialized = render_json(report)
    assert secret not in serialized and "secret-cookie" not in serialized
    assert to_dict(report)["coverage"]["api_endpoints_checked"] == 1
    assert to_dict(report)["coverage"]["api_selected_paths"] == ["/api/private"]
    restored = ScanReport.from_dict(json.loads(serialized))
    assert len(restored.api_endpoints) == 1
    assert restored.api_endpoints[0].api_expect_auth is True
    assert restored.api_discovered == 2
    assert restored.overall_score == report.overall_score
    legacy_data = json.loads(serialized)
    del legacy_data["api_endpoints"][0]["api_expect_auth"]
    assert ScanReport.from_dict(legacy_data).api_endpoints[0].api_expect_auth is True


def test_selected_api_redirect_is_not_followed():
    seen = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append(self.path)
            if self.path == "/api/redirect":
                self.send_response(302)
                self.send_header("Location", "http://127.0.0.1:1/private")
                self.end_headers()
            else:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"<html></html>")

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        report = scan(
            f"localhost:{server.server_port}/", use_osv=False, max_pages=1,
            api_paths=["/api/redirect"],
        )
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)
    assert len(report.api_endpoints) == 1
    assert report.api_endpoints[0].status_code == 302
    assert seen == ["/", "/", "/api/redirect", "/api/redirect"]


def test_invalid_openapi_and_failed_selected_path_are_visible(monkeypatch):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            body = b'{"paths": {}}' if self.path == "/openapi.json" else b"<html></html>"
            self.send_response(200)
            self.send_header("Content-Type", "application/json" if self.path == "/openapi.json" else "text/html")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = Thread(target=server.serve_forever, daemon=True)
    worker.start()
    real_fetch = scanner_module.fetch

    def fail_selected(*args, **kwargs):
        if args[1].endswith("/api/fail"):
            raise requests.ConnectionError("closed")
        return real_fetch(*args, **kwargs)

    monkeypatch.setattr(scanner_module, "fetch", fail_selected)
    try:
        report = scan(
            f"localhost:{server.server_port}/", use_osv=False, max_pages=1,
            openapi_path="/openapi.json", api_paths=["/api/fail"],
        )
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)
    assert report.openapi_status == "invalid"
    assert report.api_requested == 1 and report.api_skipped == 1
    assert report.api_skipped_paths == ["/api/fail"]
    assert to_dict(report)["coverage"]["api_endpoints_skipped_paths"] == ["/api/fail"]


def test_dns_change_during_api_probe_stops_scan(monkeypatch):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html></html>")

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = Thread(target=server.serve_forever, daemon=True)
    worker.start()
    real_fetch = scanner_module.fetch

    def changed(*args, **kwargs):
        if args[1].endswith("/api/health"):
            raise DNSChanged("changed")
        return real_fetch(*args, **kwargs)

    monkeypatch.setattr(scanner_module, "fetch", changed)
    try:
        with pytest.raises(DNSChanged):
            scan(
                f"localhost:{server.server_port}/", use_osv=False, max_pages=1,
                api_paths=["/api/health"],
            )
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)


def test_legacy_report_without_api_fields_still_renders():
    old = ScanReport.from_dict({
        "url": "https://owned.test/", "final_url": "https://owned.test/",
        "status_code": 200, "categories": [],
        "pages": [{
            "url": "https://owned.test/", "final_url": "https://owned.test/",
            "status_code": 200, "categories": [],
        }],
    })
    assert old.openapi_status == "not_requested"
    assert old.api_endpoints == [] and old.api_skipped_paths == []
    assert "API access control was not tested" in render_text(old, use_color=False)
    assert to_dict(old)["coverage"]["api_endpoints_checked"] == 0
