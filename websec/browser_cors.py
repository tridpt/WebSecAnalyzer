"""Opt-in, bounded browser CORS check through an isolated loopback bridge.

The browser talks only to two short-lived local servers. The bridge forwards
header-only GET/OPTIONS to one owner-selected API through the scanner's pinned
session. Browser cookie selection and CORS enforcement run on a real browser
network response; no target body or session value enters a report.
"""

from __future__ import annotations

import ipaddress
import os
import re
import ssl
import tempfile
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

import requests

from .api import ApiCredential
from .control import ScanControl, ScanStopped
from .fetch import RequestPacer, fetch
from .findings import CheckResult, Severity, Verification
from .network import DNSChanged, PinnedDNS, guarded_session
from .targets import InvalidTarget

_COOKIE_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_CORS_HEADERS = {
    "Access-Control-Allow-Origin", "Access-Control-Allow-Credentials",
    "Access-Control-Allow-Methods", "Access-Control-Allow-Headers",
    "Access-Control-Expose-Headers", "Access-Control-Allow-Private-Network",
    "Vary",
}
_FETCH_SCRIPT = """async ({url, authorization, maxMs}) => {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), maxMs);
  try {
    const options = {
      method: 'GET', mode: 'cors', credentials: 'include',
      redirect: 'error', signal: controller.signal
    };
    if (authorization) options.headers = {Authorization: authorization};
    const response = await fetch(url, options);
    return {readable: true, status: response.status};
  } catch (error) {
    return {readable: false, error: error.name};
  } finally {
    clearTimeout(timer);
  }
}"""


class BrowserUnavailable(Exception):
    """An optional local browser or its bridge could not start."""


@dataclass(frozen=True)
class CookieAttributes:
    same_site: str
    secure: bool
    path: str
    http_only: bool = False

    @property
    def evidence(self) -> str:
        return (
            f"SameSite={self.same_site}; Secure={'có' if self.secure else 'không'}; "
            f"Path={self.path}; thuộc tính do người dùng khai báo"
        )


def parse_cookie_attributes(raw: str | None) -> CookieAttributes:
    """Require explicit cookie attributes before modeling browser behavior."""
    parts = [part.strip() for part in (raw or "").split(";") if part.strip()]
    if not parts or len(raw or "") > 500:
        raise InvalidTarget(
            "Xác minh CORS bằng Cookie cần thuộc tính, ví dụ SameSite=None; Secure; Path=/."
        )
    attributes: dict[str, str | bool] = {}
    for part in parts:
        name, separator, value = part.partition("=")
        key = name.strip().lower()
        if key not in {"samesite", "secure", "path", "httponly"} or key in attributes:
            raise InvalidTarget("Chỉ nhập SameSite, Secure, HttpOnly và Path của Cookie.")
        if key in {"secure", "httponly"}:
            if separator:
                raise InvalidTarget("Secure và HttpOnly là cờ, không có giá trị.")
            attributes[key] = True
        elif not separator:
            raise InvalidTarget("SameSite và Path cần có giá trị.")
        else:
            attributes[key] = value.strip()
    same_site = str(attributes.get("samesite", "")).capitalize()
    path = str(attributes.get("path", ""))
    if same_site not in {"None", "Lax", "Strict"}:
        raise InvalidTarget("SameSite phải là None, Lax hoặc Strict.")
    if (
        not path.startswith("/") or path.startswith("//")
        or len(path) > 200 or any(
            char in "?#\\" or not 33 <= ord(char) <= 126 for char in path
        )
    ):
        raise InvalidTarget("Path của Cookie phải là đường dẫn bắt đầu bằng /.")
    secure = bool(attributes.get("secure"))
    if same_site == "None" and not secure:
        raise InvalidTarget("Cookie SameSite=None cần cờ Secure để trình duyệt chấp nhận.")
    return CookieAttributes(same_site, secure, path, bool(attributes.get("httponly")))


def _single_cookie(raw: str) -> tuple[str, str]:
    if ";" in raw:
        raise InvalidTarget(
            "Xác minh CORS trong trình duyệt hiện chỉ hỗ trợ một cặp Cookie name=value."
        )
    name, separator, value = raw.partition("=")
    if not separator or not _COOKIE_NAME.fullmatch(name.strip()) or not value:
        raise InvalidTarget("Cookie thử nghiệm cho trình duyệt phải có dạng name=value.")
    return name.strip(), value.strip()


def validate_browser_options(
    enabled: bool, credential: ApiCredential | None, attributes: str | None,
) -> CookieAttributes | None:
    if not enabled:
        if attributes and attributes.strip():
            raise InvalidTarget("Hãy bật xác minh CORS bằng trình duyệt để dùng thuộc tính Cookie.")
        return None
    if credential is None:
        raise InvalidTarget("Xác minh CORS bằng trình duyệt cần phiên tài khoản A.")
    if credential.mode == "cookie":
        _single_cookie(credential.secret)
        return parse_cookie_attributes(attributes)
    if attributes and attributes.strip():
        raise InvalidTarget("Thuộc tính Cookie chỉ dùng khi phiên A là Cookie.")
    return None


@dataclass
class BrowserObservation:
    origin: str
    mode: str
    cookie_attributes: CookieAttributes | None
    get_status: int | None = None
    preflight_status: int | None = None
    preflight_allowed: bool | None = None
    credential_sent: bool = False
    readable: bool = False
    redirect: bool = False
    error: str | None = None


def check_browser_cors(observed: BrowserObservation) -> tuple[CheckResult, str]:
    """Report browser behavior without including a body or a credential value."""
    result = CheckResult(category="API CORS Browser")
    if observed.error:
        result.error = observed.error
        return result, "inconclusive"
    evidence = "; ".join([
        f"Origin trình duyệt: {observed.origin}",
        f"GET HTTP {observed.get_status if observed.get_status is not None else '[không gửi]'}",
        f"OPTIONS HTTP {observed.preflight_status if observed.preflight_status is not None else '[không gửi]'}",
        f"{'Cookie' if observed.mode == 'cookie' else 'Authorization'} được gửi: "
        f"{'có' if observed.credential_sent else 'không'}",
        f"JavaScript đọc được mã HTTP: {'có' if observed.readable else 'không'}",
        observed.cookie_attributes.evidence if observed.cookie_attributes else "Phiên Bearer thử nghiệm",
    ])
    if observed.redirect or (
        observed.get_status is None
        and (
            observed.preflight_status is None
            or observed.preflight_status >= 500
            or observed.preflight_allowed is True
        )
    ):
        result.add(
            "cors-browser-inconclusive", "Trình duyệt chưa kiểm tra xong CORS",
            Severity.INFO, "Yêu cầu chuyển hướng hoặc không nhận được phản hồi từ API đã chọn.",
            evidence=evidence, verification=Verification.INCONCLUSIVE,
        )
        return result, "inconclusive"
    if observed.mode == "cookie" and observed.get_status is not None and not observed.credential_sent:
        result.add(
            "cors-browser-cookie-omitted", "Trình duyệt không gửi Cookie qua Origin thử nghiệm",
            Severity.INFO,
            "Trình duyệt bỏ Cookie trong phép thử với thuộc tính đã khai báo; "
            "hãy đối chiếu thuộc tính với Cookie thật của website.",
            evidence=evidence, verification=Verification.OBSERVED,
        )
        return result, "cookie_not_sent"
    if observed.get_status in {401, 403} and observed.credential_sent:
        result.add(
            "cors-browser-auth-denied", "Phiên thử nghiệm bị API từ chối",
            Severity.INFO, "Chưa đánh giá được phản hồi riêng khi API trả 401/403.",
            evidence=evidence, verification=Verification.INCONCLUSIVE,
        )
        return result, "inconclusive"
    if observed.readable and observed.credential_sent and observed.get_status is not None and 200 <= observed.get_status < 300:
        if observed.mode == "cookie":
            result.add(
                "cors-browser-cookie-readable",
                "Trình duyệt gửi Cookie và JavaScript đọc được phản hồi",
                Severity.HIGH,
                "JavaScript từ Origin thử nghiệm đọc được mã HTTP 2xx của GET có Cookie. "
                "Công cụ không đọc body nên chưa xác nhận nội dung riêng bị lộ.",
                "Giới hạn Origin chính xác, bỏ credentials cho Origin không tin cậy "
                "và kiểm tra thuộc tính Cookie thật.",
                evidence, verification=Verification.OBSERVED,
            )
        else:
            result.add(
                "cors-browser-bearer-readable",
                "JavaScript đọc được GET mang Bearer từ Origin thử nghiệm",
                Severity.MEDIUM,
                "Trình duyệt cho phép đọc mã HTTP 2xx khi Origin thử nghiệm đã có token. "
                "Điều này không chứng minh Origin lạ lấy được token.",
                "Chỉ cho phép Origin tin cậy dùng API mang Bearer token.",
                evidence, verification=Verification.OBSERVED,
            )
        return result, "readable"
    if not observed.readable and (
        observed.get_status is not None or observed.preflight_status is not None
    ):
        result.add(
            "cors-browser-blocked", "Trình duyệt chặn đọc phản hồi CORS",
            Severity.INFO,
            "Fetch từ Origin thử nghiệm bị trình duyệt từ chối với phản hồi đã quan sát. "
            "Kết quả chỉ áp dụng cho Origin và phiên thử nghiệm này.",
            evidence=evidence, verification=Verification.OBSERVED,
        )
        return result, "blocked"
    result.add(
        "cors-browser-inconclusive", "Chưa kết luận được CORS trong trình duyệt",
        Severity.INFO, "Mã HTTP hoặc trạng thái phiên không đủ để xác nhận truy cập dữ liệu riêng.",
        evidence=evidence, verification=Verification.INCONCLUSIVE,
    )
    return result, "inconclusive"


class _LocalServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False


def _tls_context() -> ssl.SSLContext:
    """Make a short-lived local certificate; the real target TLS stays verified."""
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
    except ImportError as exc:
        raise BrowserUnavailable("Thiếu thư viện cryptography cho cầu nối trình duyệt HTTPS.") from exc
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "WebSecAnalyzer local probe")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(x509.SubjectAlternativeName([
            x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
        ]), critical=False)
        .sign(key, hashes.SHA256())
    )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    with tempfile.TemporaryDirectory(prefix="websec-browser-") as directory:
        cert_path = Path(directory) / "cert.pem"
        key_path = Path(directory) / "key.pem"
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ))
        context.load_cert_chain(str(cert_path), str(key_path))
    return context


class BrowserCorsVerifier:
    """One ephemeral browser and bridge shared by selected private endpoints."""

    def __init__(
        self, *, dns: PinnedDNS, pacer: RequestPacer, control: ScanControl,
        timeout: float, allow_private: bool, site_origin: tuple[str, str, int],
        initial_loopback: bool, credential: ApiCredential,
        cookie_attributes: CookieAttributes | None,
    ) -> None:
        self.dns = dns
        self.pacer = pacer
        self.control = control
        self.timeout = timeout
        self.allow_private = allow_private
        self.site_origin = site_origin
        self.initial_loopback = initial_loopback
        self.credential = credential
        self.cookie_attributes = cookie_attributes
        self.session = guarded_session(dns)
        self.origin_server: _LocalServer | None = None
        self.bridge_server: _LocalServer | None = None
        self.threads: list[threading.Thread] = []
        self.started_servers: list[_LocalServer] = []
        self.playwright = None
        self.browser = None
        self.context = None
        self.page = None
        self.origin = ""
        self.bridge_base = ""
        self.target_url = ""
        self.bridge_path = ""
        self.observation: BrowserObservation | None = None
        self.request_count = 0
        self.fatal: Exception | None = None
        self._lock = threading.Lock()

    def start(self, scheme: str) -> None:
        self.control.check()
        verifier = self

        class OriginHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path != "/":
                    self.send_error(404)
                    return
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *_args):
                pass

        class BridgeHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                verifier._forward(self)

            def do_OPTIONS(self):
                verifier._forward(self)

            def log_message(self, *_args):
                pass

        try:
            self.origin_server = _LocalServer(("127.0.0.1", 0), OriginHandler)
            self.bridge_server = _LocalServer(("127.0.0.1", 0), BridgeHandler)
            if scheme == "https":
                context = _tls_context()
                for server in (self.origin_server, self.bridge_server):
                    server.socket = context.wrap_socket(server.socket, server_side=True)
            self.origin = f"{scheme}://localhost:{self.origin_server.server_port}"
            self.bridge_base = f"{scheme}://127.0.0.1:{self.bridge_server.server_port}"
            for server in (self.origin_server, self.bridge_server):
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                self.threads.append(thread)
                self.started_servers.append(server)
            try:
                from playwright.sync_api import Error as PlaywrightError, sync_playwright
            except ImportError as exc:
                raise BrowserUnavailable("Thiếu Playwright để xác minh CORS trong trình duyệt.") from exc
            self.playwright = sync_playwright().start()
            channels = ("msedge", "chrome", None) if os.name == "nt" else (None,)
            for channel in channels:
                self.control.check()
                try:
                    kwargs = {"headless": True, "timeout": int(self.control.timeout(10) * 1000)}
                    if channel:
                        kwargs["channel"] = channel
                    self.browser = self.playwright.chromium.launch(**kwargs)
                    break
                except PlaywrightError:
                    continue
            if self.browser is None:
                raise BrowserUnavailable("Không khởi động được Edge, Chrome hoặc Chromium.")
            self.context = self.browser.new_context(
                ignore_https_errors=scheme == "https", service_workers="block",
            )
            self.page = self.context.new_page()
            self.page.goto(
                self.origin + "/", wait_until="domcontentloaded",
                timeout=int(self.control.timeout(10) * 1000),
            )
            self.control.check()
        except (BrowserUnavailable, ScanStopped):
            self.close()
            raise
        except Exception as exc:
            self.close()
            self.control.check()
            raise BrowserUnavailable("Không chuẩn bị được trình duyệt cô lập.") from exc

    def _forward(self, handler: BaseHTTPRequestHandler) -> None:
        observation = self.observation
        if observation is None or handler.path != self.bridge_path:
            handler.send_error(404)
            return
        method = handler.command
        if method not in {"GET", "OPTIONS"} or handler.headers.get("Origin") != self.origin:
            handler.send_error(403)
            return
        if method == "OPTIONS":
            requested = {
                value.strip().lower() for value in
                handler.headers.get("Access-Control-Request-Headers", "").split(",")
                if value.strip()
            }
            allowed = {"authorization"} if self.credential.mode == "bearer" else set()
            if (
                handler.headers.get("Access-Control-Request-Method", "").upper() != "GET"
                or not requested <= allowed
            ):
                handler.send_error(403)
                return
        with self._lock:
            self.request_count += 1
            if self.request_count > 3:
                observation.error = "Trình duyệt vượt giới hạn 3 yêu cầu trên endpoint."
                handler.send_error(429)
                return
        cookie = handler.headers.get("Cookie")
        authorization = handler.headers.get("Authorization")
        if method == "OPTIONS" and (cookie or authorization):
            observation.error = "Preflight của trình duyệt mang thông tin phiên; đã dừng."
            handler.send_error(403)
            return
        if method == "GET":
            if self.credential.mode == "cookie":
                expected_cookie = "=".join(_single_cookie(self.credential.secret))
                if authorization or (cookie and cookie != expected_cookie):
                    observation.error = "Trình duyệt gửi Cookie ngoài phiên đã khai báo; đã dừng."
                    handler.send_error(403)
                    return
                observation.credential_sent = bool(cookie)
            else:
                if cookie or authorization != f"Bearer {self.credential.secret}":
                    observation.error = "Header phiên trình duyệt không khớp; đã dừng."
                    handler.send_error(403)
                    return
                observation.credential_sent = True
        safe_headers = {
            name: value for name, value in handler.headers.items()
            if name.lower() in {
                "origin", "accept", "cookie", "authorization", "referer", "user-agent",
                "access-control-request-method", "access-control-request-headers",
                "access-control-request-private-network", "sec-fetch-mode",
                "sec-fetch-site", "sec-fetch-dest",
            }
        }
        self.session.cookies.clear()
        try:
            response = fetch(
                self.session, self.target_url, method=method,
                timeout=self.timeout, allow_private=self.allow_private,
                pacer=self.pacer, expected_origin=self.site_origin,
                initial_loopback=self.initial_loopback, control=self.control,
                request_headers=safe_headers, read_body=False, follow_redirects=False,
            )
        except (DNSChanged, ScanStopped) as exc:
            self.fatal = exc
            handler.send_error(502)
            return
        except (InvalidTarget, requests.RequestException):
            observation.error = "Cầu nối không nhận được phản hồi từ API đã chọn."
            handler.send_error(502)
            return
        if method == "OPTIONS":
            observation.preflight_status = response.status_code
            allowed_methods = {
                value.strip().lower() for value in
                response.headers.get("Access-Control-Allow-Methods", "").split(",")
            }
            allowed_headers = {
                value.strip().lower() for value in
                response.headers.get("Access-Control-Allow-Headers", "").split(",")
            }
            requested_headers = {
                value.strip().lower() for value in
                handler.headers.get("Access-Control-Request-Headers", "").split(",")
                if value.strip()
            }
            observation.preflight_allowed = (
                200 <= response.status_code < 300
                and response.headers.get("Access-Control-Allow-Origin") == self.origin
                and response.headers.get("Access-Control-Allow-Credentials", "").lower() == "true"
                and "get" in allowed_methods
                and requested_headers <= allowed_headers
            )
        else:
            observation.get_status = response.status_code
        if response.is_redirect:
            observation.redirect = True
        handler.send_response(response.status_code)
        for name in _CORS_HEADERS:
            value = response.headers.get(name)
            if value and len(value) <= 2000 and "\r" not in value and "\n" not in value:
                handler.send_header(name, value)
        handler.send_header("Cache-Control", "no-store")
        handler.send_header("Content-Length", "0")
        handler.end_headers()

    def verify(self, endpoint_url: str) -> BrowserObservation:
        self.control.check()
        if self.context is None or self.page is None:
            raise BrowserUnavailable("Trình duyệt chưa sẵn sàng.")
        self.target_url = endpoint_url
        self.bridge_path = urlsplit(endpoint_url).path or "/"
        self.observation = BrowserObservation(
            self.origin, self.credential.mode, self.cookie_attributes,
        )
        self.request_count = 0
        self.fatal = None
        bridge_url = self.bridge_base + self.bridge_path
        try:
            self.context.clear_cookies()
            if self.credential.mode == "cookie":
                name, value = _single_cookie(self.credential.secret)
                attributes = self.cookie_attributes
                assert attributes is not None
                self.context.add_cookies([{
                    "name": name, "value": value, "domain": "127.0.0.1",
                    "path": attributes.path, "sameSite": attributes.same_site,
                    "secure": attributes.secure, "httpOnly": attributes.http_only,
                }])
            browser_result = self.page.evaluate(_FETCH_SCRIPT, {
                "url": bridge_url,
                "authorization": (
                    f"Bearer {self.credential.secret}"
                    if self.credential.mode == "bearer" else None
                ),
                "maxMs": int(self.control.timeout(10) * 1000),
            })
            if isinstance(browser_result, dict):
                self.observation.readable = browser_result.get("readable") is True
        except Exception:
            self.control.check()
            self.observation.error = "Trình duyệt không hoàn tất yêu cầu CORS."
        self.control.check()
        if self.fatal is not None:
            raise self.fatal
        return self.observation

    def close(self) -> None:
        for object_ in (self.context, self.browser, self.playwright):
            if object_ is not None:
                try:
                    object_.close() if hasattr(object_, "close") else object_.stop()
                except Exception:
                    pass
        self.context = self.browser = self.playwright = self.page = None
        for server in (self.origin_server, self.bridge_server):
            if server is not None:
                try:
                    if server in self.started_servers:
                        server.shutdown()
                    server.server_close()
                except Exception:
                    pass
        for thread in self.threads:
            thread.join(timeout=1)
        self.session.close()
