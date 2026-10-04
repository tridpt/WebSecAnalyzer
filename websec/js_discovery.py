"""Discover links after same-origin JavaScript renders an already fetched page.

The browser has no direct network access to the target. Only bounded static
JavaScript GETs are fetched through the scanner's guarded, paced session.
"""

from __future__ import annotations

import os
from urllib.parse import parse_qsl, urlsplit

import requests

from .control import ScanControl, ScanStopped
from .crawler import _STATE_CHANGING_SEGMENTS
from .fetch import RequestPacer, fetch, origin
from .network import DNSChanged, PinnedDNS, guarded_session
from .targets import InvalidTarget, is_loopback_host

MAX_SCRIPTS_PER_PAGE = 8
MAX_SCRIPT_REQUESTS = 60
MAX_CACHED_SCRIPT_BYTES = 8_000_000
MAX_RENDERED_LINKS = 120


class BrowserDiscoveryUnavailable(Exception):
    """The optional isolated browser could not start or render a page."""


def safe_script_url(url: str, site_origin: tuple[str, str, int]) -> bool:
    """Allow static-looking scripts only; never browser-initiated API requests."""
    try:
        parsed = urlsplit(url)
        query = parse_qsl(parsed.query, keep_blank_values=True)
        segments = set(parsed.path.lower().split("/"))
        segments.update(part.rsplit(".", 1)[0] for part in list(segments) if "." in part)
        return (
            len(url) <= 2048
            and parsed.scheme in {"http", "https"}
            and origin(url) == site_origin
            and parsed.username is None and parsed.password is None
            and parsed.path.lower().endswith((".js", ".mjs"))
            and not segments & _STATE_CHANGING_SEGMENTS
            and not any(
                key.lower() in _STATE_CHANGING_SEGMENTS
                or (key.lower() in {"action", "do"}
                    and value.lower() in _STATE_CHANGING_SEGMENTS)
                for key, value in query
            )
        )
    except ValueError:
        return False


class JsLinkDiscoverer:
    """Render HTML snapshots with an ephemeral browser and extract anchor URLs."""

    def __init__(
        self, *, dns: PinnedDNS, pacer: RequestPacer, control: ScanControl,
        timeout: float, allow_private: bool, site_origin: tuple[str, str, int],
        user_agent: str,
    ) -> None:
        self.control = control
        self.pacer = pacer
        self.timeout = timeout
        self.allow_private = allow_private
        self.site_origin = site_origin
        self.session = guarded_session(dns)
        self.session.headers["User-Agent"] = user_agent
        self.session.trust_env = False
        self.playwright = None
        self.browser = None
        self.context = None
        self.document: requests.Response | None = None
        self.script_cache: dict[str, tuple[int, dict[str, str], bytes]] = {}
        self.script_requests = 0
        self.cached_script_bytes = 0
        self.page_script_requests = 0
        self.partial = False
        self.fatal: Exception | None = None

    def start(self) -> None:
        self.control.check()
        try:
            from playwright.sync_api import Error as PlaywrightError, sync_playwright
        except ImportError as exc:
            raise BrowserDiscoveryUnavailable(
                "Thiếu Playwright; cài requirements-browser.txt để khám phá trang JavaScript."
            ) from exc
        try:
            self.playwright = sync_playwright().start()
            channels = ("msedge", "chrome", None) if os.name == "nt" else (None,)
            for channel in channels:
                self.control.check()
                try:
                    options = {
                        "headless": True,
                        "timeout": int(self.control.timeout(10) * 1000),
                    }
                    if channel:
                        options["channel"] = channel
                    self.browser = self.playwright.chromium.launch(**options)
                    break
                except PlaywrightError:
                    continue
            if self.browser is None:
                raise BrowserDiscoveryUnavailable(
                    "Không khởi động được Edge, Chrome hoặc Chromium."
                )
            self.context = self.browser.new_context(
                service_workers="block", accept_downloads=False,
                java_script_enabled=True,
            )
            self.context.set_default_timeout(int(self.control.timeout(5) * 1000))
            self.context.route("**/*", self._route)
            self.context.add_init_script("""
                const blocked = function () { throw new Error('blocked'); };
                for (const name of ['WebSocket', 'WebTransport',
                                    'RTCPeerConnection', 'webkitRTCPeerConnection']) {
                    try {
                        Object.defineProperty(window, name, {
                            value: blocked, writable: false, configurable: false,
                        });
                    } catch (_) { window[name] = blocked; }
                }
            """)
        except (BrowserDiscoveryUnavailable, ScanStopped):
            self.close()
            raise
        except Exception as exc:
            self.close()
            self.control.check()
            raise BrowserDiscoveryUnavailable(
                "Không chuẩn bị được trình duyệt khám phá trang."
            ) from exc

    def _route(self, route) -> None:
        request = route.request
        document = self.document
        if document is None or request.method != "GET":
            route.abort()
            return
        if request.resource_type == "document":
            if request.url != document.url:
                route.abort()
                return
            headers = {"Content-Type": document.headers.get("Content-Type", "text/html")}
            for name in ("Content-Security-Policy", "X-Content-Type-Options"):
                if name in document.headers:
                    headers[name] = document.headers[name]
            route.fulfill(status=document.status_code, headers=headers, body=document.content)
            return
        if request.resource_type != "script" or not safe_script_url(
            request.url, self.site_origin
        ):
            route.abort()
            return
        if request.url not in self.script_cache:
            if (self.page_script_requests >= MAX_SCRIPTS_PER_PAGE
                    or self.script_requests >= MAX_SCRIPT_REQUESTS):
                self.partial = True
                route.abort()
                return
            self.page_script_requests += 1
            self.script_requests += 1
            try:
                self.session.cookies.clear()
                response = fetch(
                    self.session, request.url, timeout=self.timeout,
                    allow_private=self.allow_private, pacer=self.pacer,
                    expected_origin=self.site_origin,
                    initial_loopback=is_loopback_host(self.site_origin[1]),
                    control=self.control, follow_redirects=False,
                )
                self.session.cookies.clear()
                if response.is_redirect or response.status_code >= 400:
                    self.partial = True
                    route.abort()
                    return
                headers = {
                    "Content-Type": response.headers.get(
                        "Content-Type", "text/javascript"
                    ),
                }
                if "X-Content-Type-Options" in response.headers:
                    headers["X-Content-Type-Options"] = response.headers[
                        "X-Content-Type-Options"
                    ]
                if self.cached_script_bytes + len(response.content) > MAX_CACHED_SCRIPT_BYTES:
                    self.partial = True
                    route.abort()
                    return
                self.cached_script_bytes += len(response.content)
                self.script_cache[request.url] = (
                    response.status_code, headers, response.content,
                )
            except (DNSChanged, ScanStopped) as exc:
                self.fatal = exc
                route.abort()
                return
            except (InvalidTarget, requests.RequestException):
                self.partial = True
                route.abort()
                return
            finally:
                self.session.cookies.clear()
        status, headers, body = self.script_cache[request.url]
        route.fulfill(status=status, headers=headers, body=body)

    def discover(self, response: requests.Response) -> list[str]:
        self.control.check()
        if self.context is None:
            raise BrowserDiscoveryUnavailable("Trình duyệt chưa sẵn sàng.")
        self.document = response
        self.page_script_requests = 0
        self.fatal = None
        try:
            page = self.context.new_page()
        except Exception as exc:
            self.control.check()
            self.partial = True
            self.document = None
            raise BrowserDiscoveryUnavailable(
                "Không mở được trang trong trình duyệt cô lập."
            ) from exc
        page.on("popup", lambda popup: popup.close())
        try:
            page.goto(
                response.url, wait_until="domcontentloaded",
                timeout=int(self.control.timeout(self.timeout) * 1000),
            )
            # Give client-side routers a short, bounded chance to create links.
            page.wait_for_timeout(int(self.control.timeout(0.4) * 1000))
            links = page.locator("a[href]").evaluate_all(
                "(nodes) => nodes.slice(0, 120).map(node => node.href)"
            )
            self.control.check()
            if self.fatal is not None:
                raise self.fatal
            return [url for url in links if isinstance(url, str)][:MAX_RENDERED_LINKS]
        except (DNSChanged, ScanStopped):
            raise
        except Exception as exc:
            self.control.check()
            if self.fatal is not None:
                raise self.fatal
            self.partial = True
            raise BrowserDiscoveryUnavailable("Không kết xuất được một trang JavaScript.") from exc
        finally:
            try:
                page.close()
            except Exception:
                pass
            self.document = None

    def close(self) -> None:
        for object_ in (self.context, self.browser, self.playwright):
            if object_ is not None:
                try:
                    object_.close() if hasattr(object_, "close") else object_.stop()
                except Exception:
                    pass
        self.context = self.browser = self.playwright = None
        self.session.close()
