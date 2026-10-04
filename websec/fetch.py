"""Bounded HTTP fetching shared by page crawling and security checks."""

from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import urldefrag, urljoin, urlsplit

import requests

from .targets import InvalidTarget, is_loopback_host, normalize_target
from .control import ScanControl

MAX_REDIRECTS = 5
MAX_RESPONSE_BYTES = 1_000_000


class OutOfScope(InvalidTarget):
    """A discovered URL or redirect left the website being scanned."""


class RequestLimitReached(InvalidTarget):
    """The scan has made its maximum number of HTTP requests."""


def origin(url: str) -> tuple[str, str, int]:
    parsed = urlsplit(url)
    return (
        parsed.scheme.lower(),
        (parsed.hostname or "").lower(),
        parsed.port or (443 if parsed.scheme.lower() == "https" else 80),
    )


def without_fragment(url: str) -> str:
    return urldefrag(url).url


@dataclass
class RequestPacer:
    min_interval: float = 0.35
    next_at: float = 0.0
    max_requests: int = 68
    request_count: int = 0

    def wait(self, control: ScanControl | None = None) -> None:
        if control:
            control.check()
        if self.request_count >= self.max_requests:
            raise RequestLimitReached("Đã đạt giới hạn số yêu cầu HTTP cho lần quét này.")
        remaining = self.next_at - time.monotonic()
        if remaining > 0:
            if control:
                control.wait(remaining)
            else:
                time.sleep(remaining)
        self.next_at = time.monotonic() + self.min_interval
        self.request_count += 1


def fetch(
    session: requests.Session,
    url: str,
    *,
    timeout: float,
    allow_private: bool,
    pacer: RequestPacer,
    expected_origin: tuple[str, str, int] | None = None,
    initial_loopback: bool = False,
    initial_host: str | None = None,
    control: ScanControl | None = None,
    request_headers: dict[str, str] | None = None,
    method: str = "GET",
    read_body: bool = True,
    follow_redirects: bool = True,
) -> requests.Response:
    """GET or OPTIONS within scope; optionally avoid reading the body."""
    if method not in {"GET", "OPTIONS"}:
        raise InvalidTarget("Chỉ hỗ trợ GET và OPTIONS trong lượt quét.")
    current_url = without_fragment(url)
    for hop in range(MAX_REDIRECTS + 1):
        if control:
            control.check()
        if (
            hop
            and not allow_private
            and not initial_loopback
            and is_loopback_host(urlsplit(current_url).hostname)
        ):
            raise InvalidTarget("Website công khai chuyển hướng tới localhost; đã dừng quét.")

        current_url = normalize_target(
            current_url, allow_private=allow_private,
            dns=getattr(session, "websec_dns", None),
        )
        if initial_host:
            current_host = (urlsplit(current_url).hostname or "").lower()
            allowed_hosts = {initial_host.lower()}
            if not is_loopback_host(initial_host):
                if initial_host.lower().startswith("www."):
                    allowed_hosts.add(initial_host.lower()[4:])
                else:
                    allowed_hosts.add("www." + initial_host.lower())
            if current_host not in allowed_hosts:
                raise OutOfScope("URL đầu vào chuyển hướng sang tên miền khác; đã dừng quét.")
        if expected_origin and origin(current_url) != expected_origin:
            raise OutOfScope("URL chuyển hướng ra ngoài website đang quét.")

        pacer.wait(control)
        try:
            send = session.get if method == "GET" else session.options
            response = send(
                current_url,
                timeout=control.timeout(timeout) if control else timeout,
                allow_redirects=False,
                stream=True,
                headers=request_headers,
            )
            response.websec_observed_at = datetime.now(timezone.utc).isoformat(
                timespec="seconds"
            ).replace("+00:00", "Z")
        except requests.RequestException:
            if control:
                control.check()
            raise
        try:
            if response.is_redirect and response.headers.get("Location"):
                if not follow_redirects:
                    return response
                if hop == MAX_REDIRECTS:
                    raise InvalidTarget("Website chuyển hướng quá nhiều lần.")
                current_url = urljoin(current_url, response.headers["Location"])
                continue

            if not read_body:
                return response

            chunks: list[bytes] = []
            size = 0
            try:
                for chunk in response.iter_content(chunk_size=16_384):
                    if control:
                        control.check()
                    size += len(chunk)
                    if size > MAX_RESPONSE_BYTES:
                        raise InvalidTarget(
                            "Trang trả về hơn 1 MB dữ liệu. Hãy quét một trang HTML nhỏ hơn."
                        )
                    chunks.append(chunk)
            except requests.RequestException:
                if control:
                    control.check()
                raise
            response._content = b"".join(chunks)
            response._content_consumed = True
            return response
        finally:
            response.close()

    raise InvalidTarget("Website chuyển hướng quá nhiều lần.")  # pragma: no cover
