"""Safely preview owner-selected GET operations from a same-origin OpenAPI file."""

from __future__ import annotations

from urllib.parse import urljoin, urlsplit

from .api import selectable_get_routes, validate_openapi_path
from .control import ScanControl
from .fetch import RequestPacer, fetch, origin
from .network import PinnedDNS, guarded_session
from .scanner import USER_AGENT
from .targets import InvalidTarget, is_loopback_host, normalize_target


def preview_openapi(
    url: str, openapi_path: str, *, allow_private: bool = False,
) -> dict:
    """Read only the site entry and OpenAPI document; never call discovered routes."""
    path = validate_openapi_path(openapi_path)
    if not path:
        raise InvalidTarget("Nhập path OpenAPI, ví dụ /openapi.json.")
    control = ScanControl(max_seconds=15)
    dns = PinnedDNS(allow_private=allow_private, control=control)
    target = normalize_target(url, allow_private=allow_private, dns=dns)
    pacer = RequestPacer(max_requests=12)
    session = guarded_session(dns)
    session.headers["User-Agent"] = USER_AGENT
    try:
        first = fetch(
            session, target, timeout=5, allow_private=allow_private,
            pacer=pacer, initial_host=urlsplit(target).hostname,
            initial_loopback=is_loopback_host(urlsplit(target).hostname),
            control=control, read_body=False,
        )
        document = fetch(
            session, urljoin(first.url, path), timeout=5,
            allow_private=allow_private, pacer=pacer,
            expected_origin=origin(first.url),
            initial_loopback=is_loopback_host(urlsplit(first.url).hostname),
            control=control,
        )
        if document.status_code != 200:
            raise InvalidTarget(
                f"OpenAPI trả HTTP {document.status_code}; chưa thể chọn route."
            )
        routes, total_get, eligible_get = selectable_get_routes(document.content)
        return {
            "routes": routes,
            "total_get": total_get,
            "eligible_get": eligible_get,
            "limit": len(routes),
        }
    finally:
        session.close()
