"""Validate scan targets before any network request.

The web UI is a local tool, but target validation also protects it from
accidentally following a public site's redirect into a private service.
"""

from __future__ import annotations

import ipaddress
import socket
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

if TYPE_CHECKING:
    from .network import PinnedDNS


class InvalidTarget(ValueError):
    """The entered URL is not a suitable HTTP(S) scan target."""


def is_loopback_host(host: str | None) -> bool:
    if not host:
        return False
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def normalize_target(
    raw: str, *, allow_private: bool = False, dns: PinnedDNS | None = None,
) -> str:
    value = raw.strip()
    if not value:
        raise InvalidTarget("Vui lòng nhập địa chỉ website.")
    if len(value) > 2048 or any(ord(char) < 32 for char in value):
        raise InvalidTarget("URL quá dài hoặc chứa ký tự không hợp lệ.")

    if "://" not in value:
        try:
            entered_host = urlsplit("//" + value).hostname
        except ValueError as exc:
            raise InvalidTarget("URL không hợp lệ.") from exc
        scheme = "http" if is_loopback_host(entered_host) else "https"
        value = f"{scheme}://{value}"
    try:
        parsed = urlsplit(value)
        port = parsed.port
        host = parsed.hostname
    except ValueError as exc:
        raise InvalidTarget("URL không hợp lệ.") from exc

    if parsed.scheme.lower() not in {"http", "https"} or not host:
        raise InvalidTarget("Chỉ hỗ trợ URL bắt đầu bằng http:// hoặc https://.")
    if port == 0:
        raise InvalidTarget("Cổng trong URL phải lớn hơn 0.")
    if parsed.username is not None or parsed.password is not None:
        raise InvalidTarget("Không nhập tên đăng nhập hoặc mật khẩu trong URL.")
    if parsed.fragment:
        value = value.split("#", 1)[0]
    if any(char.isspace() for char in parsed.netloc):
        raise InvalidTarget("Tên miền không hợp lệ.")

    if dns is not None:
        dns.verify(host, port or (443 if parsed.scheme == "https" else 80))
    elif not allow_private:
        try:
            addresses = socket.getaddrinfo(
                host, port or (443 if parsed.scheme == "https" else 80),
                type=socket.SOCK_STREAM,
            )
        except (socket.gaierror, UnicodeError) as exc:
            raise InvalidTarget(f"Không phân giải được tên miền: {host}.") from exc
        try:
            resolved = [ipaddress.ip_address(entry[4][0]) for entry in addresses]
            if is_loopback_host(host):
                blocked = not resolved or any(not address.is_loopback for address in resolved)
            else:
                blocked = not resolved or any(not address.is_global for address in resolved)
        except ValueError:
            blocked = True
        if blocked:
            raise InvalidTarget(
                "Địa chỉ mạng nội bộ bị chặn. "
                "Để kiểm tra site nội bộ do bạn quản lý, bật ALLOW_PRIVATE_TARGETS=1."
            )

    return value
