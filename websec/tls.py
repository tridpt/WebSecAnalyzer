"""Passive TLS/SSL configuration checks.

Uses only the standard library ssl/socket modules to inspect the certificate
and negotiated protocol. This performs a normal TLS handshake (the same thing
a browser does) - it is not an attack.
"""

from __future__ import annotations

import datetime
import socket
import ssl
import warnings
from urllib.parse import urlparse

from .findings import CheckResult, Severity
from .control import ScanControl
from .network import PinnedDNS

# Protocol versions considered obsolete/insecure.
_WEAK_PROTOCOLS = {"TLSv1", "TLSv1.1", "SSLv2", "SSLv3"}


def _accepts_legacy_tls(
    host: str, port: int, version: ssl.TLSVersion, timeout: float,
    address: str | None = None,
) -> bool | None:
    """True if a handshake succeeds, False if rejected, None if untestable."""
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            context.minimum_version = version
            context.maximum_version = version
            context.set_ciphers("DEFAULT:@SECLEVEL=0")
        with socket.create_connection((address or host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host):
                return True
    except ssl.SSLError as exc:
        if getattr(exc, "reason", "") in {
            "NO_CIPHERS_AVAILABLE", "NO_PROTOCOLS_AVAILABLE"
        }:
            return None
        return False
    except (OSError, ValueError):
        return None


def _check_legacy_tls(
    result: CheckResult, host: str, port: int, timeout: float,
    *, dns: PinnedDNS | None = None, control: ScanControl | None = None,
) -> None:
    rejected: list[str] = []
    unknown: list[str] = []
    for version, label in (
        (ssl.TLSVersion.TLSv1, "TLS 1.0"),
        (ssl.TLSVersion.TLSv1_1, "TLS 1.1"),
    ):
        if control:
            control.check()
        address = dns.verify(host, port) if dns else None
        effective_timeout = control.timeout(timeout) if control else timeout
        accepted = (
            _accepts_legacy_tls(host, port, version, effective_timeout, address)
            if address else _accepts_legacy_tls(host, port, version, effective_timeout)
        )
        if accepted is True:
            result.add(
                check=f"tls-legacy-{label}",
                title=f"Máy chủ còn chấp nhận {label}",
                severity=Severity.HIGH,
                detail=f"Thử nghiệm đã thương lượng thành công {label}.",
                recommendation="Tắt TLS 1.0/1.1 trên máy chủ và chỉ cho phép TLS 1.2+.",
            )
        elif accepted is False:
            rejected.append(label)
        else:
            unknown.append(label)
    if rejected:
        result.add(
            check="tls-legacy-rejected",
            title="Không thương lượng được giao thức TLS cũ",
            severity=Severity.INFO,
            detail=f"Máy quét không kết nối được bằng {', '.join(rejected)}. "
            "Kết quả âm tính còn phụ thuộc thư viện TLS của máy quét.",
        )
    if unknown:
        result.add(
            check="tls-legacy-unknown",
            title="Chưa kiểm tra được một số giao thức TLS cũ",
            severity=Severity.INFO,
            detail=f"Không thể kết luận cho {', '.join(unknown)} với thư viện TLS hiện tại.",
        )


def check_tls(
    url: str, timeout: float = 10.0, *,
    dns: PinnedDNS | None = None, control: ScanControl | None = None,
) -> CheckResult:
    result = CheckResult(category="TLS/SSL Configuration")
    parsed = urlparse(url)

    if parsed.scheme != "https":
        result.add(
            check="tls-scheme",
            title="Trang chưa dùng HTTPS",
            severity=Severity.HIGH,
            detail=f"URL dùng giao thức '{parsed.scheme}', nên dữ liệu không được mã hóa.",
            recommendation="Bật HTTPS với chứng chỉ hợp lệ và chuyển hướng HTTP sang HTTPS.",
        )
        return result

    host = parsed.hostname
    port = parsed.port or 443
    if host is None:
        result.error = "Không đọc được tên miền từ URL."
        return result

    context = ssl.create_default_context()
    cert = None
    protocol = None
    cipher = None
    try:
        address = dns.verify(host, port) if dns else host
        with socket.create_connection(
            (address, port), timeout=control.timeout(timeout) if control else timeout
        ) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                protocol = ssock.version()
                cipher = ssock.cipher()
    except ssl.SSLCertVerificationError as exc:
        if control:
            control.check()
        result.add(
            check="tls-cert",
            title="Chứng chỉ TLS không hợp lệ",
            severity=Severity.HIGH,
            detail=f"Không xác minh được chứng chỉ: {exc}",
            recommendation="Cài chứng chỉ từ CA tin cậy và phục vụ đủ chuỗi chứng chỉ.",
        )
    except (OSError, ssl.SSLError) as exc:
        if control:
            control.check()
        result.error = f"Không thể thiết lập kết nối TLS: {exc}"
        return result

    # Protocol version.
    if protocol in _WEAK_PROTOCOLS:
        result.add(
            check="tls-protocol",
            title=f"Giao thức TLS yếu: {protocol}",
            severity=Severity.HIGH,
            detail=f"Máy chủ dùng {protocol}, một giao thức đã lỗi thời.",
            recommendation="Tắt TLS 1.1 trở xuống; yêu cầu TLS 1.2 hoặc mới hơn.",
        )
    elif protocol:
        result.add(
            check="tls-protocol",
            title=f"Giao thức: {protocol}",
            severity=Severity.INFO,
            detail=f"Kết nối dùng {protocol} và bộ mã hóa {cipher[0] if cipher else '?'}.",
        )

    # Certificate expiry.
    not_before = cert.get("notBefore") if cert else None
    if not_before:
        starts = datetime.datetime.strptime(
            not_before, "%b %d %H:%M:%S %Y %Z"
        ).replace(tzinfo=datetime.timezone.utc)
        if starts > datetime.datetime.now(datetime.timezone.utc):
            result.add(
                check="tls-not-yet-valid",
                title="Chứng chỉ chưa có hiệu lực",
                severity=Severity.HIGH,
                detail=f"Chứng chỉ bắt đầu có hiệu lực lúc {starts.isoformat()}.",
                recommendation="Cài chứng chỉ đang có hiệu lực và kiểm tra đồng hồ máy chủ.",
            )

    not_after = cert.get("notAfter") if cert else None
    if not_after:
        expires = datetime.datetime.strptime(
            not_after, "%b %d %H:%M:%S %Y %Z"
        ).replace(tzinfo=datetime.timezone.utc)
        now = datetime.datetime.now(datetime.timezone.utc)
        days_left = (expires - now).days
        if days_left < 0:
            result.add(
                check="tls-expiry",
                title="Chứng chỉ đã hết hạn",
                severity=Severity.HIGH,
                detail=f"Chứng chỉ đã hết hạn {abs(days_left)} ngày.",
                recommendation="Gia hạn chứng chỉ ngay.",
            )
        elif days_left < 15:
            result.add(
                check="tls-expiry",
                title="Chứng chỉ sắp hết hạn",
                severity=Severity.MEDIUM,
                detail=f"Chứng chỉ sẽ hết hạn sau {days_left} ngày.",
                recommendation="Gia hạn và tự động hóa việc gia hạn chứng chỉ.",
            )
        else:
            result.add(
                check="tls-expiry",
                title="Chứng chỉ còn hiệu lực",
                severity=Severity.INFO,
                detail=f"Chứng chỉ còn hiệu lực {days_left} ngày.",
            )

    if cert:
        issuer_parts = [
            str(value)
            for group in cert.get("issuer", ())
            for key, value in group
            if key in {"organizationName", "commonName"}
        ]
        if issuer_parts:
            result.add(
                check="tls-issuer",
                title="Đơn vị cấp chứng chỉ",
                severity=Severity.INFO,
                detail=", ".join(issuer_parts),
            )

    _check_legacy_tls(
        result, host, port, min(timeout, 5.0), dns=dns, control=control,
    )
    return result
