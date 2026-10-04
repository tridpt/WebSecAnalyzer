"""Check whether plain HTTP is upgraded to HTTPS."""

from __future__ import annotations

from urllib.parse import urljoin, urlsplit

import requests

from .fetch import RequestPacer
from .findings import CheckResult, Severity
from .targets import InvalidTarget, normalize_target
from .control import ScanControl


def check_https_redirect(
    session: requests.Session,
    final_url: str,
    *,
    timeout: float,
    allow_private: bool,
    pacer: RequestPacer,
    control: ScanControl | None = None,
) -> CheckResult:
    result = CheckResult(category="HTTP to HTTPS Redirect")
    parsed = urlsplit(final_url)
    if parsed.scheme != "https":
        result.add(
            "https-redirect", "Trang hiện dùng HTTP", Severity.INFO,
            "Trang đích không ở HTTPS; xem cảnh báo trong mục TLS.",
        )
        return result
    if parsed.port not in (None, 443):
        result.add(
            "https-redirect", "Bỏ qua kiểm tra chuyển hướng HTTP", Severity.INFO,
            "Trang dùng cổng HTTPS tùy chỉnh; không suy đoán cổng HTTP tương ứng.",
        )
        return result

    host = parsed.hostname or ""
    netloc = f"[{host}]" if ":" in host else host
    http_url = f"http://{netloc}/"
    try:
        normalize_target(
            http_url, allow_private=allow_private,
            dns=getattr(session, "websec_dns", None),
        )
        pacer.wait(control)
        response = session.get(
            http_url, timeout=control.timeout(timeout) if control else timeout,
            allow_redirects=False, stream=True,
        )
    except (InvalidTarget, requests.RequestException) as exc:
        if control:
            control.check()
        result.add(
            "https-redirect", "Không xác định được chuyển hướng HTTP", Severity.INFO,
            f"Không lấy được phản hồi từ cổng HTTP: {exc}",
        )
        return result

    try:
        location = response.headers.get("Location")
        if response.is_redirect and location:
            destination = urljoin(http_url, location)
            destination_parts = urlsplit(destination)
            if (
                destination_parts.scheme.lower() == "https"
                and (destination_parts.hostname or "").lower() == host.lower()
            ):
                result.add(
                    "https-redirect", "HTTP chuyển sang HTTPS", Severity.INFO,
                    f"HTTP {response.status_code} chuyển tới {destination}.",
                )
            else:
                result.add(
                    "https-redirect", "HTTP chưa chuyển thẳng sang HTTPS",
                    Severity.MEDIUM,
                    f"HTTP {response.status_code} chuyển tới {destination}.",
                    "Chuyển yêu cầu HTTP trực tiếp sang URL HTTPS tương ứng.",
                )
        else:
            severity = Severity.HIGH if 200 <= response.status_code < 300 else Severity.MEDIUM
            result.add(
                "https-redirect", "HTTP không chuyển sang HTTPS", severity,
                f"Cổng HTTP trả về mã {response.status_code} mà không chuyển sang HTTPS.",
                "Cấu hình chuyển hướng 301/308 từ HTTP sang HTTPS.",
            )
    finally:
        response.close()
    return result
