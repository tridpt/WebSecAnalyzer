"""Passive HTTP security header checks."""

from __future__ import annotations

import requests

from .findings import CheckResult, Severity

# Header name -> (severity if missing, human explanation, recommendation)
_EXPECTED_HEADERS: dict[str, tuple[Severity, str, str]] = {
    "strict-transport-security": (
        Severity.HIGH,
        "HSTS yêu cầu trình duyệt dùng HTTPS trong các lần truy cập sau.",
        "Thiết lập Strict-Transport-Security: max-age=31536000; "
        "includeSubDomains sau khi toàn bộ subdomain đã hỗ trợ HTTPS.",
    ),
    "x-content-type-options": (
        Severity.MEDIUM,
        "Ngăn trình duyệt tự đoán kiểu nội dung khác với Content-Type đã khai báo.",
        "Thêm X-Content-Type-Options: nosniff.",
    ),
    "x-frame-options": (
        Severity.MEDIUM,
        "Kiểm soát việc nhúng trang trong iframe để giảm rủi ro clickjacking. "
        "CSP frame-ancestors cũng có thể bảo vệ việc này.",
        "Thêm X-Frame-Options: DENY hoặc SAMEORIGIN, hay dùng CSP frame-ancestors.",
    ),
    "referrer-policy": (
        Severity.LOW,
        "Giới hạn thông tin địa chỉ nguồn gửi kèm các yêu cầu.",
        "Thêm Referrer-Policy: strict-origin-when-cross-origin.",
    ),
    "permissions-policy": (
        Severity.LOW,
        "Giới hạn các tính năng trình duyệt như camera và vị trí.",
        "Thêm Permissions-Policy để tắt các tính năng không sử dụng.",
    ),
}

# Headers that leak implementation details.
_LEAKY_HEADERS = {
    "server": "Có thể tiết lộ phần mềm máy chủ và phiên bản.",
    "x-powered-by": "Có thể tiết lộ ngôn ngữ hoặc framework backend.",
    "x-aspnet-version": "Tiết lộ phiên bản ASP.NET.",
    "x-aspnetmvc-version": "Tiết lộ phiên bản ASP.NET MVC.",
}


def check_headers(response: requests.Response) -> CheckResult:
    result = CheckResult(category="HTTP Security Headers")
    headers = {k.lower(): v for k, v in response.headers.items()}
    csp = headers.get("content-security-policy", "")
    is_http = getattr(response, "url", "").lower().startswith("http://")

    for name, (severity, explanation, recommendation) in _EXPECTED_HEADERS.items():
        # Browsers ignore HSTS received over plain HTTP; TLS check covers that risk.
        if name == "strict-transport-security" and is_http:
            continue
        if name == "x-frame-options" and "frame-ancestors" in csp.lower():
            continue
        if name not in headers:
            result.add(
                check=name,
                title=f"Thiếu {name}",
                severity=severity,
                detail=explanation,
                recommendation=recommendation,
                evidence=f"{name}: [không có] trong phản hồi HTTP {getattr(response, 'status_code', '?')}",
            )

    for name, why in _LEAKY_HEADERS.items():
        if name in headers:
            result.add(
                check=name,
                title=f"Lộ thông tin qua {name}",
                severity=Severity.LOW,
                detail=f"{why} Giá trị: {headers[name]!r}",
                recommendation=f"Ẩn hoặc bỏ header {name} trong phản hồi.",
            )

    hsts = headers.get("strict-transport-security", "")
    if hsts and not is_http:
        try:
            max_age = next(
                int(part.split("=", 1)[1].strip())
                for part in hsts.split(";")
                if part.strip().lower().startswith("max-age=")
            )
        except (StopIteration, ValueError):
            max_age = 0
        if max_age < 15_552_000:
            result.add(
                check="strict-transport-security",
                title="Thời hạn HSTS quá ngắn hoặc không hợp lệ",
                severity=Severity.MEDIUM,
                detail=f"max-age hiện tại: {max_age} giây; nên đạt ít nhất 6 tháng.",
                recommendation="Cấu hình max-age=31536000 sau khi xác nhận "
                "website và subdomain luôn hoạt động qua HTTPS.",
                evidence=f"Strict-Transport-Security: {hsts[:200]}",
            )

    if not result.findings:
        result.add(
            check="headers",
            title="Các HTTP security header cơ bản đã có",
            severity=Severity.INFO,
            detail="Không phát hiện header cơ bản bị thiếu hoặc cấu hình yếu.",
        )
    return result
