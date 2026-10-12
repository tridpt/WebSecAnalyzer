"""Passive HTTP security header checks."""

from __future__ import annotations

import re
from urllib.parse import urlsplit

import requests

from .evidence import safe_header_value
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

_REFERRER_POLICIES = {
    "no-referrer", "no-referrer-when-downgrade", "origin",
    "origin-when-cross-origin", "same-origin", "strict-origin",
    "strict-origin-when-cross-origin", "unsafe-url",
}
_BROAD_PERMISSIONS = {
    "camera", "microphone", "geolocation", "display-capture", "usb",
}
_PERMISSION_DIRECTIVE = re.compile(r"([a-z][a-z0-9-]*)\s*=\s*(\*|\([^()]*\))", re.I)
_PERMISSION_MEMBERS = re.compile(
    r'(?:self|"https?://[^"\s]+")'
    r'(?:\s+(?:self|"https?://[^"\s]+"))*', re.I,
)


def _evidence(name: str, value: str | None) -> str:
    return f"{name}: {safe_header_value(value) if value is not None else '[không có]'}"


def _hsts_max_age(value: str) -> int | None:
    directives = [part.strip() for part in value.split(";") if part.strip()]
    ages = [part for part in directives if part.split("=", 1)[0].strip().lower() == "max-age"]
    if len(ages) != 1:
        return None
    match = re.fullmatch(r"max-age\s*=\s*(\d{1,20})", ages[0], flags=re.I)
    return int(match.group(1)) if match else None


def _specific_ancestor(source: str) -> bool:
    if source.lower() == "'self'":
        return True
    if (source in {"*", "http:", "https:"} or
            (source.endswith(":") and not source.endswith(":*")) or
            "'" in source or '"' in source):
        return False
    candidate = source[:-2] if source.endswith(":*") else source
    try:
        parsed = urlsplit(candidate if "://" in candidate else "//" + candidate)
        host = parsed.hostname or ""
        if parsed.scheme and parsed.scheme not in {"http", "https"}:
            return False
        if not host or host == "*" or ("*" in host and not (
            host.startswith("*.") and host.count("*") == 1 and len(host) > 2
        )):
            return False
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            return False
        parsed.port  # Reject a malformed port.
    except ValueError:
        return False
    return True


def _frame_ancestors_state(csp: str) -> str:
    """Classify the first enforced frame-ancestors directive conservatively."""
    for part in csp.split(";"):
        tokens = part.strip().split()
        if not tokens or tokens[0].lower() != "frame-ancestors":
            continue
        sources = [item.lower() for item in tokens[1:]]
        if not sources:
            return "invalid"
        if "*" in sources or "http:" in sources or "https:" in sources:
            return "broad"
        if sources == ["'none'"]:
            return "restrictive"
        if "'none'" in sources or not all(_specific_ancestor(item) for item in sources):
            return "invalid"
        return "restrictive"
    return "missing"


def _permissions_state(value: str) -> tuple[list[str], list[str]]:
    invalid: list[str] = []
    broad: list[str] = []
    seen: set[str] = set()
    for part in value.split(","):
        item = part.strip()
        match = _PERMISSION_DIRECTIVE.fullmatch(item)
        if not match:
            invalid.append(item[:60] or "[rỗng]")
            continue
        feature, allowlist = match.group(1).lower(), match.group(2)
        if feature in seen:
            invalid.append(feature + " [lặp]")
            continue
        seen.add(feature)
        if allowlist.startswith("("):
            members = allowlist[1:-1].strip()
            if members and not _PERMISSION_MEMBERS.fullmatch(members):
                invalid.append(feature)
            else:
                for quoted_origin in re.findall(r'"([^"]+)"', members):
                    try:
                        parsed = urlsplit(quoted_origin)
                        if (parsed.scheme not in {"http", "https"} or not parsed.hostname
                                or parsed.path not in {"", "/"} or parsed.query or parsed.fragment
                                or parsed.username or parsed.password):
                            invalid.append(feature)
                            break
                        parsed.port
                    except ValueError:
                        invalid.append(feature)
                        break
        elif feature in _BROAD_PERMISSIONS:
            broad.append(feature)
    return invalid, broad


def check_headers(response: requests.Response) -> CheckResult:
    result = CheckResult(category="HTTP Security Headers")
    headers = {k.lower(): v for k, v in response.headers.items()}
    csp = headers.get("content-security-policy", "")
    is_http = getattr(response, "url", "").lower().startswith("http://")
    frame_state = _frame_ancestors_state(csp)

    for name, (severity, explanation, recommendation) in _EXPECTED_HEADERS.items():
        # Browsers ignore HSTS received over plain HTTP; TLS check covers that risk.
        if name == "strict-transport-security" and is_http:
            continue
        if name == "x-frame-options" and frame_state != "missing":
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

    nosniff = headers.get("x-content-type-options")
    if nosniff is not None and nosniff.strip().lower() != "nosniff":
        result.add(
            "x-content-type-options", "X-Content-Type-Options không có giá trị nosniff",
            Severity.MEDIUM,
            "Trình duyệt chỉ áp dụng bảo vệ MIME sniffing khi giá trị là nosniff.",
            "Đặt X-Content-Type-Options: nosniff và bỏ giá trị khác hoặc lặp.",
            _evidence("X-Content-Type-Options", nosniff),
        )

    xfo = headers.get("x-frame-options")
    if frame_state == "missing" and xfo is not None and xfo.strip().upper() not in {"DENY", "SAMEORIGIN"}:
        result.add(
            "x-frame-options", "X-Frame-Options không hợp lệ",
            Severity.MEDIUM,
            "Giá trị này không phải DENY hoặc SAMEORIGIN nên có thể bị trình duyệt bỏ qua.",
            "Đặt X-Frame-Options: DENY/SAMEORIGIN hoặc CSP frame-ancestors giới hạn nguồn nhúng.",
            _evidence("X-Frame-Options", xfo),
        )
    elif frame_state == "restrictive" and xfo is not None and xfo.strip().upper() not in {"DENY", "SAMEORIGIN"}:
        result.add(
            "x-frame-options", "X-Frame-Options không hợp lệ; CSP đang giới hạn iframe",
            Severity.LOW,
            "CSP frame-ancestors đang giới hạn nhúng, nhưng trình duyệt cũ dựa vào X-Frame-Options có thể bỏ qua giá trị này.",
            "Đặt X-Frame-Options: DENY/SAMEORIGIN hoặc bỏ header sai sau khi xem nhu cầu trình duyệt cũ.",
            _evidence("X-Frame-Options", xfo),
        )
    if frame_state in {"broad", "invalid"}:
        invalid_with_xfo = (
            frame_state == "invalid" and xfo is not None
            and xfo.strip().upper() in {"DENY", "SAMEORIGIN"}
        )
        result.add(
            "frame-ancestors", "CSP frame-ancestors quá rộng" if frame_state == "broad" else
            "CSP frame-ancestors không hợp lệ",
            Severity.LOW if invalid_with_xfo else Severity.MEDIUM,
            "Chỉ thị cho phép nguồn nhúng rộng; trình duyệt hỗ trợ CSP có thể ưu tiên nó hơn X-Frame-Options."
            if frame_state == "broad" else
            "Cú pháp không rõ hiệu lực; trình duyệt có thể bỏ qua hoặc áp dụng khác dự kiến. "
            "X-Frame-Options hợp lệ có thể bảo vệ ở một số trình duyệt.",
            "Đặt frame-ancestors 'none', 'self' hoặc danh sách origin cụ thể; kiểm tra lại X-Frame-Options nếu cần hỗ trợ trình duyệt cũ.",
            _evidence("Content-Security-Policy", csp),
        )

    referrer = headers.get("referrer-policy")
    if referrer is not None:
        recognized = [item.strip().lower() for item in referrer.split(",")
                      if item.strip().lower() in _REFERRER_POLICIES]
        effective = recognized[-1] if recognized else None
        if effective is None:
            result.add(
                "referrer-policy", "Referrer-Policy không hợp lệ", Severity.LOW,
                "Không thấy chỉ thị hợp lệ; trình duyệt có thể dùng chính sách mặc định thay vì giá trị dự kiến.",
                "Đặt Referrer-Policy: strict-origin-when-cross-origin hoặc no-referrer.",
                _evidence("Referrer-Policy", referrer),
            )
        elif effective in {"unsafe-url", "no-referrer-when-downgrade"}:
            result.add(
                "referrer-policy", f"Referrer-Policy hiệu lực quá rộng: {effective}",
                Severity.MEDIUM if effective == "unsafe-url" else Severity.LOW,
                "Chính sách có thể gửi URL đầy đủ, gồm query, sang website khác qua Referer.",
                "Dùng strict-origin-when-cross-origin, strict-origin hoặc no-referrer theo nhu cầu ứng dụng.",
                _evidence("Referrer-Policy", referrer),
            )

    permissions = headers.get("permissions-policy")
    if permissions is not None:
        invalid, broad = _permissions_state(permissions)
        if invalid:
            result.add(
                "permissions-policy-invalid", "Permissions-Policy có cú pháp không hợp lệ",
                Severity.LOW,
                "Một số chỉ thị có thể bị trình duyệt bỏ qua; kiểm tra chỉ xác minh cú pháp allowlist cơ bản.",
                "Dùng dạng feature=(), feature=(self), feature=(\"https://origin.example\") hoặc feature=* khi có chủ đích.",
                _evidence("Permissions-Policy", permissions),
            )
        if broad:
            result.add(
                "permissions-policy-broad", "Permissions-Policy mở rộng tính năng nhạy cảm",
                Severity.LOW,
                f"Các tính năng {', '.join(broad)} đang cho phép mọi origin; quyền của người dùng vẫn có thể được yêu cầu riêng.",
                "Giới hạn các tính năng không dùng bằng () và chỉ cho phép origin tin cậy khi cần.",
                _evidence("Permissions-Policy", permissions),
            )

    for name, why in _LEAKY_HEADERS.items():
        if name in headers:
            result.add(
                check=name,
                title=f"Lộ thông tin qua {name}",
                severity=Severity.LOW,
                detail=f"{why} Giá trị: {safe_header_value(headers[name])!r}",
                recommendation=f"Ẩn hoặc bỏ header {name} trong phản hồi.",
            )

    hsts = headers.get("strict-transport-security")
    if hsts is not None and not is_http:
        max_age = _hsts_max_age(hsts)
        if max_age is None or max_age == 0:
            result.add(
                check="strict-transport-security",
                title="HSTS không hợp lệ hoặc đã tắt",
                severity=Severity.HIGH,
                detail="Thiếu max-age hợp lệ, khai báo lặp hoặc max-age=0 khiến HSTS không bảo vệ như dự kiến.",
                recommendation="Đặt một max-age=31536000 trên HTTPS; chỉ thêm includeSubDomains khi mọi subdomain đã hỗ trợ HTTPS.",
                evidence=_evidence("Strict-Transport-Security", hsts),
            )
        elif max_age < 15_552_000:
            result.add(
                check="strict-transport-security",
                title="Thời hạn HSTS quá ngắn",
                severity=Severity.MEDIUM,
                detail=f"max-age hiện tại: {max_age} giây; nên đạt ít nhất 6 tháng.",
                recommendation="Cấu hình max-age=31536000 sau khi xác nhận "
                "website và subdomain luôn hoạt động qua HTTPS.",
                evidence=_evidence("Strict-Transport-Security", hsts),
            )

    if not result.findings:
        result.add(
            check="headers",
            title="Các HTTP security header cơ bản đã có",
            severity=Severity.INFO,
            detail="Không thấy vấn đề trong các giá trị header cơ bản được kiểm tra.",
        )
    return result
