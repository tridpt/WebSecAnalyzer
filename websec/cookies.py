"""Inspect cookie attributes without ever showing cookie values in evidence."""

from __future__ import annotations

import requests

from .findings import CheckResult, Severity


def check_cookies(response: requests.Response) -> CheckResult:
    result = CheckResult(category="Cookie Flags")
    raw = getattr(response, "raw", None)
    raw_headers = getattr(raw, "headers", None)
    raw_cookies = raw_headers.getlist("Set-Cookie") if hasattr(raw_headers, "getlist") else []
    if not raw_cookies:
        single = response.headers.get("Set-Cookie")
        raw_cookies = [single] if single else []
    if not raw_cookies:
        result.add("cookies", "Trang không đặt cookie", Severity.INFO,
                   "Phản hồi này không có Set-Cookie để kiểm tra.",
                   evidence="Set-Cookie: [không có]")
        return result

    for cookie in raw_cookies:
        name = cookie.split("=", 1)[0].strip()[:100]
        attrs: dict[str, str] = {}
        for part in cookie.split(";")[1:]:
            key, _, value = part.strip().partition("=")
            if key:
                attrs[key.lower()] = value.strip()
        # The cookie value and unknown attributes may contain secrets.
        same_site_evidence = attrs.get("samesite", "")
        if same_site_evidence.lower() not in {"lax", "strict", "none"}:
            same_site_evidence = "[không có]" if not same_site_evidence else "[không hợp lệ]"
        evidence = (
            f"Set-Cookie: {name}=<đã ẩn>; "
            f"Secure={'có' if 'secure' in attrs else 'không'}; "
            f"HttpOnly={'có' if 'httponly' in attrs else 'không'}; "
            f"SameSite={same_site_evidence}; "
            f"Path={'/' if attrs.get('path') == '/' else '[khác / hoặc không có]'}; "
            f"Domain={'có' if 'domain' in attrs else 'không'}"
        )

        def add(check: str, title: str, severity: Severity, detail: str, fix: str):
            result.add(check, f"Cookie '{name}' {title}", severity, detail, fix, evidence)

        if "httponly" not in attrs:
            add("cookie-httponly", "thiếu HttpOnly", Severity.MEDIUM,
                "JavaScript có thể đọc cookie này; cookie phiên sẽ dễ bị lộ khi có XSS.",
                "Thêm HttpOnly cho cookie phiên và cookie không cần JavaScript đọc.")
        if "secure" not in attrs:
            add("cookie-secure", "thiếu Secure", Severity.MEDIUM,
                "Cookie có thể được gửi qua HTTP không mã hóa.",
                "Thêm Secure và phục vụ website qua HTTPS.")
        same_site = attrs.get("samesite", "").lower()
        if not same_site:
            add("cookie-samesite", "thiếu SameSite", Severity.LOW,
                "Cookie có thể đi kèm yêu cầu từ website khác, tăng rủi ro CSRF.",
                "Thêm SameSite=Lax hoặc Strict nếu phù hợp luồng đăng nhập.")
        elif same_site not in {"lax", "strict", "none"}:
            add("cookie-samesite-invalid", "có SameSite không hợp lệ", Severity.MEDIUM,
                "Trình duyệt có thể bỏ qua giá trị SameSite này.",
                "Đặt SameSite=Lax, Strict hoặc None theo nhu cầu thực tế.")
        elif same_site == "none" and "secure" not in attrs:
            add("cookie-samesite-none", "dùng SameSite=None thiếu Secure", Severity.MEDIUM,
                "Trình duyệt hiện đại có thể từ chối cookie này.",
                "Thêm Secure khi dùng SameSite=None.")
        if name.startswith("__Host-") and (
            "secure" not in attrs or attrs.get("path") != "/" or "domain" in attrs
        ):
            add("cookie-host-prefix", "vi phạm quy tắc __Host-", Severity.MEDIUM,
                "Cookie __Host- cần Secure, Path=/ và không có Domain.",
                "Đặt Secure; Path=/ và bỏ Domain.")
        if name.startswith("__Secure-") and "secure" not in attrs:
            add("cookie-secure-prefix", "vi phạm quy tắc __Secure-", Severity.MEDIUM,
                "Cookie __Secure- cần cờ Secure.", "Thêm Secure.")
        if "partitioned" in attrs and "secure" not in attrs:
            add("cookie-partitioned", "Partitioned thiếu Secure", Severity.MEDIUM,
                "Cookie Partitioned cần cờ Secure.", "Thêm Secure.")

    if not result.findings:
        result.add("cookies", "Các cookie có cờ bảo vệ cơ bản", Severity.INFO,
                   "Mọi cookie trong phản hồi có HttpOnly, Secure và SameSite hợp lệ.")
    return result
