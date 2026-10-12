"""Passive checks of resource URLs declared in an HTML response."""

from __future__ import annotations

from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

import requests

from .evidence import redact_url
from .fetch import origin
from .findings import CheckResult, Severity


def _upgrades_http(policy: str) -> bool:
    return any(
        part.strip().lower() == "upgrade-insecure-requests"
        for part in policy.split(";")
    )


class _Resources(HTMLParser):
    def __init__(self, page_url: str, upgrade_http: bool) -> None:
        super().__init__(convert_charrefs=True)
        self.base_url = page_url
        self.base_seen = False
        self.upgrade_http = upgrade_http
        self.resources: list[tuple[str, str, str, bool, bool]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        attributes = {key.lower(): value for key, value in attrs if value is not None}
        if tag == "base" and not self.base_seen and attributes.get("href"):
            self.base_seen = True
            try:
                candidate = urljoin(self.base_url, attributes["href"].strip())
                parsed = urlsplit(candidate)
                parsed.port  # A malformed port makes the base URL unusable.
                if parsed.scheme.lower() in {"http", "https"} and parsed.hostname:
                    self.base_url = candidate
            except ValueError:
                pass
            return
        if tag == "meta" and attributes.get("http-equiv", "").lower() == "content-security-policy":
            self.upgrade_http |= _upgrades_http(attributes.get("content", ""))
            return

        attribute = "src"
        if tag == "link":
            rel = set(attributes.get("rel", "").lower().split())
            as_type = attributes.get("as", "").lower()
            if "stylesheet" not in rel and not ("preload" in rel and as_type in {"script", "style"}):
                return
            attribute = "href"
        elif tag == "object":
            attribute = "data"
        elif tag == "form":
            attribute = "action"
        elif tag not in {"script", "iframe", "embed", "img", "audio", "video", "source"}:
            return

        raw_url = attributes.get(attribute, "").strip()
        if not raw_url:
            return
        try:
            url = urljoin(self.base_url, raw_url)
            parsed = urlsplit(url)
            if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
                return
            parsed.port  # Reject malformed ports before origin() sees them.
        except ValueError:
            return
        has_integrity = bool(attributes.get("integrity", "").strip())
        self.resources.append((tag, attribute, url, self.upgrade_http, has_integrity))


def _add_group(
    result: CheckResult, check: str, title: str, severity: Severity,
    description: str, recommendation: str, matches: list[str],
) -> None:
    if not matches:
        return
    examples = list(dict.fromkeys(matches))[:5]
    extra = f"; còn {len(matches) - 5} mục" if len(matches) > 5 else ""
    result.add(
        check, title, severity,
        f"{description} Tìm thấy {len(matches)} khai báo trong HTML.",
        recommendation,
        "Khai báo HTML: " + "; ".join(examples) + extra,
    )


def check_html_resources(response: requests.Response) -> CheckResult:
    """Inspect static HTML declarations without requesting their destinations."""
    result = CheckResult(category="HTML Resource Security")
    page_url = getattr(response, "url", "")
    if urlsplit(page_url).scheme.lower() != "https":
        result.add(
            "html-resources-https-only", "Kiểm tra tài nguyên yêu cầu trang HTTPS",
            Severity.INFO, "Trang hiện không dùng HTTPS; kiểm tra HTTPS riêng đã ghi nhận điều này.",
        )
        return result

    parser = _Resources(
        page_url, _upgrades_http(response.headers.get("Content-Security-Policy", "")),
    )
    parser.feed(response.text)
    active: list[str] = []
    passive: list[str] = []
    forms: list[str] = []
    no_sri: list[str] = []
    seen: set[tuple[str, str, str]] = set()
    page_origin = origin(page_url)
    for tag, attribute, url, upgraded, has_integrity in parser.resources:
        marker = (tag, attribute, url)
        if marker in seen:
            continue
        seen.add(marker)
        scheme = urlsplit(url).scheme.lower()
        display = f"<{tag} {attribute}> {redact_url(url)[:350]}"
        if scheme == "http":
            if tag == "form" and not upgraded:
                forms.append(display)
            elif not upgraded:
                (passive if tag in {"img", "audio", "video", "source"} else active).append(display)
        elif tag == "script" and origin(url) != page_origin and not has_integrity:
            no_sri.append(display)

    _add_group(
        result, "mixed-content-active", "Tài nguyên chủ động qua HTTP trên trang HTTPS",
        Severity.MEDIUM,
        "Script, stylesheet hoặc nội dung nhúng có URL HTTP; trình duyệt có thể chặn tải hoặc làm yếu kết nối.",
        "Đổi URL tài nguyên sang HTTPS và xác nhận đích tải hỗ trợ HTTPS.", active,
    )
    _add_group(
        result, "mixed-content-passive", "Tài nguyên qua HTTP trên trang HTTPS",
        Severity.LOW,
        "Ảnh hoặc media có URL HTTP; trình duyệt có thể tự nâng cấp hoặc chặn tải.",
        "Đổi URL ảnh/media sang HTTPS.", passive,
    )
    _add_group(
        result, "insecure-form-action", "Biểu mẫu trên HTTPS khai báo action HTTP",
        Severity.MEDIUM,
        "Action khai báo URL HTTP; dữ liệu gửi có thể lộ trên đường truyền.",
        "Đổi action sang endpoint HTTPS và kiểm tra mọi bước chuyển hướng sau khi gửi.", forms,
    )
    _add_group(
        result, "external-script-no-sri", "Script bên thứ ba thiếu Subresource Integrity",
        Severity.LOW,
        "Script HTTPS khác origin không khai báo integrity; đây là lớp bảo vệ bổ sung khi nguồn script bị thay đổi.",
        "Nếu URL script có phiên bản cố định, thêm integrity với hash SHA-384/512 và crossorigin phù hợp; "
        "hoặc tự lưu trữ script. Cập nhật hash mỗi khi đổi phiên bản.", no_sri,
    )
    if not result.findings:
        result.add(
            "html-resources-ok", "Chưa thấy khai báo tài nguyên yếu trong HTML",
            Severity.INFO,
            "Đã xem URL trong các thẻ HTML được hỗ trợ; chưa kiểm tra URL tạo lúc chạy JavaScript, CSS hoặc chuyển hướng của tài nguyên.",
        )
    return result
