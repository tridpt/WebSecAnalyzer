"""Explicit, read-only HTML targets for scans with a test session."""

from __future__ import annotations

from .api import _safe_path
from .findings import CheckResult
from .targets import InvalidTarget

MAX_AUTH_HTML_PAGES = 10


def parse_auth_html_paths(lines: list[str] | None) -> list[str]:
    if lines is not None and len(lines) > 100:
        raise InvalidTarget("Danh sách trang sau đăng nhập quá dài.")
    paths: list[str] = []
    for raw in lines or []:
        if not raw.strip():
            continue
        path = _safe_path(raw, label="Trang HTML")
        if path not in paths:
            paths.append(path)
        if len(paths) > MAX_AUTH_HTML_PAGES:
            raise InvalidTarget(
                f"Chỉ quét tối đa {MAX_AUTH_HTML_PAGES} trang sau đăng nhập mỗi lượt."
            )
    return paths


def redact_result_values(results: list[CheckResult], values: list[str]) -> None:
    """Do not persist a test secret reflected in response headers or HTML."""
    for result in results:
        if result.error:
            for value in values:
                result.error = result.error.replace(value, "[REDACTED]")
        for finding in result.findings:
            for field in ("title", "detail", "recommendation", "evidence", "impact"):
                text = getattr(finding, field)
                for value in values:
                    text = text.replace(value, "[REDACTED]")
                setattr(finding, field, text)
