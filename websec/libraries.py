"""Detect outdated / known-vulnerable JavaScript libraries.

This parses <script src="..."> tags, extracts a library name and version, and
then checks each detected version two ways:

1. Against the live OSV.dev vulnerability database (real CVEs). Enabled by
   default; degrades gracefully to (2) if the network is unavailable.
2. Against a small curated table of minimum-safe versions (offline fallback).
"""

from __future__ import annotations

import re
from urllib.parse import parse_qs, urlsplit

import requests

from .findings import CheckResult, Severity
from .osv import query_npm
from .control import ScanControl

# library key -> (npm package name, minimum safe version, offline note)
_LIBRARIES: dict[str, tuple[str, tuple[int, ...], str]] = {
    "jquery": ("jquery", (3, 5, 0), "jQuery < 3.5.0 có cảnh báo XSS (CVE-2020-11022/23)."),
    "angular": ("angular", (1, 8, 0), "AngularJS 1.x đã ngừng hỗ trợ."),
    "bootstrap": ("bootstrap", (4, 3, 1), "Bootstrap < 4.3.1 có cảnh báo XSS trong data-*."),
    "lodash": ("lodash", (4, 17, 21), "lodash cũ có nguy cơ prototype pollution."),
    "moment": ("moment", (2, 29, 4), "moment cũ có nguy cơ ReDoS."),
    "vue": ("vue", (2, 7, 0), "Một số bản Vue 2 cũ có cảnh báo XSS/ReDoS."),
    "react": ("react", (16, 0, 0), "React < 16 không còn được hỗ trợ."),
    "handlebars": ("handlebars", (4, 7, 7), "handlebars cũ có nguy cơ prototype pollution."),
    "dompurify": ("dompurify", (2, 4, 0), "DOMPurify cũ có thể bị vượt qua bộ lọc mXSS."),
}

# Matches things like  jquery-3.4.1.min.js  bootstrap.3.3.7.js  vue@2.6.11
_SRC_VERSION_RE = re.compile(
    r"(?P<name>[a-zA-Z][a-zA-Z0-9_\-\.]*?)"
    r"[-@/.]v?(?P<version>\d+\.\d+(?:\.\d+)?)",
)
_SCRIPT_SRC_RE = re.compile(
    r"""<script[^>]*\bsrc\s*=\s*["']([^"']+)["']""", re.IGNORECASE
)
_QUERY_VERSION_RE = re.compile(r"^\d+\.\d+(?:\.\d+)?$")
MAX_LIBRARY_VERSIONS = 20


def _parse_version(text: str) -> tuple[int, ...]:
    return tuple(int(p) for p in text.split("."))


def _known_library(name: str) -> str | None:
    name = name.lower()
    for lib in _LIBRARIES:
        if lib in name:
            return lib
    return None


def _detect_versions(body: str) -> set[tuple[str, tuple[int, ...]]]:
    """Return each distinct known library/version visible in script URLs."""
    seen: set[tuple[str, tuple[int, ...]]] = set()
    for src in _SCRIPT_SRC_RE.findall(body):
        parsed = urlsplit(src)
        for match in _SRC_VERSION_RE.finditer(parsed.path):
            lib = _known_library(match.group("name"))
            if lib is None:
                continue
            try:
                version = _parse_version(match.group("version"))
            except ValueError:
                continue
            seen.add((lib, version))

        lib = _known_library(parsed.path.rsplit("/", 1)[-1])
        if lib:
            query = parse_qs(parsed.query)
            for key in ("ver", "version", "v"):
                for value in query.get(key, []):
                    if _QUERY_VERSION_RE.fullmatch(value):
                        seen.add((lib, _parse_version(value)))
        if len(seen) >= MAX_LIBRARY_VERSIONS:
            break
    return seen


def check_libraries(
    response: requests.Response,
    use_osv: bool = True,
    advisory_cache: dict[tuple[str, str], list | None] | None = None,
    control: ScanControl | None = None,
) -> CheckResult:
    result = CheckResult(category="JavaScript Libraries")
    seen = _detect_versions(response.text)

    for lib, version in sorted(seen)[:MAX_LIBRARY_VERSIONS]:
        if control:
            control.check()
        npm_name, min_safe, note = _LIBRARIES[lib]
        version_str = ".".join(map(str, version))

        advisories = None
        if use_osv:
            cache_key = (npm_name, version_str)
            if advisory_cache is not None and cache_key in advisory_cache:
                advisories = advisory_cache[cache_key]
            else:
                advisories = (
                    query_npm(npm_name, version_str, timeout=control.timeout(8.0))
                    if control else query_npm(npm_name, version_str)
                )
                if control:
                    control.check()
                if advisory_cache is not None:
                    advisory_cache[cache_key] = advisories

        if advisories:
            for adv in advisories:
                sev_note = f" (severity {adv.severity})" if adv.severity else ""
                result.add(
                    check=f"lib-{lib}-{adv.id}",
                    title=f"{lib} {version_str} có cảnh báo {adv.id}{sev_note}",
                    severity=Severity.HIGH,
                    detail=f"Cảnh báo OSV {adv.id}: {adv.summary}",
                    recommendation=f"Nâng cấp {lib} lên phiên bản không bị ảnh hưởng. "
                    f"Chi tiết: https://osv.dev/vulnerability/{adv.id}",
                )
            continue

        # No live advisories (or OSV unavailable/disabled) -> offline heuristic.
        min_str = ".".join(map(str, min_safe))
        if version < min_safe:
            result.add(
                check=f"lib-{lib}",
                title=f"{lib} {version_str} đã cũ",
                severity=Severity.HIGH,
                detail=f"Nhận diện {lib} {version_str}; mốc tham khảo là {min_str}. {note}",
                recommendation=f"Nâng cấp {lib} lên {min_str} hoặc phiên bản mới hơn.",
            )
        else:
            if not use_osv:
                source = f"mốc phiên bản tham khảo >= {min_str}; đã bỏ tra OSV"
            elif advisories is None:
                source = f"mốc phiên bản tham khảo >= {min_str}; chưa tra được OSV"
            else:
                source = "OSV: không thấy cảnh báo đã biết"
            result.add(
                check=f"lib-{lib}",
                title=f"{lib} {version_str}: chưa thấy vấn đề",
                severity=Severity.INFO,
                detail=f"Nhận diện {lib} {version_str} ({source}).",
            )

    if not seen:
        result.add(
            check="libraries",
            title="Không nhận diện được phiên bản thư viện phổ biến",
            severity=Severity.INFO,
            detail="Phiên bản có thể bị ẩn trong bundle hoặc file minified. "
            "Hãy kiểm tra thêm package.json của dự án.",
        )
    return result
