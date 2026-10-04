"""Small, redacted HTTP observations that can be exported with each finding."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import TYPE_CHECKING
from urllib.parse import parse_qsl, urljoin, urlsplit, urlunsplit

import requests

if TYPE_CHECKING:
    from .scanner import ScanReport


_SAFE_HEADERS = (
    "Content-Type", "Cache-Control", "Strict-Transport-Security",
    "X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy",
    "Permissions-Policy", "Content-Security-Policy", "Server",
    "X-Powered-By", "Access-Control-Allow-Origin",
    "Access-Control-Allow-Credentials", "Access-Control-Allow-Methods",
    "Access-Control-Allow-Headers", "Vary", "Cross-Origin-Resource-Policy",
    "Cross-Origin-Opener-Policy", "Cross-Origin-Embedder-Policy",
)
_SAFE_REQUEST_HEADERS = (
    "Accept", "Origin", "Access-Control-Request-Method",
    "Access-Control-Request-Headers",
)
_KNOWN_HEADER_NAMES = {
    "*",
    "origin", "accept", "accept-encoding", "content-type", "cookie",
    "authorization", "access-control-request-method",
    "access-control-request-headers", "user-agent",
}
_KNOWN_METHODS = {"*", "get", "head", "post", "put", "patch", "delete", "options"}
_SECRET_SEGMENTS = {
    "token", "reset", "secret", "key", "session", "invite", "verify",
    "verification", "activation", "password", "auth",
}
_PURPOSES = {
    "TLS/SSL Configuration": {"site_root"},
    "HTTP to HTTPS Redirect": {"http_redirect"},
    "HTTP Security Headers": {"page"},
    "Content Security Policy": {"page"},
    "Cookie Flags": {"page"},
    "JavaScript Libraries": {"page"},
    "CORS": {"page", "cors_probe", "api_anonymous", "api_cors_probe"},
    "API Access": {"api_anonymous"},
    "API Response Headers": {"api_anonymous"},
    "API CORS Preflight": {"api_preflight"},
    "API Authentication Comparison": {"api_anonymous", "api_authenticated"},
    "API Cross-Account Comparison": {"api_authenticated", "api_second_account"},
    "API CORS Credentialed": {"api_preflight", "api_credentialed_cors"},
    "API CORS Browser": {"api_credentialed_cors"},
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def redact_url(url: str) -> str:
    """Keep the route and query keys but remove credentials and query values."""
    try:
        parsed = urlsplit(url)
        host = parsed.hostname or ""
        if ":" in host:
            host = f"[{host}]"
        if parsed.port is not None:
            host += f":{parsed.port}"
        previous = ""
        segments = []
        for segment in parsed.path.split("/"):
            if (previous.lower() in _SECRET_SEGMENTS
                    or (len(segment) >= 24 and re.search(r"[A-Za-z]", segment)
                        and re.search(r"\d", segment))):
                segments.append("[REDACTED]")
            else:
                segments.append(segment)
            previous = segment
        query_keys = []
        for key, _value in parse_qsl(parsed.query, keep_blank_values=True)[:30]:
            if (not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", key)
                    or (len(key) >= 24 and re.search(r"[A-Za-z]", key)
                        and re.search(r"\d", key))):
                key = "[KEY REDACTED]"
            query_keys.append(f"{key}=[REDACTED]")
        query = "&".join(query_keys)
        return urlunsplit((parsed.scheme, host, "/".join(segments), query, ""))[:2048]
    except ValueError:
        return "[URL REDACTED]"


def _safe_value(value: str, redact_values: list[str] | None = None) -> str:
    value = value.replace("\r", " ").replace("\n", " ")[:1000]
    for secret in sorted((item for item in (redact_values or []) if item), key=len, reverse=True):
        value = value.replace(secret, "[REDACTED]")
    value = re.sub(r"(?i)'nonce-[^']*'", "'nonce-[REDACTED]'", value)
    value = re.sub(
        r"(?i)\b(bearer\s+)[^\s;,]+", r"\1[REDACTED]", value,
    )
    value = re.sub(
        r"(?i)\b(token|secret|api[_-]?key|password|session)\s*[:=]\s*[^\s;,]+",
        r"\1=[REDACTED]", value,
    )
    value = re.sub(
        r"https?://[^\s;,'\"]+", lambda match: redact_url(match.group(0)), value,
    )
    return value[:500] + ("…[truncated]" if len(value) > 500 else "")


def _safe_header_list(value: str, allowed: set[str]) -> str:
    names = [part.strip() for part in value.split(",")[:30]]
    return ", ".join(
        name if name.lower() in allowed else "[OTHER REDACTED]"
        for name in names if name
    )


def _redacted_cookies(response: requests.Response) -> list[str]:
    raw = getattr(response, "raw", None)
    raw_headers = getattr(raw, "headers", None)
    cookies = raw_headers.getlist("Set-Cookie") if hasattr(raw_headers, "getlist") else []
    if not cookies and response.headers.get("Set-Cookie"):
        cookies = [response.headers["Set-Cookie"]]
    sanitized = []
    for cookie in cookies[:20]:
        name = cookie.split("=", 1)[0].strip()[:80]
        if not re.fullmatch(r"[A-Za-z0-9_!#$%&'*+.^`|~-]{1,80}", name):
            name = "[NAME REDACTED]"
        attrs = {}
        for part in cookie.split(";")[1:]:
            key, _, value = part.strip().partition("=")
            attrs[key.lower()] = value.strip()
        flags = [flag for flag in ("Secure", "HttpOnly", "Partitioned")
                 if flag.lower() in attrs]
        same_site = attrs.get("samesite", "").lower()
        if same_site in {"lax", "strict", "none"}:
            flags.append(f"SameSite={same_site.title()}")
        if "path" in attrs:
            flags.append("Path=/" if attrs["path"] == "/" else "Path=[REDACTED]")
        if "domain" in attrs:
            flags.append("Domain=[REDACTED]")
        sanitized.append(f"{name}=[REDACTED]" + ("; " + "; ".join(flags) if flags else ""))
    return sanitized


def snapshot_response(
    response: requests.Response, *, purpose: str, method: str = "GET",
    request_headers: dict[str, str] | None = None,
    credential_mode: str | None = None,
    redact_values: list[str] | None = None,
) -> dict:
    """Capture metadata only; never retain response body or private headers."""
    reflected_values = list(redact_values or [])
    reflected_values.extend(
        value for _key, value in parse_qsl(urlsplit(response.url).query)
        if value
    )
    headers = {
        name: _safe_value(value, reflected_values)
        for name in _SAFE_HEADERS
        if (value := response.headers.get(name)) is not None
    }
    for name in ("Server", "X-Powered-By"):
        if name in headers:
            headers[name] = "[present; value omitted]"
    for name in ("Vary", "Access-Control-Allow-Headers"):
        if value := response.headers.get(name):
            headers[name] = _safe_header_list(value, _KNOWN_HEADER_NAMES)
    if value := response.headers.get("Access-Control-Allow-Methods"):
        headers["Access-Control-Allow-Methods"] = _safe_header_list(
            value, _KNOWN_METHODS,
        )
    if location := response.headers.get("Location"):
        headers["Location"] = redact_url(urljoin(response.url, location))
    if cookies := _redacted_cookies(response):
        headers["Set-Cookie"] = cookies
    selected_request_headers = {
        name: _safe_value(value, reflected_values)
        for name in _SAFE_REQUEST_HEADERS
        if (value := (request_headers or {}).get(name)) is not None
    }
    return {
        "purpose": purpose,
        "observed_at": getattr(response, "websec_observed_at", utc_now()),
        "method": method,
        "url": redact_url(response.url),
        "status_code": response.status_code,
        "request_headers": selected_request_headers,
        "credential_mode": credential_mode,
        "response_headers": headers,
    }


def evidence_bundle(report: ScanReport) -> dict:
    """Map every finding to its relevant redacted HTTP observations."""
    surfaces = [("site", report)] + [("html", page) for page in report.pages] + [
        ("api", endpoint) for endpoint in report.api_endpoints
    ]
    records = []
    for surface, item in surfaces:
        responses = [
            {"id": f"r{index}", **observation}
            for index, observation in enumerate(item.observations, 1)
        ]
        findings = []
        for result in item.results:
            for index, finding in enumerate(result.findings, 1):
                purposes = _PURPOSES.get(result.category, set())
                findings.append({
                    "category": result.category,
                    "check": finding.check,
                    "finding_index": index,
                    "severity": finding.severity.label,
                    "verification": finding.verification.value,
                    "response_ids": [
                        response["id"] for response in responses
                        if response.get("purpose") in purposes
                    ],
                })
        records.append({
            "surface": surface,
            "url": redact_url(item.final_url),
            "responses": responses,
            "findings": findings,
        })
    return {
        "format": "websec-evidence-v1",
        "exported_at": utc_now(),
        "target_url": redact_url(report.url),
        "note": (
            "Only selected response headers and status codes are stored. "
            "Cookie values, Authorization, bodies and query values are omitted. "
            "Findings without response_ids rely on the main report or non-HTTP checks."
        ),
        "surfaces": records,
    }
