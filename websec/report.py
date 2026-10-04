"""Render a ScanReport as colored terminal text or JSON."""

from __future__ import annotations

import json

from .findings import Severity
from .scanner import ScanReport
from .scope import checked_scope

_COLORS = {
    Severity.HIGH: "\033[91m",    # red
    Severity.MEDIUM: "\033[93m",  # yellow
    Severity.LOW: "\033[96m",     # cyan
    Severity.INFO: "\033[92m",    # green
}
_RESET = "\033[0m"
_BOLD = "\033[1m"


def _score_color(score: int) -> str:
    if score >= 85:
        return _COLORS[Severity.INFO]
    if score >= 60:
        return _COLORS[Severity.LOW]
    if score >= 40:
        return _COLORS[Severity.MEDIUM]
    return _COLORS[Severity.HIGH]


def render_text(report: ScanReport, use_color: bool = True) -> str:
    def c(code: str) -> str:
        return code if use_color else ""

    lines: list[str] = []
    lines.append(f"{c(_BOLD)}Scan report for {report.url}{c(_RESET)}")
    if report.final_url != report.url:
        lines.append(f"  Final URL: {report.final_url}")
    lines.append(f"  HTTP status: {report.status_code}")
    overall = report.overall_score
    lines.append(
        f"  {c(_BOLD)}Overall score: "
        f"{c(_score_color(overall))}{overall}/100{c(_RESET)}"
    )
    if report.pages:
        lines.append(
            f"  Pages checked: {len(report.pages)}/{report.max_pages}; "
            f"other discovered URLs not checked: {report.skipped_urls}"
        )
    lines.append(
        f"  Checked scope: {len(report.pages)} HTML page(s), "
        f"{len(report.api_endpoints)}/{report.api_requested} selected API endpoint(s); "
        f"OpenAPI: {report.openapi_status}, {report.api_discovered} operation(s) listed."
    )
    if report.api_auth_mode != "not_configured":
        checked_auth = sum(
            endpoint.api_auth_status_code is not None for endpoint in report.api_endpoints
        )
        lines.append(
            f"  Test-account API checks: {checked_auth}/{report.api_auth_requested} "
            f"expected-private endpoint(s); mode: {report.api_auth_mode}."
        )
        if report.api_auth_skipped_paths:
            lines.append(
                "  Test-account paths not checked: "
                + ", ".join(report.api_auth_skipped_paths)
            )
    if report.api_requested:
        preflight_checked = sum(
            endpoint.api_cors_preflight_status_code is not None
            for endpoint in report.api_endpoints
        )
        credentialed_checked = sum(
            endpoint.api_cors_credentialed_status_code is not None
            for endpoint in report.api_endpoints
        )
        lines.append(
            f"  API CORS preflight: {preflight_checked}/{report.api_requested}; "
            f"test-session Origin GET: {credentialed_checked}/{report.api_auth_requested}."
        )
    if report.api_cors_browser_enabled:
        browser_checked = sum(
            endpoint.api_cors_browser_outcome not in {None, "inconclusive"}
            for endpoint in report.api_endpoints
        )
        lines.append(
            f"  Browser CORS check: {browser_checked}/{report.api_cors_browser_requested} "
            "selected private endpoint(s)."
        )
        if report.api_cors_browser_skipped_paths:
            lines.append(
                "  Browser CORS paths inconclusive: "
                + ", ".join(report.api_cors_browser_skipped_paths)
            )
    if report.api_compare_requested:
        compared = sum(bool(endpoint.api_compared_pointers) for endpoint in report.api_endpoints)
        lines.append(
            f"  Cross-account JSON checks: {compared}/{report.api_compare_requested} "
            "selected private endpoint(s)."
        )
        if report.api_compare_skipped_paths:
            lines.append(
                "  Cross-account paths not fully compared: "
                + ", ".join(report.api_compare_skipped_paths)
            )
    lines.append("  Score basis: weakest checked HTML page or selected API endpoint, including site-wide checks.")
    if report.api_skipped_paths:
        lines.append("  Selected API paths not checked: " + ", ".join(report.api_skipped_paths))
    if not report.api_requested:
        lines.append("  API access control was not tested.")
    lines.append("")

    def append_results(results):
        for result in results:
            header = f"[{result.category}]"
            if result.error:
                lines.append(f"{c(_BOLD)}{header}{c(_RESET)} inconclusive: {result.error}")
                lines.append("")
                continue
            lines.append(
                f"{c(_BOLD)}{header}{c(_RESET)} "
                f"score {c(_score_color(result.score))}{result.score}/100{c(_RESET)}"
            )
            for finding in result.findings:
                tag = (
                    f"{c(_COLORS[finding.severity])}"
                    f"{finding.severity.label:<6}{c(_RESET)}"
                )
                lines.append(f"  {tag} {finding.title} [{finding.verification.label}]")
                lines.append(f"         {finding.detail}")
                if finding.recommendation:
                    lines.append(f"         -> {finding.recommendation}")
                if finding.evidence:
                    lines.append(f"         Evidence: {finding.evidence}")
            lines.append("")

    if report.pages or report.api_endpoints:
        lines.append("Website-wide checks:")
        append_results(report.results)
        for index, page in enumerate(report.pages, 1):
            lines.append(
                f"Page {index}: {page.final_url} (HTTP {page.status_code}, "
                f"score {report.page_score(page)}/100)"
            )
            append_results(page.results)
        for index, endpoint in enumerate(report.api_endpoints, 1):
            auth_note = (
                f", test account HTTP {endpoint.api_auth_status_code}"
                if endpoint.api_auth_status_code is not None else ""
            )
            second_note = (
                f", account B HTTP {endpoint.api_second_auth_status_code}"
                if endpoint.api_second_auth_status_code is not None else ""
            )
            preflight_note = (
                f", OPTIONS HTTP {endpoint.api_cors_preflight_status_code}"
                if endpoint.api_cors_preflight_status_code is not None else ""
            )
            cors_note = (
                f", test-session Origin GET HTTP {endpoint.api_cors_credentialed_status_code}"
                if endpoint.api_cors_credentialed_status_code is not None else ""
            )
            browser_note = (
                f", browser CORS {endpoint.api_cors_browser_outcome}"
                if endpoint.api_cors_browser_outcome else ""
            )
            lines.append(
                f"API endpoint {index}: {endpoint.final_url} "
                f"(anonymous HTTP {endpoint.status_code}{auth_note}{second_note}"
                f"{preflight_note}{cors_note}{browser_note}, "
                f"score {report.page_score(endpoint)}/100)"
            )
            append_results(endpoint.results)
    else:
        append_results(report.results)

    return "\n".join(lines)


def to_dict(report: ScanReport) -> dict:
    """Serialize a ScanReport into a plain dict (JSON-ready)."""
    return {
        "url": report.url,
        "final_url": report.final_url,
        "status_code": report.status_code,
        "api_expect_auth": report.api_expect_auth,
        "api_auth_status_code": report.api_auth_status_code,
        "api_second_auth_status_code": report.api_second_auth_status_code,
        "api_cors_preflight_status_code": report.api_cors_preflight_status_code,
        "api_cors_credentialed_status_code": report.api_cors_credentialed_status_code,
        "api_cors_browser_outcome": report.api_cors_browser_outcome,
        "api_compared_pointers": report.api_compared_pointers,
        "overall_score": report.overall_score,
        "max_pages": report.max_pages,
        "skipped_urls": report.skipped_urls,
        "page_count": len(report.pages) if report.pages else 1,
        "api_endpoint_count": len(report.api_endpoints),
        "pages": [to_dict(page) for page in report.pages],
        "api_endpoints": [to_dict(endpoint) for endpoint in report.api_endpoints],
        "api_routes": report.api_routes,
        "coverage": {
            "score_basis": "weakest_checked_url_including_site_checks",
            "checked_urls": checked_scope(report),
            "html_pages_checked": len(report.pages),
            "html_page_limit": report.max_pages,
            "html_urls_not_checked": report.skipped_urls,
            "api_routes_discovered": report.api_discovered,
            "api_endpoints_requested": report.api_requested,
            "api_selected_paths": report.api_selected_paths,
            "api_endpoints_checked": len(report.api_endpoints),
            "api_endpoints_skipped": report.api_skipped,
            "api_endpoints_skipped_paths": report.api_skipped_paths,
            "api_auth_mode": report.api_auth_mode,
            "api_authenticated_requested": report.api_auth_requested,
            "api_authenticated_checked": sum(
                endpoint.api_auth_status_code is not None
                for endpoint in report.api_endpoints
            ),
            "api_authenticated_skipped_paths": report.api_auth_skipped_paths,
            "api_cors_preflight_requested": report.api_requested,
            "api_cors_preflight_checked": sum(
                endpoint.api_cors_preflight_status_code is not None
                for endpoint in report.api_endpoints
            ),
            "api_cors_preflight_skipped_paths": report.api_cors_preflight_skipped_paths,
            "api_cors_credentialed_requested": report.api_auth_requested,
            "api_cors_credentialed_checked": sum(
                endpoint.api_cors_credentialed_status_code is not None
                for endpoint in report.api_endpoints
            ),
            "api_cors_credentialed_skipped_paths": report.api_cors_credentialed_skipped_paths,
            "api_cors_browser_enabled": report.api_cors_browser_enabled,
            "api_cors_browser_requested": report.api_cors_browser_requested,
            "api_cors_browser_checked": sum(
                endpoint.api_cors_browser_outcome not in {None, "inconclusive"}
                for endpoint in report.api_endpoints
            ),
            "api_cors_browser_skipped_paths": report.api_cors_browser_skipped_paths,
            "api_cross_account_requested": report.api_compare_requested,
            "api_cross_account_checked": sum(
                bool(endpoint.api_compared_pointers) for endpoint in report.api_endpoints
            ),
            "api_cross_account_skipped_paths": report.api_compare_skipped_paths,
            "openapi_status": report.openapi_status,
        },
        "categories": [
            {
                "category": r.category,
                "score": None if r.error else r.score,
                "error": r.error,
                "verification": "inconclusive" if r.error else "completed",
                "findings": [
                    {
                        "check": f.check,
                        "title": f.title,
                        "severity": f.severity.label,
                        "detail": f.detail,
                        "recommendation": f.recommendation,
                        "evidence": f.evidence,
                        "verification": f.verification.value,
                    }
                    for f in r.findings
                ],
            }
            for r in report.results
        ],
    }


def render_json(report: ScanReport) -> str:
    return json.dumps(to_dict(report), indent=2, ensure_ascii=False)
