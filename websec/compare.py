"""Compare actionable findings between two scans."""

from __future__ import annotations

from .scanner import ScanReport
from .waivers import fingerprint


def _checked_surfaces(report: ScanReport) -> set[tuple[str, str]]:
    return (
        {("site", report.final_url)}
        | {("html", page.final_url) for page in report.pages}
        | {("api", endpoint.final_url) for endpoint in report.api_endpoints}
    )


def _issues(report: ScanReport) -> dict[tuple[str, str, str, str, str], dict]:
    issues: dict[tuple[str, str, str, str, str], dict] = {}

    def collect(surface: str, location: str, results) -> None:
        for category in results:
            for finding in category.findings:
                if finding.severity.name == "INFO":
                    continue
                key = (surface, location, category.category, finding.check, finding.title)
                issues[key] = {
                    "url": location, "surface": surface, "category": category.category,
                    "check": finding.check, "title": finding.title,
                    "fingerprint": fingerprint(
                        report.url, surface, location, category.category,
                        finding.check, finding.title,
                    ),
                    "severity": finding.severity.name,
                    "detail": finding.detail,
                    "recommendation": finding.recommendation,
                    "evidence": finding.evidence,
                    "verification": finding.verification.value,
                }

    collect("site", report.final_url, report.results)
    for page in report.pages:
        collect("html", page.final_url, page.results)
    for endpoint in report.api_endpoints:
        collect("api", endpoint.final_url, endpoint.results)
    return issues


def compare_reports(old: ScanReport, new: ScanReport) -> dict:
    before = _issues(old)
    after = _issues(new)
    old_scope = _checked_surfaces(old)
    new_scope = _checked_surfaces(new)
    rechecked = {key for key in before.keys() - after.keys() if key[:2] in new_scope}
    return {
        "old_url": old.url, "new_url": new.url,
        "old_score": old.overall_score, "new_score": new.overall_score,
        "scope_changed": old_scope != new_scope,
        "old_html_count": len(old.pages), "new_html_count": len(new.pages),
        "old_api_count": len(old.api_endpoints), "new_api_count": len(new.api_endpoints),
        "new_issues": [after[key] for key in sorted(after.keys() - before.keys())],
        "fixed_issues": [before[key] for key in sorted(rechecked)],
        "not_rechecked_count": len(before.keys() - after.keys() - rechecked),
        "unchanged_count": len(before.keys() & after.keys()),
    }


def new_high_issues(old: ScanReport, new: ScanReport) -> list[dict]:
    """High findings absent from the old scan's high findings.

    A finding promoted from medium/low to high is treated as newly high.
    The identity uses surface, URL, category, check and title, as in the UI comparison.
    """
    before = _issues(old)
    after = _issues(new)
    return [
        after[key]
        for key in sorted(after)
        if after[key]["severity"] == "HIGH"
        and (key not in before or before[key]["severity"] != "HIGH")
    ]
