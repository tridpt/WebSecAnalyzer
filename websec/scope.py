"""Exact checked URL inventory shared by reports and the CI scope gate."""

from __future__ import annotations

from .scanner import ScanReport


ScopeValue = str | bool | int | list[str] | None
ScopeEntry = dict[str, ScopeValue]


def checked_scope(report: ScanReport) -> dict[str, list[ScopeEntry]]:
    """Keep requested and final URLs so changed redirects also change scope."""
    def entry(item: ScanReport) -> dict[str, str]:
        return {"requested_url": item.url, "final_url": item.final_url}

    return {
        "site": [entry(report)],
        "html": [entry(page) for page in report.pages],
        "api": [
            {
                **entry(endpoint),
                "expects_authentication": endpoint.api_expect_auth,
                "authenticated_status_code": endpoint.api_auth_status_code,
                "second_account_status_code": endpoint.api_second_auth_status_code,
                "cors_preflight_status_code": endpoint.api_cors_preflight_status_code,
                "cors_credentialed_status_code": endpoint.api_cors_credentialed_status_code,
                "cors_browser_outcome": endpoint.api_cors_browser_outcome,
                "compared_pointers": endpoint.api_compared_pointers,
            }
            for endpoint in report.api_endpoints
        ],
    }


def missing_baseline_scope(old: ScanReport, new: ScanReport) -> list[ScopeEntry]:
    """Return every previously checked surface absent from the new scan."""
    old_scope = checked_scope(old)
    new_scope = checked_scope(new)
    missing: list[ScopeEntry] = []
    for surface in ("site", "html", "api"):
        current = {
            (entry["requested_url"], entry["final_url"]): entry
            for entry in new_scope[surface]
        }
        for entry in old_scope[surface]:
            matched = current.get((entry["requested_url"], entry["final_url"]))
            if matched is None:
                missing.append({"surface": surface, **entry})
                continue
            if surface != "api":
                continue
            old_auth_status = entry.get("authenticated_status_code")
            new_auth_status = matched.get("authenticated_status_code")
            old_pointers = entry.get("compared_pointers")
            new_pointers = matched.get("compared_pointers")
            old_preflight = entry.get("cors_preflight_status_code")
            new_preflight = matched.get("cors_preflight_status_code")
            old_credentialed_cors = entry.get("cors_credentialed_status_code")
            new_credentialed_cors = matched.get("cors_credentialed_status_code")
            old_browser = entry.get("cors_browser_outcome")
            new_browser = matched.get("cors_browser_outcome")
            if (
                entry.get("expects_authentication") is True
                and matched.get("expects_authentication") is not True
            ) or (
                isinstance(old_auth_status, int)
                and (
                    not isinstance(new_auth_status, int)
                    or (200 <= old_auth_status < 300 and not 200 <= new_auth_status < 300)
                )
            ) or (
                isinstance(old_pointers, list)
                and bool(old_pointers)
                and (
                    not isinstance(new_pointers, list)
                    or any(pointer not in new_pointers for pointer in old_pointers)
                )
            ) or (
                isinstance(old_preflight, int) and not isinstance(new_preflight, int)
            ) or (
                isinstance(old_credentialed_cors, int)
                and not isinstance(new_credentialed_cors, int)
            ) or (
                old_browser in {"readable", "blocked", "cookie_not_sent"}
                and new_browser not in {"readable", "blocked", "cookie_not_sent"}
            ):
                missing.append({"surface": surface, **entry})
    for path in old.api_selected_paths:
        if path not in new.api_selected_paths or path in new.api_skipped_paths:
            missing.append({
                "surface": "api_selected", "requested_url": path, "final_url": path,
            })
    return missing
