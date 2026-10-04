"""Query the OSV.dev vulnerability database for JS library versions.

OSV.dev is a free, open vulnerability database (no API key required).
We query the npm ecosystem for a given package + version and return any
known advisories. Network failures degrade gracefully (return empty).

API: https://google.github.io/osv.dev/post-v1-query/
"""

from __future__ import annotations

from dataclasses import dataclass

import requests

_OSV_QUERY_URL = "https://api.osv.dev/v1/query"


@dataclass
class Advisory:
    id: str
    summary: str
    severity: str  # OSV severity string, may be "" if not provided


def query_npm(package: str, version: str, timeout: float = 10.0) -> list[Advisory] | None:
    """Return known advisories for an npm package at a specific version.

    Returns None on a network/parse error so callers can distinguish an
    unavailable lookup from a successful query with no advisories.
    """
    payload = {
        "version": version,
        "package": {"name": package, "ecosystem": "npm"},
    }
    try:
        resp = requests.post(_OSV_QUERY_URL, json=payload, timeout=timeout)
        resp.raise_for_status()
        data = resp.json()
    except (requests.RequestException, ValueError):
        return None

    advisories: list[Advisory] = []
    for vuln in data.get("vulns", []):
        advisories.append(
            Advisory(
                id=vuln.get("id", "UNKNOWN"),
                summary=vuln.get("summary")
                or (vuln.get("details", "")[:120] if vuln.get("details") else "")
                or "No summary provided.",
                severity=_extract_severity(vuln),
            )
        )
    return advisories


def _extract_severity(vuln: dict) -> str:
    # OSV puts CVSS under "severity"; database_specific sometimes has a label.
    sev = vuln.get("severity")
    if sev and isinstance(sev, list):
        for entry in sev:
            if entry.get("score"):
                return str(entry["score"])
    db = vuln.get("database_specific", {})
    if isinstance(db, dict) and db.get("severity"):
        return str(db["severity"])
    return ""
