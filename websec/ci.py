"""Load a prior JSON report as a CI baseline."""

from __future__ import annotations

import json
from pathlib import Path

from .scanner import ScanReport
from .targets import InvalidTarget

MAX_BASELINE_BYTES = 10_000_000


def load_baseline(path: Path) -> ScanReport:
    try:
        with path.open("rb") as source:
            raw = source.read(MAX_BASELINE_BYTES + 1)
    except OSError as exc:
        raise InvalidTarget(f"Không đọc được báo cáo gốc: {exc}") from exc
    if len(raw) > MAX_BASELINE_BYTES:
        raise InvalidTarget("Báo cáo gốc vượt giới hạn 10 MB.")
    try:
        data = json.loads(raw)
        if not isinstance(data, dict) or not isinstance(data.get("categories"), list):
            raise ValueError("missing categories")
        if not isinstance(data.get("pages", []), list):
            raise ValueError("invalid pages")
        if not isinstance(data.get("url"), str) or not data["url"]:
            raise ValueError("invalid URL")
        return ScanReport.from_dict(data)
    except (ValueError, TypeError, KeyError, UnicodeError) as exc:
        raise InvalidTarget("Báo cáo gốc không phải JSON WebSecAnalyzer hợp lệ.") from exc
