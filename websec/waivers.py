"""Time-limited, exact-finding exceptions for local review and CI."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Iterator

from .findings import Finding, Severity
from .scanner import ScanReport
from .targets import InvalidTarget

WAIVER_FORMAT = "websec-waivers-v1"
MAX_WAIVER_BYTES = 10_000_000
MAX_WAIVERS = 1000


def fingerprint(
    target_url: str, surface: str, url: str, category: str, check: str, title: str,
) -> str:
    identity = [target_url, surface, url, category, check, title]
    return hashlib.sha256(
        json.dumps(identity, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


@dataclass(frozen=True)
class FindingRef:
    fingerprint: str
    target_url: str
    surface: str
    url: str
    category: str
    finding: Finding


def finding_refs(report: ScanReport) -> Iterator[FindingRef]:
    def collect(surface: str, url: str, results) -> Iterator[FindingRef]:
        for category in results:
            for finding in category.findings:
                yield FindingRef(
                    fingerprint(
                        report.url, surface, url, category.category,
                        finding.check, finding.title,
                    ),
                    report.url, surface, url, category.category, finding,
                )

    yield from collect("site", report.final_url, report.results)
    for page in report.pages:
        yield from collect("html", page.final_url, page.results)
    for endpoint in report.api_endpoints:
        yield from collect("api", endpoint.final_url, endpoint.results)


def validate_new_waiver(reason: str, expires_on: str) -> tuple[str, str]:
    reason = reason.strip()
    if not reason or len(reason) > 500 or any(ord(char) < 32 and char not in "\n\t" for char in reason):
        raise InvalidTarget("Ngoại lệ cần lý do dài từ 1 đến 500 ký tự.")
    try:
        expiry = date.fromisoformat(expires_on)
    except ValueError as exc:
        raise InvalidTarget("Ngày hết hạn phải ở dạng YYYY-MM-DD.") from exc
    if expiry.isoformat() != expires_on or expiry < datetime.now(timezone.utc).date():
        raise InvalidTarget("Ngày hết hạn ngoại lệ phải từ hôm nay trở đi (UTC).")
    return reason, expires_on


@dataclass(frozen=True)
class Waiver:
    fingerprint: str
    target_url: str
    surface: str
    url: str
    category: str
    check: str
    title: str
    reason: str
    expires_on: str
    created_at: str

    @property
    def active(self) -> bool:
        return date.fromisoformat(self.expires_on) >= datetime.now(timezone.utc).date()

    @classmethod
    def from_finding(cls, ref: FindingRef, reason: str, expires_on: str) -> Waiver:
        reason, expires_on = validate_new_waiver(reason, expires_on)
        if ref.finding.severity == Severity.INFO:
            raise InvalidTarget("Chỉ ghi ngoại lệ cho phát hiện có mức độ rủi ro.")
        return cls(
            ref.fingerprint, ref.target_url, ref.surface, ref.url,
            ref.category, ref.finding.check, ref.finding.title,
            reason, expires_on, datetime.now(timezone.utc).isoformat(timespec="seconds"),
        )

    @classmethod
    def from_dict(cls, value: dict) -> Waiver:
        try:
            waiver = cls(**{name: value[name] for name in cls.__dataclass_fields__})
            if any(not isinstance(item, str) for item in asdict(waiver).values()):
                raise ValueError("non-string field")
            if waiver.surface not in {"site", "html", "api"}:
                raise ValueError("invalid surface")
            if (
                not waiver.reason.strip() or len(waiver.reason) > 500
                or any(ord(char) < 32 and char not in "\n\t" for char in waiver.reason)
            ):
                raise ValueError("invalid reason")
            if date.fromisoformat(waiver.expires_on).isoformat() != waiver.expires_on:
                raise ValueError("invalid expiry format")
            if waiver.fingerprint != fingerprint(
                waiver.target_url, waiver.surface, waiver.url,
                waiver.category, waiver.check, waiver.title,
            ):
                raise ValueError("invalid fingerprint")
            return waiver
        except (KeyError, TypeError, ValueError) as exc:
            raise InvalidTarget("Tệp ngoại lệ không hợp lệ.") from exc


def waiver_payload(waivers: list[Waiver]) -> dict:
    return {"format": WAIVER_FORMAT, "exceptions": [asdict(item) for item in waivers]}


def load_waivers(path: Path) -> dict[str, Waiver]:
    try:
        with path.open("rb") as source:
            raw = source.read(MAX_WAIVER_BYTES + 1)
    except OSError as exc:
        raise InvalidTarget(f"Không đọc được tệp ngoại lệ: {exc}") from exc
    if len(raw) > MAX_WAIVER_BYTES:
        raise InvalidTarget("Tệp ngoại lệ vượt giới hạn 10 MB.")
    try:
        data = json.loads(raw)
        if not isinstance(data, dict) or data.get("format") != WAIVER_FORMAT:
            raise ValueError("invalid format")
        items = data.get("exceptions")
        if not isinstance(items, list) or len(items) > MAX_WAIVERS:
            raise ValueError("invalid count")
        waivers = [Waiver.from_dict(item) for item in items]
        if len({item.fingerprint for item in waivers}) != len(waivers):
            raise ValueError("duplicate fingerprint")
        return {item.fingerprint: item for item in waivers}
    except (ValueError, TypeError, UnicodeError) as exc:
        raise InvalidTarget("Tệp ngoại lệ không phải JSON WebSecAnalyzer hợp lệ.") from exc


def active_waiver_for(issue: dict, target_url: str, waivers: dict[str, Waiver]) -> Waiver | None:
    waiver = waivers.get(issue["fingerprint"])
    return waiver if waiver and waiver.active and waiver.target_url == target_url else None
