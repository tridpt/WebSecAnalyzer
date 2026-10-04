"""Shared data structures for findings and severity levels."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, IntEnum


class Severity(IntEnum):
    """Severity of a finding. Higher value = more severe."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3

    @property
    def label(self) -> str:
        return self.name

    @property
    def penalty(self) -> int:
        """Points subtracted from the 100-point score per finding."""
        return {
            Severity.INFO: 0,
            Severity.LOW: 4,
            Severity.MEDIUM: 10,
            Severity.HIGH: 20,
        }[self]


class Verification(str, Enum):
    """How directly the scanner established an observation."""

    OBSERVED = "observed"
    SUSPECTED = "suspected"
    INCONCLUSIVE = "inconclusive"

    @property
    def label(self) -> str:
        return {
            Verification.OBSERVED: "Có bằng chứng",
            Verification.SUSPECTED: "Nghi ngờ",
            Verification.INCONCLUSIVE: "Không kết luận được",
        }[self]


def infer_verification(category: str, check: str, title: str) -> Verification:
    """Conservative defaults for current checks and reports saved before this field."""
    if check in {"tls-legacy-unknown", "lockfile-osv-unavailable", "api-auth-inconclusive"}:
        return Verification.INCONCLUSIVE
    if check == "https-redirect" and ("Không xác định" in title or "Bỏ qua" in title):
        return Verification.INCONCLUSIVE
    if category == "JavaScript Libraries":
        return Verification.INCONCLUSIVE if check == "libraries" else Verification.SUSPECTED
    if check in {"api-auth-missing", "api-auth-review", "api-cache", "tls-legacy-rejected"}:
        return Verification.SUSPECTED
    directly_observed = {
        "TLS/SSL Configuration", "HTTP to HTTPS Redirect", "HTTP Security Headers",
        "Content Security Policy", "CORS", "Cookie Flags", "npm Lockfile / OSV",
        "API Access", "API Response Headers",
    }
    return Verification.OBSERVED if category in directly_observed else Verification.SUSPECTED


@dataclass
class Finding:
    """A single security observation."""

    check: str
    title: str
    severity: Severity
    detail: str
    recommendation: str = ""
    evidence: str = ""
    verification: Verification = Verification.SUSPECTED


@dataclass
class CheckResult:
    """Result of one category of checks (e.g. headers)."""

    category: str
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None

    def add(
        self,
        check: str,
        title: str,
        severity: Severity,
        detail: str,
        recommendation: str = "",
        evidence: str = "",
        verification: Verification | None = None,
    ) -> None:
        self.findings.append(
            Finding(
                check, title, severity, detail, recommendation, evidence,
                verification or infer_verification(self.category, check, title),
            )
        )

    @property
    def score(self) -> int:
        """0-100 score for this category based on finding penalties."""
        score = 100 - sum(f.severity.penalty for f in self.findings)
        return max(0, score)
