"""Tests for the scoring / severity model."""

from __future__ import annotations

from websec.findings import CheckResult, Severity


def test_severity_penalties_are_ordered():
    assert Severity.INFO.penalty == 0
    assert Severity.LOW.penalty < Severity.MEDIUM.penalty < Severity.HIGH.penalty


def test_empty_result_scores_100():
    result = CheckResult(category="x")
    assert result.score == 100


def test_score_subtracts_penalties():
    result = CheckResult(category="x")
    result.add("a", "t", Severity.HIGH, "d")     # -20
    result.add("b", "t", Severity.MEDIUM, "d")   # -10
    result.add("c", "t", Severity.LOW, "d")      # -4
    assert result.score == 100 - 20 - 10 - 4


def test_score_never_negative():
    result = CheckResult(category="x")
    for _ in range(10):
        result.add("a", "t", Severity.HIGH, "d")  # 10 * -20 = -200
    assert result.score == 0


def test_info_findings_do_not_lower_score():
    result = CheckResult(category="x")
    result.add("a", "t", Severity.INFO, "d")
    assert result.score == 100


def test_severity_label():
    assert Severity.HIGH.label == "HIGH"
    assert Severity.INFO.label == "INFO"
