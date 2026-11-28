"""Tests for how the terminal report groups a rule's findings."""

from __future__ import annotations

from harness_eval.inspection.types import Finding, Location, RuleCategory, Severity
from harness_eval.output.report import _compress_findings


def _finding(
    severity: Severity, message: str, rule_id: str = "content/broken-references"
) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=severity,
        message=message,
        location=Location(file="SKILL.md"),
        category=RuleCategory.CONTENT,
    )


def test_findings_of_one_rule_are_labelled_by_their_own_severity() -> None:
    lines = _compress_findings(
        [
            _finding(Severity.WARNING, "unverified path"),
            _finding(Severity.ERROR, "broken link"),
        ]
    )

    (warning_line,) = [line for line in lines if "unverified path" in line]
    (error_line,) = [line for line in lines if "broken link" in line]
    assert warning_line.strip().startswith("WARNING")
    assert error_line.strip().startswith("FAIL")


def test_many_findings_of_one_severity_stay_in_one_group() -> None:
    lines = _compress_findings(
        [_finding(Severity.WARNING, f"path {i}") for i in range(3)]
        + [_finding(Severity.ERROR, "broken link")]
    )

    assert sum("3 findings" in line for line in lines) == 1
    assert any(line.strip().startswith("FAIL") and "broken link" in line for line in lines)


def test_info_findings_are_labelled_info() -> None:
    (line,) = _compress_findings([_finding(Severity.INFO, "note")])
    assert line.strip().startswith("INFO")
