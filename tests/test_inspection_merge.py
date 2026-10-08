"""merge_inspection_results keeps distinct findings and the higher severity of a duplicate."""

from __future__ import annotations

from harness_eval.inspection.merge import merge_inspection_results
from harness_eval.inspection.types import (
    Finding,
    InspectionResult,
    Location,
    RuleCategory,
    RuleResult,
    Severity,
)


def _finding(message: str, severity: Severity) -> Finding:
    return Finding(
        rule_id="security/no-credential-access",
        severity=severity,
        message=message,
        location=Location(file="SKILL.md", start_line=3),
        category=RuleCategory.SECURITY,
    )


def _result(*findings: Finding, passed: bool = False) -> InspectionResult:
    return InspectionResult(
        target_path="skills/demo",
        target_name="demo",
        tokens=10,
        target_type="skill",
        diagnostics=list(findings),
        rules_run=[
            RuleResult(rule_id="security/no-credential-access", description="", passed=passed)
        ],
    )


def test_same_rule_keeps_distinct_messages() -> None:
    aws = _finding("References sensitive path '~/.aws/credentials'", Severity.WARNING)
    ssh = _finding("References sensitive path '~/.ssh/'", Severity.WARNING)

    merged = merge_inspection_results([_result(aws)], [_result(ssh)])
    messages = [d.message for d in merged[0].diagnostics]

    assert aws.message in messages
    assert ssh.message in messages
    assert merged[0].warning_count == 2


def test_duplicate_finding_keeps_higher_severity() -> None:
    warning = _finding("auto-approve", Severity.WARNING)
    error = _finding("auto-approve", Severity.ERROR)

    merged = merge_inspection_results(
        [_result(warning, passed=True)],
        [_result(error, passed=False)],
    )

    assert len(merged[0].diagnostics) == 1
    assert merged[0].diagnostics[0].severity == Severity.ERROR
    assert merged[0].error_count == 1
    assert merged[0].rules_run[0].passed is False


def test_merge_does_not_mutate_inputs() -> None:
    original = _result(_finding("one", Severity.WARNING))
    merge_inspection_results([original], [_result(_finding("two", Severity.ERROR))])
    assert len(original.diagnostics) == 1
