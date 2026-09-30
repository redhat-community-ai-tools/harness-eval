"""Tests for JSON and terminal serialization of rubric review results."""

from __future__ import annotations

import json
from dataclasses import asdict, fields

from harness_eval.cli.review import _format_json_review
from harness_eval.cli.security import _format_json_security, _SecurityReport
from harness_eval.output.metadata import EvalMetadata
from harness_eval.rubric.output import format_rubric_issue_lines, rubric_issue_to_dict
from harness_eval.rubric.types import RubricIssue, RubricResult


def _issue() -> RubricIssue:
    return RubricIssue(
        category="specificity",
        description="Instructions are vague",
        evidence="line 3",
        suggestion="Add a concrete example",
        severity="error",
        impact="The command fails at runtime",
    )


def _result() -> RubricResult:
    return RubricResult(
        component_name="code-review",
        component_type="skill",
        issues=[_issue()],
        summary="One broken instruction",
        verdict="REVIEW",
    )


def test_rubric_issue_to_dict_includes_every_field() -> None:
    issue = _issue()

    assert rubric_issue_to_dict(issue) == asdict(issue)
    assert set(rubric_issue_to_dict(issue)) == {field.name for field in fields(RubricIssue)}


def test_review_json_preserves_rubric_issue_severity() -> None:
    data = json.loads(_format_json_review("sample-setup", 1, [_result()], EvalMetadata()))

    assert data["rubric"][0]["issues"][0] == rubric_issue_to_dict(_issue())
    assert data["rubric"][0]["summary"] == "One broken instruction"
    assert data["rubric"][0]["verdict"] == "REVIEW"


def test_security_json_preserves_rubric_issue_severity() -> None:
    report = _SecurityReport(
        setup_name="sample-setup",
        risk="CAUTION",
        adjudicated=False,
        results=[],
        adjudication_map={},
        rubric_results=[_result()],
        skip_notices=[],
        metadata=EvalMetadata(),
        effective_errors=0,
        effective_warnings=0,
        false_positive_count=0,
        downgraded_count=0,
    )

    data = json.loads(_format_json_security(report))

    assert data["semantic_review"][0]["issues"][0] == rubric_issue_to_dict(_issue())


def test_format_rubric_issue_lines_includes_severity() -> None:
    lines = format_rubric_issue_lines(_issue(), indent="    ")

    assert lines[0] == "    FAIL     [specificity] Instructions are vague"
    assert "      Evidence: line 3" in lines
    assert "      Impact: The command fails at runtime" in lines


def test_format_rubric_issue_lines_omits_empty_impact() -> None:
    issue = RubricIssue(
        category="redundancy",
        description="Restates git defaults",
        evidence="Always commit",
        suggestion="Remove it",
        severity="info",
    )

    lines = format_rubric_issue_lines(issue, indent="  ")

    assert lines[0] == "  INFO     [redundancy] Restates git defaults"
    assert all("Impact:" not in line for line in lines)
