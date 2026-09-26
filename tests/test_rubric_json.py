"""Tests for JSON serialization of rubric review results."""

from __future__ import annotations

import json

from harness_eval.cli.security import _format_json_security, _SecurityReport
from harness_eval.output.metadata import EvalMetadata
from harness_eval.rubric.types import RubricIssue, RubricResult


def test_security_json_preserves_rubric_issue_severity() -> None:
    report = _SecurityReport(
        setup_name="sample-setup",
        risk="CAUTION",
        adjudicated=False,
        results=[],
        adjudication_map={},
        rubric_results=[
            RubricResult(
                component_name="code-review",
                component_type="skill",
                issues=[
                    RubricIssue(
                        category="specificity",
                        description="Instructions are vague",
                        evidence="line 3",
                        suggestion="Add a concrete example",
                        severity="error",
                    )
                ],
            )
        ],
        skip_notices=[],
        metadata=EvalMetadata(),
        effective_errors=0,
        effective_warnings=0,
        false_positive_count=0,
        downgraded_count=0,
    )

    data = json.loads(_format_json_security(report))

    assert data["semantic_review"][0]["issues"][0]["severity"] == "error"
