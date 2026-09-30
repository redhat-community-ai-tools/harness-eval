"""Serialization helpers for rubric output."""

from __future__ import annotations

from dataclasses import asdict
from typing import cast

from harness_eval.rubric.types import RubricIssue


def rubric_issue_to_dict(issue: RubricIssue) -> dict[str, str]:
    """Serialize a rubric issue, including every dataclass field."""
    return cast(dict[str, str], asdict(issue))


def format_rubric_issue_lines(issue: RubricIssue, *, indent: str) -> list[str]:
    """Terminal lines for one rubric issue, including its severity."""
    if issue.severity == "error":
        label = "FAIL"
    elif issue.severity == "info":
        label = "INFO"
    else:
        label = "WARNING"
    detail = f"{indent}  "
    lines = [
        f"{indent}{label:<8} [{issue.category}] {issue.description}",
        f"{detail}Evidence: {issue.evidence}",
        f"{detail}Fix: {issue.suggestion}",
    ]
    if issue.impact:
        lines.append(f"{detail}Impact: {issue.impact}")
    return lines
