"""Serialization helpers for rubric output."""

from __future__ import annotations

from harness_eval.rubric.types import RubricIssue


def rubric_issue_to_dict(issue: RubricIssue) -> dict[str, str]:
    """Serialize a rubric issue without dropping metadata."""
    return {
        "category": issue.category,
        "description": issue.description,
        "evidence": issue.evidence,
        "suggestion": issue.suggestion,
        "severity": issue.severity,
        "impact": issue.impact,
    }
