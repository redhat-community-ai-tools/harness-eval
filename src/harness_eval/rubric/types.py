"""Types for rubric issue detection."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class IssueCategory:
    """Definition of an issue category to check for."""

    name: str
    description: str


@dataclass(frozen=True)
class RubricIssue:
    """A single issue found during rubric checking."""

    category: str
    description: str
    evidence: str
    suggestion: str
    severity: str = "warning"
    impact: str = ""


@dataclass
class RubricResult:
    """Complete rubric checking result for a component."""

    component_name: str
    component_type: str
    issues: list[RubricIssue] = field(default_factory=list)
    summary: str = ""
    verdict: str = ""
    # Why the component was not reviewed. An empty `issues` list means "the
    # reviewer found nothing" only when this is empty too.
    error: str = ""

    @property
    def reviewed(self) -> bool:
        return not self.error
