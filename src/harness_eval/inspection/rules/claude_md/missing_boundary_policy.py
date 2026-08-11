from __future__ import annotations

import re

from harness_eval.core.types import ComponentType
from harness_eval.inspection.types import (
    Location,
    ReportDescriptor,
    RuleCategory,
    RuleContext,
    RuleMeta,
    Severity,
)

_BOUNDARY_PATTERNS = [
    re.compile(r"\boff[- ]?limits?\b", re.I),
    re.compile(r"\bdo\s+not\s+(?:touch|modify|edit|delete|access)\b", re.I),
    re.compile(r"\bnever\s+(?:touch|modify|edit|delete|access)\b", re.I),
    re.compile(r"\brestricted\s+(?:to|files?|director)", re.I),
    re.compile(r"\bonly\s+(?:work|operate|modify)\s+(?:in|within|inside)\b", re.I),
    re.compile(r"\bproject\s+(?:root|directory|boundary)\b", re.I),
    re.compile(r"\bdo\s+not\s+(?:go|navigate|access)\s+outside\b", re.I),
]


class ClaudeMdMissingBoundaryPolicy:
    meta = RuleMeta(
        id="content/missing-boundary-policy",
        default_severity=Severity.INFO,
        fixable=False,
        description=(
            "Flag instruction files that define no directory or resource "
            "boundaries. Without scope limits, the agent operates with no "
            "declared constraints on which files or systems it can access."
        ),
        category=RuleCategory.CONTENT,
        messages={
            "no_boundary": (
                "No boundary policy found in system instructions. Consider "
                "defining which directories or resources are off-limits."
            ),
        },
        target_type=ComponentType.CLAUDE_MD,
        default_suggestion=(
            "Add a section defining which directories, files, or resources "
            "the agent should not access."
        ),
    )

    def create(self, context: RuleContext) -> None:
        target = context.target
        if target is None:
            return

        content = ""
        file_path = ""
        if hasattr(target, "raw_content"):
            content = target.raw_content or ""
            file_path = getattr(target, "file_path", "")

        if not content:
            return

        for pattern in _BOUNDARY_PATTERNS:
            if pattern.search(content):
                return

        context.report(
            ReportDescriptor(
                message_id="no_boundary",
                location=Location(file=file_path),
            )
        )
