from __future__ import annotations

from harness_eval.core.types import ComponentType
from harness_eval.inspection.types import (
    Location,
    ReportDescriptor,
    RuleCategory,
    RuleContext,
    RuleMeta,
    Severity,
)


class AgentDescriptionRequired:
    meta: RuleMeta = RuleMeta(
        id="agent/description-required",
        tier="gating",
        default_severity=Severity.ERROR,
        fixable=False,
        description="Agent must have a description in frontmatter",
        category=RuleCategory.FRONTMATTER,
        messages={
            "missing": "Required field 'description' is missing from agent frontmatter",
            "empty": "Field 'description' must not be empty",
        },
        target_type=ComponentType.AGENT,
        default_suggestion="Add a 'description' field to the agent frontmatter.",
    )

    def create(self, context: RuleContext) -> None:
        agent = context.agent
        if not agent or agent.parse_errors:
            return

        description = agent.frontmatter.get("description")
        loc = Location(
            file=agent.agent_md_path,
            start_line=agent.frontmatter_start_line or 1,
        )

        if description is None:
            context.report(ReportDescriptor(message_id="missing", location=loc))
        elif isinstance(description, str) and description.strip() == "":
            context.report(ReportDescriptor(message_id="empty", location=loc))
