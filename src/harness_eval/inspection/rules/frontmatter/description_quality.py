from __future__ import annotations

from harness_eval.inspection.types import (
    Location,
    ReportDescriptor,
    RuleCategory,
    RuleContext,
    RuleMeta,
    Severity,
)

MAX_DESCRIPTION_LENGTH = 1024


class DescriptionQuality:
    meta: RuleMeta = RuleMeta(
        id="frontmatter/description-quality",
        default_severity=Severity.WARNING,
        fixable=False,
        description="Description must fit the Agent Skills 1,024-character limit",
        category=RuleCategory.FRONTMATTER,
        messages={
            "too_long": "Description is {{length}} characters — the Agent Skills limit is 1,024",
        },
        default_suggestion="Rewrite the description to clearly state what the skill does and when to use it.",
    )

    def create(self, context: RuleContext) -> None:
        skill = context.skill
        if skill is None:
            return
        if skill.parse_errors:
            return

        description = skill.frontmatter.get("description", "")
        if not isinstance(description, str) or not description:
            return

        loc = Location(
            file=skill.skill_md_path,
            start_line=skill.frontmatter_start_line or 1,
        )

        if len(description) > MAX_DESCRIPTION_LENGTH:
            context.report(
                ReportDescriptor(
                    message_id="too_long",
                    data={"length": str(len(description))},
                    location=loc,
                )
            )
