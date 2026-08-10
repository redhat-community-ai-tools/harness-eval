from __future__ import annotations

from harness_eval.inspection.types import (
    Location,
    ReportDescriptor,
    RuleCategory,
    RuleContext,
    RuleMeta,
    Severity,
)


class DescriptionRequired:
    meta: RuleMeta = RuleMeta(
        id="frontmatter/description-required",
        default_severity=Severity.ERROR,
        fixable=False,
        description="The 'description' field is required in frontmatter",
        category=RuleCategory.FRONTMATTER,
        messages={
            "missing": "Required field 'description' is missing from frontmatter",
            "empty": "Field 'description' must not be empty",
        },
        default_suggestion="Add a 'description' field to the frontmatter.",
    )

    def create(self, context: RuleContext) -> None:
        skill = context.skill
        if skill.parse_errors:
            return

        description = skill.frontmatter.get("description")
        loc = Location(
            file=skill.skill_md_path,
            start_line=skill.frontmatter_start_line or 1,
        )

        if description is None:
            context.report(ReportDescriptor(message_id="missing", location=loc))
        elif isinstance(description, str) and description.strip() == "":
            context.report(ReportDescriptor(message_id="empty", location=loc))
