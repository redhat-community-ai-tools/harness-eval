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
        tier="gating",
        default_severity=Severity.WARNING,
        fixable=False,
        description="The 'description' field is required in frontmatter",
        category=RuleCategory.FRONTMATTER,
        messages={
            "missing": (
                "Field 'description' is missing: the Agent Skills specification requires"
                " it. Claude Code falls back to the first paragraph of the body to decide"
                " when to use the skill; spec-conformant consumers may reject the skill."
            ),
            "empty": (
                "Field 'description' is empty: the Agent Skills specification requires a"
                " non-empty description. Claude Code falls back to the first paragraph of"
                " the body; spec-conformant consumers may reject the skill."
            ),
        },
        default_suggestion="Add a 'description' field to the frontmatter.",
    )

    def create(self, context: RuleContext) -> None:
        skill = context.skill
        if skill is None:
            return
        if skill.parse_errors:
            return
        # No frontmatter block at all is frontmatter/format-valid's finding;
        # reporting a missing description as well counts one defect twice.
        if not skill.frontmatter and not skill.raw_content.lstrip("\ufeff").startswith("---"):
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
