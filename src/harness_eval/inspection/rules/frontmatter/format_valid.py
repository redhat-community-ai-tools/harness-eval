from __future__ import annotations

from harness_eval.inspection.types import (
    Location,
    ReportDescriptor,
    RuleCategory,
    RuleContext,
    RuleMeta,
    Severity,
)


class FormatValid:
    meta: RuleMeta = RuleMeta(
        id="frontmatter/format-valid",
        tier="gating",
        default_severity=Severity.WARNING,
        fixable=False,
        description="Frontmatter must be valid YAML with expected fields",
        category=RuleCategory.FRONTMATTER,
        messages={
            "no_frontmatter": "No YAML frontmatter found — skill files should start with '---'",
            "missing_name": "Field 'name' is missing from frontmatter",
        },
        default_suggestion="Fix the YAML frontmatter syntax errors.",
    )

    def create(self, context: RuleContext) -> None:
        skill = context.skill
        loc = Location(
            file=skill.skill_md_path,
            start_line=skill.frontmatter_start_line or 1,
        )

        if not skill.raw_content:
            return

        if not skill.raw_frontmatter and not skill.parse_errors:
            context.report(ReportDescriptor(message_id="no_frontmatter", location=loc))
            return

        if skill.parse_errors:
            return

        name = skill.frontmatter.get("name")
        if name is None:
            context.report(ReportDescriptor(message_id="missing_name", location=loc))
