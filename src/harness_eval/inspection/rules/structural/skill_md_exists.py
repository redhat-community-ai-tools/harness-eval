from __future__ import annotations

from harness_eval.inspection.types import (
    Location,
    ReportDescriptor,
    RuleCategory,
    RuleContext,
    RuleMeta,
    Severity,
)


class SkillMdExists:
    meta: RuleMeta = RuleMeta(
        id="structural/skill-md-exists",
        default_severity=Severity.ERROR,
        fixable=False,
        description="SKILL.md file must exist in the skill directory",
        category=RuleCategory.STRUCTURAL,
        messages={
            "not_found": "SKILL.md not found in {{dir}}",
        },
        default_suggestion="Add a SKILL.md file to the skill directory.",
    )

    def create(self, context: RuleContext) -> None:
        skill = context.skill
        if any("SKILL.md not found" in e for e in skill.parse_errors):
            context.report(
                ReportDescriptor(
                    message_id="not_found",
                    data={"dir": skill.dir_name},
                    location=Location(file=skill.skill_md_path),
                )
            )
