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


class ReferencedSkillsExist:
    meta: RuleMeta = RuleMeta(
        id="agent/referenced-skills-exist",
        default_severity=Severity.ERROR,
        fixable=False,
        description="Every skill referenced in agent frontmatter must have a matching SKILL.md",
        category=RuleCategory.CONTENT,
        messages={
            "missing_skill": "Agent references skill '{{skill}}' but no SKILL.md found for it",
        },
        target_type=ComponentType.AGENT,
        default_suggestion="Create the missing skill or fix the reference.",
    )

    def create(self, context: RuleContext) -> None:
        agent = context.agent
        if not agent or not agent.referenced_skills:
            return

        known_skills = {s.dir_name for s in context.all_skills}
        for skill_name in agent.referenced_skills:
            if skill_name not in known_skills:
                context.report(
                    ReportDescriptor(
                        message_id="missing_skill",
                        data={"skill": skill_name},
                        location=Location(
                            file=agent.agent_md_path,
                            start_line=agent.frontmatter_start_line or 1,
                        ),
                    )
                )
