from __future__ import annotations

from harness_eval.core.types import ComponentType
from harness_eval.inspection.rules._component_index import component_index, resolve_skill_reference
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
        scope="PAIRWISE",
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

        idx = component_index(context)
        if idx.get("skills_in_submodule"):
            return  # the skills live in a submodule absent from this checkout
        for skill_name in agent.referenced_skills:
            if resolve_skill_reference(str(skill_name), idx) == "missing":
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
