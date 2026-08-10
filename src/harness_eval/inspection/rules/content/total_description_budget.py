from __future__ import annotations

from harness_eval.inspection.types import (
    Location,
    ReportDescriptor,
    RuleCategory,
    RuleContext,
    RuleMeta,
    Severity,
)
from harness_eval.utils.tokens import count_tokens, is_fallback

DEFAULT_TOTAL_DESCRIPTION_BUDGET = 2000


class TotalDescriptionBudget:
    meta = RuleMeta(
        id="content/total-description-budget",
        default_severity=Severity.WARNING,
        fixable=False,
        description=(
            "Total always-loaded description tokens across all skills should not "
            "exceed budget. Every description loads every session."
        ),
        category=RuleCategory.CONTENT,
        messages={
            "over_budget": (
                "Always-loaded description budget: {{total}} tokens across "
                "{{count}} skills (budget: {{budget}}). Descriptions load every "
                "session whether invoked or not."
            ),
        },
        default_suggestion="Shorten skill descriptions to reduce always-loaded token usage.",
    )

    def create(self, context: RuleContext) -> None:
        if context.scan_state.get("total_description_budget_checked"):
            return
        context.scan_state["total_description_budget_checked"] = True

        all_skills = context.all_skills
        if not all_skills:
            return

        total = 0
        count = 0
        largest_skill = all_skills[0]
        largest_tokens = 0
        for skill in all_skills:
            if not skill.frontmatter:
                continue
            desc = skill.frontmatter.get("description", "")
            if isinstance(desc, str) and desc.strip():
                t = count_tokens(desc)
                total += t
                count += 1
                if t > largest_tokens:
                    largest_tokens = t
                    largest_skill = skill

        if total > DEFAULT_TOTAL_DESCRIPTION_BUDGET:
            total_str = f"~{total}" if is_fallback() else str(total)
            context.report(
                ReportDescriptor(
                    message_id="over_budget",
                    data={
                        "total": total_str,
                        "count": str(count),
                        "budget": str(DEFAULT_TOTAL_DESCRIPTION_BUDGET),
                    },
                    location=Location(
                        file=largest_skill.skill_md_path,
                        start_line=1,
                    ),
                )
            )
