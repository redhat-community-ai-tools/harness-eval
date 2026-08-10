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

DEFAULT_MAX_DESCRIPTION_TOKENS = 100


class DescriptionLength:
    meta = RuleMeta(
        id="content/description-length",
        default_severity=Severity.WARNING,
        fixable=False,
        description=(
            "Flag skill descriptions that are too long. Descriptions load into "
            "the system prompt every session, invoked or not."
        ),
        category=RuleCategory.CONTENT,
        messages={
            "over_budget": (
                "Description is {{tokens}} tokens (budget: {{budget}}). "
                "Descriptions load every session regardless of whether the skill "
                "is invoked. Keep descriptions concise; move detail to the body."
            ),
        },
    )

    def create(self, context: RuleContext) -> None:
        skill = context.skill
        if not skill.frontmatter:
            return

        desc = skill.frontmatter.get("description", "")
        if not isinstance(desc, str) or not desc.strip():
            return

        tokens = count_tokens(desc)
        budget = DEFAULT_MAX_DESCRIPTION_TOKENS

        if tokens > budget:
            token_str = f"~{tokens}" if is_fallback() else str(tokens)
            context.report(
                ReportDescriptor(
                    message_id="over_budget",
                    data={"tokens": token_str, "budget": str(budget)},
                    location=Location(file=skill.skill_md_path),
                )
            )
