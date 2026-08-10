from __future__ import annotations

import contextlib

from harness_eval.inspection.types import (
    Location,
    ReportDescriptor,
    RuleCategory,
    RuleContext,
    RuleMeta,
    Severity,
)

DEFAULT_CONTEXT_BUDGET = 20000
DEFAULT_CONCURRENT_SKILLS = 5
ABSOLUTE_CEILING = 4000
MAX_LINES = 500


class TokenBudget:
    meta: RuleMeta = RuleMeta(
        id="content/token-budget",
        default_severity=Severity.WARNING,
        fixable=False,
        description="Skill should be within adaptive token budget and under 500 lines",
        category=RuleCategory.CONTENT,
        messages={
            "over_budget": "Skill is {{tokens}} tokens — computed budget is {{budget}} ({{context_budget}} context budget / {{concurrent}} concurrent skills, ceiling {{ceiling}})",
            "over_lines": "SKILL.md is {{lines}} lines — Anthropic recommends keeping SKILL.md under 500 lines",
        },
        default_suggestion="Split the skill into smaller focused skills, or trim low-value content.",
    )

    def create(self, context: RuleContext) -> None:
        skill = context.skill
        if not skill.raw_content:
            return

        concurrent = DEFAULT_CONCURRENT_SKILLS
        if context.options:
            with contextlib.suppress(ValueError, IndexError):
                concurrent = int(context.options[0])

        concurrent = max(concurrent, 1)
        budget = min(DEFAULT_CONTEXT_BUDGET // concurrent, ABSOLUTE_CEILING)

        if skill.tokens > budget:
            context.report(
                ReportDescriptor(
                    message_id="over_budget",
                    data={
                        "tokens": str(skill.tokens),
                        "budget": str(budget),
                        "context_budget": str(DEFAULT_CONTEXT_BUDGET),
                        "concurrent": str(concurrent),
                        "ceiling": str(ABSOLUTE_CEILING),
                    },
                    location=Location(
                        file=skill.skill_md_path,
                        start_line=skill.body_start_line or 1,
                    ),
                )
            )

        line_count = len(skill.raw_content.split("\n"))
        if line_count > MAX_LINES:
            context.report(
                ReportDescriptor(
                    message_id="over_lines",
                    data={"lines": str(line_count)},
                    location=Location(
                        file=skill.skill_md_path,
                        start_line=1,
                    ),
                )
            )
