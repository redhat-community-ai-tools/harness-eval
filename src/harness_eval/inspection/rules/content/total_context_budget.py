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

DEFAULT_CONTEXT_WINDOW = 200_000
DEFAULT_THRESHOLD_PERCENT = 30


class TotalContextBudget:
    meta = RuleMeta(
        id="content/total-context-budget",
        scope="SETUP",
        default_severity=Severity.WARNING,
        fixable=False,
        description="Total skill token usage should not exceed context window budget",
        category=RuleCategory.CONTENT,
        messages={
            "over_budget": (
                "Total context budget {{total}} tokens"
                " ({{ratio}}% of {{window}}) exceeds {{threshold}}% threshold"
            ),
        },
        target_type=ComponentType.SKILL,
        default_suggestion="Remove low-value skills or reduce their token count.",
    )

    def create(self, context: RuleContext) -> None:
        if context.scan_state.get("total_context_budget_checked"):
            return
        context.scan_state["total_context_budget_checked"] = True

        all_skills = context.all_skills
        if not all_skills:
            return

        total_tokens = sum(s.tokens for s in all_skills)

        threshold = DEFAULT_CONTEXT_WINDOW * DEFAULT_THRESHOLD_PERCENT // 100
        ratio = total_tokens * 100 // DEFAULT_CONTEXT_WINDOW if DEFAULT_CONTEXT_WINDOW else 0

        if total_tokens > threshold:
            context.report(
                ReportDescriptor(
                    message_id="over_budget",
                    data={
                        "total": str(total_tokens),
                        "ratio": str(ratio),
                        "window": str(DEFAULT_CONTEXT_WINDOW),
                        "threshold": str(DEFAULT_THRESHOLD_PERCENT),
                    },
                    location=Location(
                        file=all_skills[0].skill_md_path,
                        start_line=1,
                    ),
                )
            )
