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


class AgentModelSpecified:
    meta = RuleMeta(
        id="agent/model-specified",
        default_severity=Severity.INFO,
        fixable=False,
        description="Agent definitions should specify a model for consistent behavior",
        category=RuleCategory.BEST_PRACTICES,
        messages={
            "missing": (
                "Agent '{{name}}' does not specify a model. "
                "Consider adding 'model: inherit' or a specific model "
                "to ensure consistent behavior."
            ),
        },
        target_type=ComponentType.AGENT,
        default_suggestion="Add 'model: inherit' or a specific model to the agent definition.",
    )

    def create(self, context: RuleContext) -> None:
        agent = context.agent
        if agent is None:
            return

        if agent.parse_errors:
            return

        if agent.model is None:
            context.report(
                ReportDescriptor(
                    message_id="missing",
                    data={"name": agent.file_name.removesuffix(".md")},
                    location=Location(file=agent.agent_md_path),
                )
            )
