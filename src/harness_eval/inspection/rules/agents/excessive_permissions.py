"""Flag agents that declare no tool constraints (neither allowedTools nor disallowedTools)."""

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


class AgentExcessivePermissions:
    meta = RuleMeta(
        id="agent/excessive-permissions",
        tier="provisional",
        effect="policy",
        default_severity=Severity.WARNING,
        fixable=False,
        description="Agent declares no tool constraints, granting unrestricted access",
        category=RuleCategory.SECURITY,
        messages={
            "no_constraints": (
                "Agent '{{name}}' has no allowedTools or disallowedTools."
                " It can use every available tool without restriction."
            ),
        },
        target_type=ComponentType.AGENT,
        frameworks={"owasp_agentic": "ASI02"},
        default_suggestion="Add allowedTools or disallowedTools to restrict tool access.",
    )

    def create(self, context: RuleContext) -> None:
        agent = context.agent
        if agent is None:
            return
        if context.source_tool is not None and context.source_tool != "claude":
            return
        # An agent a pipeline harness runs lives in that harness's sandbox,
        # where the harness policy is the boundary and Claude Code runs with
        # permissions skipped; the frontmatter fields decide nothing there.
        if context.artifacts.is_harness_managed(agent.agent_md_path):
            return

        if not agent.allowed_tools and not agent.disallowed_tools:
            context.report(
                ReportDescriptor(
                    message_id="no_constraints",
                    data={"name": agent.file_name.removesuffix(".md")},
                    location=Location(file=agent.agent_md_path, start_line=1),
                    suggestion="Add allowedTools or disallowedTools to limit this agent's capabilities.",
                )
            )
