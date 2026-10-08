"""Flag an agent that lists the same tool entry in both ``tools`` and
``disallowedTools``. The two fields contradict each other; the allow is dead."""

from __future__ import annotations

from harness_eval.core.types import ComponentType
from harness_eval.inspection.rules.frontmatter._keys import claude_only, tool_base_name
from harness_eval.inspection.types import (
    Location,
    ReportDescriptor,
    RuleCategory,
    RuleContext,
    RuleMeta,
    Severity,
)


class AgentToolsDisallowedOverlap:
    meta = RuleMeta(
        id="agent/tools-disallowed-overlap",
        tier="provisional",
        effect="block",
        default_severity=Severity.ERROR,
        fixable=False,
        description="Flag a tool listed in both tools and disallowedTools of the same agent",
        category=RuleCategory.FRONTMATTER,
        messages={
            "overlap": (
                "'{{entry}}' appears in both tools and disallowedTools; the deny wins and the "
                "allow is dead."
            ),
        },
        target_type=ComponentType.AGENT,
        default_suggestion="Remove the entry from one of the two lists.",
    )

    def create(self, context: RuleContext) -> None:
        agent = context.agent
        if agent is None or not claude_only(context.source_tool):
            return
        if not agent.allowed_tools or not agent.disallowed_tools:
            return
        if isinstance(agent.frontmatter.get("tools"), dict):
            return  # OpenCode-style map; the parser already split it into allow/deny
        # An entry contradicts another only when both are the same bare tool
        # name, or the same name with the same pattern. ``tools: Bash`` with
        # ``disallowedTools: Bash(rm *)`` is a legitimate narrowing.
        disallowed = {e.strip() for e in agent.disallowed_tools}
        bare_disallowed = {e for e in disallowed if "(" not in e}
        loc = Location(file=agent.agent_md_path, start_line=agent.frontmatter_start_line or 1)
        reported: set[str] = set()
        for entry in agent.allowed_tools:
            e = entry.strip()
            if e in reported:
                continue
            if e in disallowed or ("(" not in e and tool_base_name(e) in bare_disallowed):
                reported.add(e)
                context.report(
                    ReportDescriptor(message_id="overlap", data={"entry": e}, location=loc)
                )
