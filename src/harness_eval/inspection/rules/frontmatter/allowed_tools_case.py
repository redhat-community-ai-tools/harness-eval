"""Flag a tool entry in ``allowed-tools`` / ``tools`` / ``disallowedTools``
that matches a built-in tool name only when case is ignored (``bash`` for
``Bash``, ``read`` for ``Read``). Tool names are case-sensitive, so the entry
grants or denies nothing."""

from __future__ import annotations

from harness_eval.core.types import ComponentType
from harness_eval.data import load_tool_names
from harness_eval.inspection.rules.frontmatter._keys import (
    claude_only,
    split_tool_entries,
    tool_base_name,
)
from harness_eval.inspection.types import (
    Location,
    ReportDescriptor,
    RuleCategory,
    RuleContext,
    RuleMeta,
    Severity,
)


class FrontmatterAllowedToolsCase:
    meta = RuleMeta(
        id="frontmatter/allowed-tools-case",
        tier="provisional",
        effect="block",
        default_severity=Severity.ERROR,
        fixable=False,
        description=(
            "Flag a tool entry that matches a built-in tool name only case-insensitively; "
            "tool names are case-sensitive, so the entry has no effect"
        ),
        category=RuleCategory.FRONTMATTER,
        messages={
            "case_mismatch": (
                "'{{field}}' entry '{{entry}}' matches no tool; tool names are "
                "case-sensitive. Did you mean '{{expected}}'?"
            ),
        },
        target_type=(ComponentType.SKILL, ComponentType.COMMAND, ComponentType.AGENT),
        default_suggestion="Use the tool name exactly as the client spells it.",
    )

    def create(self, context: RuleContext) -> None:
        if not claude_only(context.source_tool):
            return
        fields: list[tuple[str, list[str]]] = []
        if context.skill is not None:
            path = context.skill.skill_md_path
            line = context.skill.frontmatter_start_line or 1
            fields.append(
                (
                    "allowed-tools",
                    split_tool_entries(context.skill.frontmatter.get("allowed-tools")),
                )
            )
        elif context.command is not None:
            path = context.command.command_md_path
            line = 1
            fm = (
                context.command.frontmatter if isinstance(context.command.frontmatter, dict) else {}
            )
            fields.append(("allowed-tools", split_tool_entries(fm.get("allowed-tools"))))
        elif context.agent is not None:
            path = context.agent.agent_md_path
            line = context.agent.frontmatter_start_line or 1
            if context.agent.frontmatter.get("tools") is not None and not isinstance(
                context.agent.frontmatter.get("tools"), dict
            ):
                fields.append(("tools", list(context.agent.allowed_tools)))
            fields.append(("disallowedTools", list(context.agent.disallowed_tools)))
        else:
            return

        names = load_tool_names()
        exact = set(names)
        by_lower = {n.lower(): n for n in names}
        loc = Location(file=path, start_line=line)
        for field, entries in fields:
            for entry in entries:
                base = tool_base_name(entry)
                if not base or base in exact or base.startswith("mcp__") or "*" in base:
                    continue
                expected = by_lower.get(base.lower())
                if expected is None:
                    continue
                context.report(
                    ReportDescriptor(
                        message_id="case_mismatch",
                        data={"field": field, "entry": entry, "expected": expected},
                        location=loc,
                    )
                )
