"""Flag a frontmatter key that is a case or separator variant of a key the
client reads (``allowed_tools`` for ``allowed-tools``, ``Description`` for
``description``, ``disallowed-tools`` for ``disallowedTools``). The client
ignores the misspelt key silently, so the field has no effect."""

from __future__ import annotations

from harness_eval.core.types import ComponentType
from harness_eval.inspection.rules.frontmatter._keys import (
    KNOWN_KEYS,
    claude_only,
    normalize_key,
)
from harness_eval.inspection.types import (
    Location,
    ReportDescriptor,
    RuleCategory,
    RuleContext,
    RuleMeta,
    Severity,
)


class FrontmatterNearMissKey:
    meta = RuleMeta(
        id="frontmatter/near-miss-key",
        tier="provisional",
        effect="block",
        default_severity=Severity.ERROR,
        fixable=False,
        description=(
            "Flag a frontmatter key that differs from a key the client reads only by "
            "case or separator; the client ignores it silently"
        ),
        category=RuleCategory.FRONTMATTER,
        messages={
            "near_miss": (
                "Frontmatter key '{{key}}' is not read by Claude Code; it is ignored. "
                "Did you mean '{{expected}}'?"
            ),
        },
        target_type=(ComponentType.SKILL, ComponentType.COMMAND, ComponentType.AGENT),
        default_suggestion="Rename the key to the spelling the client documents.",
    )

    def create(self, context: RuleContext) -> None:
        if not claude_only(context.source_tool):
            return
        if context.skill is not None:
            component_type = ComponentType.SKILL
            frontmatter = context.skill.frontmatter
            path = context.skill.skill_md_path
            line = context.skill.frontmatter_start_line or 1
        elif context.command is not None:
            component_type = ComponentType.COMMAND
            frontmatter = context.command.frontmatter
            path = context.command.command_md_path
            line = 1
        elif context.agent is not None:
            component_type = ComponentType.AGENT
            frontmatter = context.agent.frontmatter
            path = context.agent.agent_md_path
            line = context.agent.frontmatter_start_line or 1
        else:
            return
        if not isinstance(frontmatter, dict) or not frontmatter:
            return
        known = KNOWN_KEYS[component_type]
        by_norm = {normalize_key(k): k for k in known}
        loc = Location(file=path, start_line=line)
        for key in frontmatter:
            if not isinstance(key, str) or key in known:
                continue
            expected = by_norm.get(normalize_key(key))
            if expected is None:
                continue
            context.report(
                ReportDescriptor(
                    message_id="near_miss",
                    data={"key": key, "expected": expected},
                    location=loc,
                )
            )
