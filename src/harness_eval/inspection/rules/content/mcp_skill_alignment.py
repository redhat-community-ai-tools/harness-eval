from __future__ import annotations

import json
import re
from pathlib import Path

from harness_eval.core.types import ComponentType
from harness_eval.inspection.types import (
    Location,
    ReportDescriptor,
    RuleCategory,
    RuleContext,
    RuleMeta,
    Severity,
)

_MCP_PATTERNS = [
    re.compile(r"\bmcp__\w+", re.IGNORECASE),
    re.compile(r"\bmcp[_\-]tool\b", re.IGNORECASE),
    re.compile(r"\buse[_\s]mcp\b", re.IGNORECASE),
    re.compile(r"\bmcp\s+server\b", re.IGNORECASE),
    re.compile(r"\bmcp\s+tool\b", re.IGNORECASE),
]


def _mentions_mcp(text: str) -> bool:
    """Check if text contains MCP-related references."""
    return any(pattern.search(text) for pattern in _MCP_PATTERNS)


def _find_mcp_config(skill_path: str) -> str | None:
    """Walk up from skill path to find .mcp.json."""
    current = Path(skill_path).resolve()
    for _ in range(10):
        candidate = current / ".mcp.json"
        if candidate.exists():
            return str(candidate)
        parent = current.parent
        if parent == current:
            break
        current = parent
    return None


class McpSkillAlignment:
    meta = RuleMeta(
        id="content/mcp-skill-alignment",
        default_severity=Severity.WARNING,
        fixable=False,
        description="MCP server configurations should align with skill usage",
        category=RuleCategory.CONTENT,
        messages={
            "mcp_unused": "MCP server '{{server}}' is configured but no skill references its tools",
        },
        target_type=ComponentType.SKILL,
        default_suggestion="Remove the unused MCP server or add a skill that uses its tools.",
    )

    def create(self, context: RuleContext) -> None:
        if context.scan_state.get("mcp_skill_alignment_checked"):
            return
        context.scan_state["mcp_skill_alignment_checked"] = True

        all_skills = context.all_skills
        if not all_skills:
            return

        # Find MCP config by walking up from first skill
        mcp_config_path = _find_mcp_config(all_skills[0].dir_path)
        context.scan_state["mcp_config_path"] = mcp_config_path

        has_mcp_config = mcp_config_path is not None

        # Check which skills mention MCP
        skills_mentioning_mcp: list[str] = []

        for skill in all_skills:
            if skill.body and _mentions_mcp(skill.body):
                skills_mentioning_mcp.append(skill.dir_name)

        if has_mcp_config and not skills_mentioning_mcp:
            try:
                with open(mcp_config_path, encoding="utf-8") as f:
                    mcp_data = json.load(f)
                servers = mcp_data.get("mcpServers", {})
                for server_name in servers:
                    context.report(
                        ReportDescriptor(
                            message_id="mcp_unused",
                            data={"server": server_name},
                            location=Location(file=mcp_config_path, start_line=1),
                        )
                    )
            except (json.JSONDecodeError, OSError):
                pass
