"""Cursor setup discoverer."""

from __future__ import annotations

from pathlib import Path

from harness_eval.core.discoverers.base import SourceEntry, ToolDiscoverer
from harness_eval.core.types import ComponentType


class CursorDiscoverer(ToolDiscoverer):
    """Discovers Cursor setup components."""

    @property
    def tool_name(self) -> str:
        return "Cursor"

    @property
    def source_tool(self) -> str:
        return "cursor"

    @property
    def discovery_summary(self) -> str:
        return (
            "`AGENTS.md`, `.cursorrules`, `.cursor/rules/`, `.cursor/commands/`, "
            "`.cursor/skills/`, `.cursor/hooks.json`, `.cursor/mcp.json`"
        )

    @property
    def source_entries(self) -> tuple[SourceEntry, ...]:
        return (
            SourceEntry(
                ".cursor/rules/*.mdc",
                ComponentType.CLAUDE_MD,
                recursive=True,
                deep=True,
            ),
            SourceEntry(
                ".cursorrules",
                ComponentType.CLAUDE_MD,
                recursive=True,
                name_mode="literal_or_relative",
                name_literal=".cursorrules",
            ),
            SourceEntry(
                "AGENTS.md",
                ComponentType.CLAUDE_MD,
                source_tool="agents-md",
                recursive=True,
            ),
            SourceEntry(
                ".cursor/commands/*.md",
                ComponentType.COMMAND,
                recursive=True,
            ),
            SourceEntry(
                ".cursor/skills/*/SKILL.md",
                ComponentType.SKILL,
                name_mode="parent",
                recursive=True,
            ),
            SourceEntry(
                ".cursor/hooks.json",
                ComponentType.HOOKS,
                name_mode="literal",
                name_literal="hooks.json",
                recursive=True,
            ),
            SourceEntry(
                ".cursor/mcp.json",
                ComponentType.MCP_CONFIG,
                name_mode="literal",
                name_literal=".cursor/mcp.json",
                recursive=True,
            ),
        )

    def detect(self, root: Path) -> bool:
        return (root / ".cursor").is_dir() or (root / ".cursorrules").is_file()
