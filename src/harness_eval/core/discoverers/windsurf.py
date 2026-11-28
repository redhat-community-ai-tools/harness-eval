"""Windsurf setup discoverer."""

from __future__ import annotations

from pathlib import Path

from harness_eval.core.discoverers.base import SourceEntry, ToolDiscoverer
from harness_eval.core.types import ComponentType


class WindsurfDiscoverer(ToolDiscoverer):
    """Discovers Windsurf setup components.

    Windsurf stores its system instructions as plain markdown, mirroring
    Cursor: a single ``.windsurfrules`` file and/or per-topic files under
    ``.windsurf/rules/``. Both map to CLAUDE_MD components.
    """

    @property
    def tool_name(self) -> str:
        return "Windsurf"

    @property
    def source_tool(self) -> str:
        return "windsurf"

    @property
    def discovery_summary(self) -> str:
        return (
            "`AGENTS.md`, `.windsurfrules`, `.windsurf/rules/`, `.devin/rules/`, "
            "`.windsurf/skills/`, `.devin/skills/`, `.agents/skills/`, "
            "`.windsurf/workflows/`, `.devin/workflows/`, "
            "`.windsurf/hooks.json`, `.windsurf/mcp_config.json`"
        )

    @property
    def source_entries(self) -> tuple[SourceEntry, ...]:
        return (
            # Rules
            SourceEntry(
                ".devin/rules/*.md",
                ComponentType.CLAUDE_MD,
                deep=True,
            ),
            SourceEntry(
                ".windsurf/rules/*.md",
                ComponentType.CLAUDE_MD,
                recursive=True,
                deep=True,
            ),
            SourceEntry(
                ".windsurfrules",
                ComponentType.CLAUDE_MD,
                recursive=True,
                name_mode="literal_or_relative",
                name_literal=".windsurfrules",
            ),
            # Skills
            SourceEntry(
                ".devin/skills/*/SKILL.md",
                ComponentType.SKILL,
                name_mode="parent",
                recursive=True,
            ),
            SourceEntry(
                ".windsurf/skills/*/SKILL.md",
                ComponentType.SKILL,
                name_mode="parent",
                recursive=True,
            ),
            SourceEntry(
                ".agents/skills/*/SKILL.md",
                ComponentType.SKILL,
                name_mode="parent",
                recursive=True,
            ),
            # Workflows
            SourceEntry(
                ".devin/workflows/*.md",
                ComponentType.COMMAND,
                recursive=True,
            ),
            SourceEntry(
                ".windsurf/workflows/*.md",
                ComponentType.COMMAND,
                recursive=True,
            ),
            # Hooks
            SourceEntry(
                ".windsurf/hooks.json",
                ComponentType.HOOKS,
            ),
            # MCP
            SourceEntry(
                ".windsurf/mcp_config.json",
                ComponentType.MCP_CONFIG,
            ),
            # AGENTS.md
            SourceEntry(
                "AGENTS.md",
                ComponentType.CLAUDE_MD,
                source_tool="agents-md",
                recursive=True,
            ),
        )

    def detect(self, root: Path) -> bool:
        return (
            (root / ".devin").is_dir()
            or (root / ".windsurf").is_dir()
            or (root / ".windsurfrules").is_file()
        )
