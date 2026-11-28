"""Codex CLI setup discoverer."""

from __future__ import annotations

from pathlib import Path

from harness_eval.core.discoverers.base import (
    SourceEntry,
    ToolDiscoverer,
    _toml_top_level_keys,
    parse_file,
)
from harness_eval.core.types import ComponentType, ParsedComponent


class CodexDiscoverer(ToolDiscoverer):
    """Discovers Codex CLI setup components.

    Codex uses AGENTS.md (shared cross-tool standard), a .codex/ directory
    for project config and sandbox setup, and codex.json for settings.

    The ``.codex/config.toml`` file produces both a CONFIG and (when it
    contains ``mcp_servers``) an MCP_CONFIG component, plus it supports a
    user-config-dir counterpart.  Those cases are handled via the override
    hooks :meth:`_extra_collect_paths` and :meth:`_extra_discover`.
    """

    @property
    def tool_name(self) -> str:
        return "Codex CLI"

    @property
    def source_tool(self) -> str:
        return "codex"

    @property
    def discovery_summary(self) -> str:
        return (
            "`AGENTS.md`, `.codex/instructions.md`, `.codex/setup.sh`, "
            "`.codex/config.toml`, `.codex/skills/`, `.agents/skills/`, `codex.json`"
        )

    @property
    def source_entries(self) -> tuple[SourceEntry, ...]:
        return (
            SourceEntry(
                "AGENTS.md",
                ComponentType.CLAUDE_MD,
                source_tool="agents-md",
                recursive=True,
            ),
            SourceEntry(
                ".codex/instructions.md",
                ComponentType.CLAUDE_MD,
            ),
            SourceEntry(
                ".agents/skills/*/SKILL.md",
                ComponentType.SKILL,
                name_mode="parent",
                recursive=True,
            ),
            SourceEntry(
                ".codex/skills/*/SKILL.md",
                ComponentType.SKILL,
                name_mode="parent",
                recursive=True,
            ),
            SourceEntry(
                "codex.json",
                ComponentType.UNCATEGORIZED,
                name_mode="literal",
                name_literal="codex.json",
            ),
            SourceEntry(
                ".codex/setup.sh",
                ComponentType.UNCATEGORIZED,
                name_mode="literal",
                name_literal="setup.sh",
            ),
        )

    def detect(self, root: Path) -> bool:
        return (root / ".codex").is_dir() or (root / "codex.json").is_file()

    # --- override hooks for config.toml and user_config_dir -----------------

    def _extra_collect_paths(
        self,
        root: Path,
        user_config_dir: Path | None = None,
        *,
        recursive: bool = False,
    ) -> list[Path]:
        paths: list[Path] = []
        project_config = root / ".codex" / "config.toml"
        if project_config.is_file():
            paths.append(project_config)
        if user_config_dir is not None:
            user_config = user_config_dir / "config.toml"
            if user_config.is_file():
                paths.append(user_config)
        return paths

    def _extra_discover(
        self,
        root: Path,
        user_config_dir: Path | None = None,
        seen: set[str] | None = None,
        *,
        recursive: bool = False,
    ) -> list[ParsedComponent]:
        results: list[ParsedComponent] = []
        candidates = [(root / ".codex" / "config.toml", ".codex/config.toml")]
        if user_config_dir is not None:
            candidates.append((user_config_dir / "config.toml", "~/.codex/config.toml"))
        for path, name in candidates:
            if not path.is_file():
                continue
            resolved = str(path.resolve())
            if seen is not None and resolved in seen:
                continue
            if seen is not None:
                seen.add(resolved)
            # MCP config (only when file contains mcp_servers)
            if "mcp_servers" in _toml_top_level_keys(path):
                results.append(
                    parse_file(
                        path,
                        ComponentType.MCP_CONFIG,
                        name=name,
                        source_tool="codex",
                    )
                )
            # Settings (always)
            results.append(
                parse_file(
                    path,
                    ComponentType.CONFIG,
                    name=name,
                    source_tool="codex",
                )
            )
        return results
