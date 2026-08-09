"""OpenCode setup discoverer."""

from __future__ import annotations

from pathlib import Path

from harness_eval.core.discoverers.base import (
    ToolDiscoverer,
    _json_top_level_keys,
    _recursive_glob,
    parse_file,
)
from harness_eval.core.types import ComponentType, ParsedComponent


class OpenCodeDiscoverer(ToolDiscoverer):
    """Discovers OpenCode setup components."""

    @property
    def tool_name(self) -> str:
        return "OpenCode"

    @property
    def source_tool(self) -> str:
        return "opencode"

    def detect(self, root: Path) -> bool:
        """Detect OpenCode setup files.

        AGENTS.md is a cross-tool standard (Codex CLI, Copilot CLI, Gemini CLI,
        Claude Code, OpenCode) so it is attributed as "agents-md" rather than
        "opencode".  The .opencode/ directory is OpenCode-specific.
        """
        return (
            (root / "AGENTS.md").is_file()
            or (root / ".opencode").is_dir()
            or (root / "opencode.json").is_file()
            or (root / "opencode.jsonc").is_file()
        )

    def discover(
        self, root: Path, user_config_dir: Path | None = None, *, recursive: bool = False
    ) -> list[ParsedComponent]:
        results: list[ParsedComponent] = []
        results.extend(self._discover_instructions(root, recursive=recursive))
        results.extend(self._discover_commands(root, recursive=recursive))
        results.extend(self._discover_agents(root, recursive=recursive))
        results.extend(self._discover_mcp(root))
        return results

    def collect_paths(
        self, root: Path, user_config_dir: Path | None = None, *, recursive: bool = False
    ) -> list[Path]:
        paths: list[Path] = []

        # OpenCode instructions
        agents_md = root / "AGENTS.md"
        if agents_md.is_file():
            paths.append(agents_md)
        if recursive:
            for f in _recursive_glob(root, "AGENTS.md"):
                paths.append(f)

        # OpenCode commands
        opencode_commands = root / ".opencode" / "commands"
        if opencode_commands.is_dir():
            for f in sorted(opencode_commands.iterdir()):
                if f.is_file() and f.suffix == ".md":
                    paths.append(f)
        if recursive:
            for f in _recursive_glob(root, ".opencode/commands/*.md"):
                paths.append(f)

        # OpenCode agents
        opencode_agents = root / ".opencode" / "agents"
        if opencode_agents.is_dir():
            for f in sorted(opencode_agents.glob("*.md")):
                if f.is_file():
                    paths.append(f)
        if recursive:
            for f in _recursive_glob(root, ".opencode/agents/*.md"):
                paths.append(f)

        for cfg_name in ("opencode.json", "opencode.jsonc"):
            cfg = root / cfg_name
            if cfg.is_file():
                paths.append(cfg)

        return paths

    def _discover_instructions(
        self, root: Path, *, recursive: bool = False
    ) -> list[ParsedComponent]:
        results = []
        seen_paths: set[str] = set()
        agents_md = root / "AGENTS.md"
        if agents_md.is_file():
            seen_paths.add(str(agents_md.resolve()))
            results.append(parse_file(agents_md, ComponentType.CLAUDE_MD, source_tool="agents-md"))
        if recursive:
            for f in _recursive_glob(root, "AGENTS.md"):
                resolved = str(f.resolve())
                if resolved not in seen_paths:
                    seen_paths.add(resolved)
                    results.append(parse_file(f, ComponentType.CLAUDE_MD, source_tool="agents-md"))
        return results

    def _discover_commands(self, root: Path, *, recursive: bool = False) -> list[ParsedComponent]:
        results = []
        seen_paths: set[str] = set()
        commands_dir = root / ".opencode" / "commands"
        if commands_dir.is_dir():
            for f in sorted(commands_dir.iterdir()):
                if f.is_file() and f.suffix == ".md":
                    seen_paths.add(str(f.resolve()))
                    results.append(
                        parse_file(f, ComponentType.COMMAND, name=f.stem, source_tool="opencode")
                    )
        if recursive:
            for f in _recursive_glob(root, ".opencode/commands/*.md"):
                resolved = str(f.resolve())
                if resolved not in seen_paths:
                    seen_paths.add(resolved)
                    results.append(
                        parse_file(f, ComponentType.COMMAND, name=f.stem, source_tool="opencode")
                    )
        return results

    def _discover_agents(self, root: Path, *, recursive: bool = False) -> list[ParsedComponent]:
        results = []
        seen_paths: set[str] = set()
        agents_dir = root / ".opencode" / "agents"
        if agents_dir.is_dir():
            for f in sorted(agents_dir.glob("*.md")):
                if f.is_file():
                    seen_paths.add(str(f.resolve()))
                    results.append(parse_file(f, ComponentType.AGENT, source_tool="opencode"))
        if recursive:
            for f in _recursive_glob(root, ".opencode/agents/*.md"):
                resolved = str(f.resolve())
                if resolved not in seen_paths:
                    seen_paths.add(resolved)
                    results.append(parse_file(f, ComponentType.AGENT, source_tool="opencode"))
        return results

    def _discover_mcp(self, root: Path) -> list[ParsedComponent]:
        # OpenCode stores MCP servers in opencode.json(c) under the 'mcp' key.
        # Only emit an MCP config component when that key is present so that
        # non-MCP OpenCode configs are not misclassified.
        for cfg_name in ("opencode.json", "opencode.jsonc"):
            cfg = root / cfg_name
            if cfg.is_file() and "mcp" in _json_top_level_keys(cfg):
                return [
                    parse_file(
                        cfg,
                        ComponentType.MCP_CONFIG,
                        name=cfg_name,
                        source_tool="opencode",
                    )
                ]
        return []
