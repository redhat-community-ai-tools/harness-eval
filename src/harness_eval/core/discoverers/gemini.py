"""Gemini CLI setup discoverer."""

from __future__ import annotations

from pathlib import Path

from harness_eval.core.discoverers.base import (
    ToolDiscoverer,
    _json_top_level_keys,
    _recursive_glob,
    parse_file,
)
from harness_eval.core.types import ComponentType, ParsedComponent


class GeminiDiscoverer(ToolDiscoverer):
    """Discovers Gemini CLI setup components."""

    @property
    def tool_name(self) -> str:
        return "Gemini CLI"

    @property
    def source_tool(self) -> str:
        return "gemini"

    def detect(self, root: Path) -> bool:
        return (root / "GEMINI.md").is_file() or (root / ".gemini").is_dir()

    def discover(
        self, root: Path, user_config_dir: Path | None = None, *, recursive: bool = False
    ) -> list[ParsedComponent]:
        results: list[ParsedComponent] = []
        results.extend(self._discover_instructions(root, recursive=recursive))
        results.extend(self._discover_commands(root, recursive=recursive))
        results.extend(self._discover_mcp(root, user_config_dir))
        return results

    def collect_paths(
        self, root: Path, user_config_dir: Path | None = None, *, recursive: bool = False
    ) -> list[Path]:
        paths: list[Path] = []

        # Gemini instructions
        gemini_md = root / "GEMINI.md"
        if gemini_md.is_file():
            paths.append(gemini_md)
        if recursive:
            for f in _recursive_glob(root, "GEMINI.md"):
                paths.append(f)

        # Gemini commands
        gemini_commands = root / ".gemini" / "commands"
        if gemini_commands.is_dir():
            for f in sorted(gemini_commands.iterdir()):
                if f.is_file() and (f.suffix == ".toml" or f.suffix == ".md"):
                    paths.append(f)
        if recursive:
            for f in _recursive_glob(root, ".gemini/commands/*.md"):
                paths.append(f)

        settings = root / ".gemini" / "settings.json"
        if settings.is_file():
            paths.append(settings)
        if user_config_dir is not None:
            global_settings = user_config_dir / "settings.json"
            if global_settings.is_file():
                paths.append(global_settings)

        return paths

    def _discover_instructions(
        self, root: Path, *, recursive: bool = False
    ) -> list[ParsedComponent]:
        results = []
        seen_paths: set[str] = set()
        gemini_md = root / "GEMINI.md"
        if gemini_md.is_file():
            seen_paths.add(str(gemini_md.resolve()))
            results.append(parse_file(gemini_md, ComponentType.CLAUDE_MD, source_tool="gemini"))
        if recursive:
            for f in _recursive_glob(root, "GEMINI.md"):
                resolved = str(f.resolve())
                if resolved not in seen_paths:
                    seen_paths.add(resolved)
                    results.append(parse_file(f, ComponentType.CLAUDE_MD, source_tool="gemini"))
        return results

    def _discover_commands(self, root: Path, *, recursive: bool = False) -> list[ParsedComponent]:
        results = []
        seen_paths: set[str] = set()
        commands_dir = root / ".gemini" / "commands"
        if commands_dir.is_dir():
            for f in sorted(commands_dir.iterdir()):
                if f.is_file() and (f.suffix == ".toml" or f.suffix == ".md"):
                    seen_paths.add(str(f.resolve()))
                    results.append(
                        parse_file(f, ComponentType.COMMAND, name=f.stem, source_tool="gemini")
                    )
        if recursive:
            for f in _recursive_glob(root, ".gemini/commands/*.md"):
                resolved = str(f.resolve())
                if resolved not in seen_paths:
                    seen_paths.add(resolved)
                    results.append(
                        parse_file(f, ComponentType.COMMAND, name=f.stem, source_tool="gemini")
                    )
        return results

    def _discover_mcp(
        self, root: Path, user_config_dir: Path | None = None
    ) -> list[ParsedComponent]:
        # Gemini CLI stores MCP servers in settings.json under the standard
        # 'mcpServers' key -- project-level (.gemini/settings.json) and global
        # (~/.gemini/settings.json, passed via --user-config). Only treat a file
        # as an MCP config when that key is present, so ordinary settings files
        # are not misclassified.
        results: list[ParsedComponent] = []
        seen: set[str] = set()
        candidates = [(root / ".gemini" / "settings.json", ".gemini/settings.json")]
        if user_config_dir is not None:
            candidates.append((user_config_dir / "settings.json", "~/.gemini/settings.json"))
        for path, name in candidates:
            if not path.is_file():
                continue
            resolved = str(path.resolve())
            if resolved in seen:
                continue
            if "mcpServers" in _json_top_level_keys(path):
                seen.add(resolved)
                results.append(
                    parse_file(
                        path,
                        ComponentType.MCP_CONFIG,
                        name=name,
                        source_tool="gemini",
                    )
                )
        return results
