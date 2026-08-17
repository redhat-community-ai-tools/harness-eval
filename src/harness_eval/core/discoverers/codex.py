"""Codex CLI setup discoverer."""

from __future__ import annotations

from pathlib import Path

from harness_eval.core.discoverers.base import (
    ToolDiscoverer,
    _recursive_glob,
    parse_file,
)
from harness_eval.core.types import ComponentType, ParsedComponent


class CodexDiscoverer(ToolDiscoverer):
    """Discovers Codex CLI setup components.

    Codex uses AGENTS.md (shared cross-tool standard), a .codex/ directory
    for project config and sandbox setup, and codex.json for settings.
    """

    @property
    def tool_name(self) -> str:
        return "Codex CLI"

    @property
    def source_tool(self) -> str:
        return "codex"

    def detect(self, root: Path) -> bool:
        return (root / ".codex").is_dir() or (root / "codex.json").is_file()

    def discover(
        self, root: Path, user_config_dir: Path | None = None, *, recursive: bool = False
    ) -> list[ParsedComponent]:
        results: list[ParsedComponent] = []
        results.extend(self._discover_instructions(root, recursive=recursive))
        results.extend(self._discover_config(root))
        return results

    def collect_paths(
        self, root: Path, user_config_dir: Path | None = None, *, recursive: bool = False
    ) -> list[Path]:
        paths: list[Path] = []

        agents_md = root / "AGENTS.md"
        if agents_md.is_file():
            paths.append(agents_md)
        if recursive:
            for f in _recursive_glob(root, "AGENTS.md"):
                paths.append(f)

        codex_dir = root / ".codex"
        if codex_dir.is_dir():
            for f in sorted(codex_dir.rglob("*")):
                if f.is_file() and f.suffix in (".md", ".toml", ".json"):
                    paths.append(f)

        cfg = root / "codex.json"
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

        instructions = root / ".codex" / "instructions.md"
        if instructions.is_file():
            resolved = str(instructions.resolve())
            if resolved not in seen_paths:
                seen_paths.add(resolved)
                results.append(
                    parse_file(instructions, ComponentType.CLAUDE_MD, source_tool="codex")
                )

        return results

    def _discover_config(self, root: Path) -> list[ParsedComponent]:
        results = []

        cfg = root / "codex.json"
        if cfg.is_file():
            results.append(
                parse_file(cfg, ComponentType.UNCATEGORIZED, name="codex.json", source_tool="codex")
            )

        setup_sh = root / ".codex" / "setup.sh"
        if setup_sh.is_file():
            results.append(
                parse_file(
                    setup_sh, ComponentType.UNCATEGORIZED, name="setup.sh", source_tool="codex"
                )
            )

        return results
