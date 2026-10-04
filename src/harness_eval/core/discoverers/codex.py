"""Codex CLI setup discoverer."""

from __future__ import annotations

from pathlib import Path

from harness_eval.core.discoverers.base import (
    ToolDiscoverer,
    _recursive_glob,
    _toml_top_level_keys,
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
        results.extend(self._discover_skills(root, recursive=recursive))
        results.extend(self._discover_mcp(root, user_config_dir))
        results.extend(self._discover_settings(root, user_config_dir))
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

        for skills_dir in (root / ".agents" / "skills", root / ".codex" / "skills"):
            if skills_dir.is_dir():
                paths.extend(sorted(skills_dir.glob("*/SKILL.md")))
        if recursive:
            for pattern in (".agents/skills/*/SKILL.md", ".codex/skills/*/SKILL.md"):
                paths.extend(_recursive_glob(root, pattern))

        project_config = root / ".codex" / "config.toml"
        if project_config.is_file():
            paths.append(project_config)
        if user_config_dir is not None:
            user_config = user_config_dir / "config.toml"
            if user_config.is_file():
                paths.append(user_config)

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

    def _discover_skills(self, root: Path, *, recursive: bool = False) -> list[ParsedComponent]:
        results: list[ParsedComponent] = []
        seen: set[str] = set()
        candidates: list[Path] = []
        for skills_dir in (root / ".agents" / "skills", root / ".codex" / "skills"):
            if skills_dir.is_dir():
                candidates.extend(sorted(skills_dir.glob("*/SKILL.md")))
        if recursive:
            for pattern in (".agents/skills/*/SKILL.md", ".codex/skills/*/SKILL.md"):
                candidates.extend(_recursive_glob(root, pattern))
        for skill_md in candidates:
            resolved = str(skill_md.resolve())
            if resolved in seen:
                continue
            seen.add(resolved)
            results.append(
                parse_file(
                    skill_md,
                    ComponentType.SKILL,
                    name=skill_md.parent.name,
                    source_tool="codex",
                )
            )
        return results

    def _discover_mcp(self, root: Path, user_config_dir: Path | None) -> list[ParsedComponent]:
        results: list[ParsedComponent] = []
        candidates = [(root / ".codex" / "config.toml", ".codex/config.toml")]
        if user_config_dir is not None:
            candidates.append((user_config_dir / "config.toml", "~/.codex/config.toml"))
        for path, name in candidates:
            if path.is_file() and "mcp_servers" in _toml_top_level_keys(path):
                results.append(
                    parse_file(path, ComponentType.MCP_CONFIG, name=name, source_tool="codex")
                )
        return results

    def _discover_settings(self, root: Path, user_config_dir: Path | None) -> list[ParsedComponent]:
        results: list[ParsedComponent] = []
        candidates = [(root / ".codex" / "config.toml", ".codex/config.toml")]
        if user_config_dir is not None:
            candidates.append((user_config_dir / "config.toml", "~/.codex/config.toml"))
        for path, name in candidates:
            if path.is_file():
                results.append(
                    parse_file(path, ComponentType.CONFIG, name=name, source_tool="codex")
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
