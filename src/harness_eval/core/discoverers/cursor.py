"""Cursor setup discoverer."""

from __future__ import annotations

from pathlib import Path

from harness_eval.core.discoverers.base import ToolDiscoverer, _recursive_glob, parse_file
from harness_eval.core.types import ComponentType, ParsedComponent


class CursorDiscoverer(ToolDiscoverer):
    """Discovers Cursor setup components."""

    @property
    def tool_name(self) -> str:
        return "Cursor"

    @property
    def source_tool(self) -> str:
        return "cursor"

    def detect(self, root: Path) -> bool:
        return (root / ".cursor").is_dir() or (root / ".cursorrules").is_file()

    def discover(
        self, root: Path, user_config_dir: Path | None = None, *, recursive: bool = False
    ) -> list[ParsedComponent]:
        results: list[ParsedComponent] = []
        results.extend(self._discover_rules(root, recursive=recursive))
        results.extend(self._discover_commands(root, recursive=recursive))
        results.extend(self._discover_skills(root, recursive=recursive))
        results.extend(self._discover_hooks(root, recursive=recursive))
        results.extend(self._discover_mcp(root, recursive=recursive))
        return results

    def collect_paths(
        self, root: Path, user_config_dir: Path | None = None, *, recursive: bool = False
    ) -> list[Path]:
        paths: list[Path] = []

        # Cursor rules
        cursor_rules_dir = root / ".cursor" / "rules"
        if cursor_rules_dir.is_dir():
            for f in sorted(cursor_rules_dir.rglob("*.mdc")):
                if f.is_file():
                    paths.append(f)
        if recursive:
            for f in _recursive_glob(root, ".cursor/rules/*.mdc"):
                paths.append(f)

        for f in sorted(root.rglob(".cursorrules")):
            if f.is_file() and ".git" not in f.parts:
                paths.append(f)
        if recursive:
            for f in _recursive_glob(root, ".cursorrules"):
                paths.append(f)

        # Cursor commands
        cursor_commands = root / ".cursor" / "commands"
        if cursor_commands.is_dir():
            for f in sorted(cursor_commands.iterdir()):
                if f.is_file() and f.suffix == ".md":
                    paths.append(f)
        if recursive:
            for f in _recursive_glob(root, ".cursor/commands/*.md"):
                paths.append(f)

        # Cursor skills
        cursor_skills = root / ".cursor" / "skills"
        if cursor_skills.is_dir():
            for f in sorted(cursor_skills.glob("*/SKILL.md")):
                paths.append(f)
        if recursive:
            for f in _recursive_glob(root, ".cursor/skills/*/SKILL.md"):
                paths.append(f)

        # Cursor hooks
        cursor_hooks = root / ".cursor" / "hooks.json"
        if cursor_hooks.is_file():
            paths.append(cursor_hooks)
        if recursive:
            for f in _recursive_glob(root, ".cursor/hooks.json"):
                paths.append(f)

        # Cursor MCP
        cursor_mcp = root / ".cursor" / "mcp.json"
        if cursor_mcp.is_file():
            paths.append(cursor_mcp)
        if recursive:
            for f in _recursive_glob(root, ".cursor/mcp.json"):
                paths.append(f)

        return paths

    def _discover_rules(self, root: Path, *, recursive: bool = False) -> list[ParsedComponent]:
        results: list[ParsedComponent] = []
        seen_paths: set[str] = set()

        cursor_rules_dir = root / ".cursor" / "rules"
        if cursor_rules_dir.is_dir():
            for f in sorted(cursor_rules_dir.rglob("*.mdc")):
                if f.is_file():
                    resolved = str(f.resolve())
                    if resolved not in seen_paths:
                        seen_paths.add(resolved)
                        results.append(
                            parse_file(
                                f, ComponentType.CLAUDE_MD, name=f.stem, source_tool="cursor"
                            )
                        )

        if recursive:
            for f in _recursive_glob(root, ".cursor/rules/*.mdc"):
                resolved = str(f.resolve())
                if resolved not in seen_paths:
                    seen_paths.add(resolved)
                    results.append(
                        parse_file(f, ComponentType.CLAUDE_MD, name=f.stem, source_tool="cursor")
                    )

        for f in sorted(root.rglob(".cursorrules")):
            if f.is_file() and ".git" not in f.parts:
                resolved = str(f.resolve())
                if resolved not in seen_paths:
                    seen_paths.add(resolved)
                    rel = f.relative_to(root)
                    name = str(rel) if rel != Path(".cursorrules") else ".cursorrules"
                    results.append(
                        parse_file(f, ComponentType.CLAUDE_MD, name=name, source_tool="cursor")
                    )

        if recursive:
            for f in _recursive_glob(root, ".cursorrules"):
                resolved = str(f.resolve())
                if resolved not in seen_paths:
                    seen_paths.add(resolved)
                    rel = f.relative_to(root)
                    name = str(rel) if rel != Path(".cursorrules") else ".cursorrules"
                    results.append(
                        parse_file(f, ComponentType.CLAUDE_MD, name=name, source_tool="cursor")
                    )

        return results

    def _discover_commands(self, root: Path, *, recursive: bool = False) -> list[ParsedComponent]:
        results = []
        seen_paths: set[str] = set()
        commands_dir = root / ".cursor" / "commands"
        if commands_dir.is_dir():
            for f in sorted(commands_dir.iterdir()):
                if f.is_file() and f.suffix == ".md":
                    seen_paths.add(str(f.resolve()))
                    results.append(
                        parse_file(f, ComponentType.COMMAND, name=f.stem, source_tool="cursor")
                    )
        if recursive:
            for f in _recursive_glob(root, ".cursor/commands/*.md"):
                resolved = str(f.resolve())
                if resolved not in seen_paths:
                    seen_paths.add(resolved)
                    results.append(
                        parse_file(f, ComponentType.COMMAND, name=f.stem, source_tool="cursor")
                    )
        return results

    def _discover_skills(self, root: Path, *, recursive: bool = False) -> list[ParsedComponent]:
        results = []
        seen_paths: set[str] = set()
        skills_dir = root / ".cursor" / "skills"
        if skills_dir.is_dir():
            for skill_md in sorted(skills_dir.glob("*/SKILL.md")):
                resolved = str(skill_md.resolve())
                if resolved not in seen_paths:
                    seen_paths.add(resolved)
                    results.append(
                        parse_file(
                            skill_md,
                            ComponentType.SKILL,
                            name=skill_md.parent.name,
                            source_tool="cursor",
                        )
                    )
        if recursive:
            for skill_md in _recursive_glob(root, ".cursor/skills/*/SKILL.md"):
                resolved = str(skill_md.resolve())
                if resolved not in seen_paths:
                    seen_paths.add(resolved)
                    results.append(
                        parse_file(
                            skill_md,
                            ComponentType.SKILL,
                            name=skill_md.parent.name,
                            source_tool="cursor",
                        )
                    )
        return results

    def _discover_hooks(self, root: Path, *, recursive: bool = False) -> list[ParsedComponent]:
        results = []
        seen_paths: set[str] = set()
        hooks_file = root / ".cursor" / "hooks.json"
        if hooks_file.is_file():
            seen_paths.add(str(hooks_file.resolve()))
            results.append(
                parse_file(hooks_file, ComponentType.HOOKS, name="hooks.json", source_tool="cursor")
            )
        if recursive:
            for f in _recursive_glob(root, ".cursor/hooks.json"):
                resolved = str(f.resolve())
                if resolved not in seen_paths:
                    seen_paths.add(resolved)
                    results.append(
                        parse_file(f, ComponentType.HOOKS, name="hooks.json", source_tool="cursor")
                    )
        return results

    def _discover_mcp(self, root: Path, *, recursive: bool = False) -> list[ParsedComponent]:
        results = []
        seen_paths: set[str] = set()
        mcp_file = root / ".cursor" / "mcp.json"
        if mcp_file.is_file():
            seen_paths.add(str(mcp_file.resolve()))
            results.append(
                parse_file(
                    mcp_file,
                    ComponentType.MCP_CONFIG,
                    name=".cursor/mcp.json",
                    source_tool="cursor",
                )
            )
        if recursive:
            for f in _recursive_glob(root, ".cursor/mcp.json"):
                resolved = str(f.resolve())
                if resolved not in seen_paths:
                    seen_paths.add(resolved)
                    results.append(
                        parse_file(
                            f,
                            ComponentType.MCP_CONFIG,
                            name=".cursor/mcp.json",
                            source_tool="cursor",
                        )
                    )
        return results
