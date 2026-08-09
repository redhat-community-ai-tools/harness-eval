"""Claude Code setup discoverer."""

from __future__ import annotations

from pathlib import Path

from harness_eval.core.discoverers.base import ToolDiscoverer, _recursive_glob, parse_file
from harness_eval.core.types import (
    ComponentScope,
    ComponentType,
    ParsedComponent,
)


class ClaudeCodeDiscoverer(ToolDiscoverer):
    """Discovers Claude Code setup components."""

    @property
    def tool_name(self) -> str:
        return "Claude Code"

    @property
    def source_tool(self) -> str:
        return "claude"

    def detect(self, root: Path) -> bool:
        return (root / "CLAUDE.md").is_file() or (root / ".claude").is_dir()

    def discover(
        self, root: Path, user_config_dir: Path | None = None, *, recursive: bool = False
    ) -> list[ParsedComponent]:
        results: list[ParsedComponent] = []
        results.extend(self._discover_claude_md(root, user_config_dir))
        results.extend(self._discover_skills(root, recursive=recursive))
        results.extend(self._discover_commands(root, recursive=recursive))
        results.extend(self._discover_hooks(root, recursive=recursive))
        results.extend(self._discover_agents(root, recursive=recursive))
        results.extend(self._discover_mcp_configs(root))
        results.extend(self._discover_rules(root))
        results.extend(self._discover_output_styles(root))
        return results

    def collect_paths(
        self, root: Path, user_config_dir: Path | None = None, *, recursive: bool = False
    ) -> list[Path]:
        paths: list[Path] = []

        # CLAUDE.md - project-local
        for pattern in ["CLAUDE.md", "**/CLAUDE.md"]:
            for f in sorted(root.glob(pattern)):
                if f.is_file():
                    paths.append(f)

        # CLAUDE.md - user-config (global + per-project)
        if user_config_dir is not None:
            user_global = user_config_dir / "CLAUDE.md"
            if user_global.is_file():
                paths.append(user_global)
            projects_dir = user_config_dir / "projects"
            if projects_dir.is_dir():
                for project_dir in sorted(projects_dir.iterdir()):
                    if project_dir.is_dir():
                        project_claude = project_dir / "CLAUDE.md"
                        if project_claude.is_file():
                            paths.append(project_claude)

        # Skills
        for skills_dir in [root / "skills", root / ".claude" / "skills"]:
            if skills_dir.is_dir():
                for f in sorted(skills_dir.rglob("SKILL.md")):
                    paths.append(f)
        if recursive:
            for f in _recursive_glob(root, "skills/*/SKILL.md"):
                paths.append(f)

        # Commands
        for commands_dir in [root / "commands", root / ".claude" / "commands"]:
            if commands_dir.is_dir():
                for item in sorted(commands_dir.iterdir()):
                    if item.is_file() and item.suffix == ".md":
                        paths.append(item)
                    elif item.is_dir():
                        cmd_md = item / "command.md"
                        if cmd_md.is_file():
                            paths.append(cmd_md)
        if recursive:
            for f in _recursive_glob(root, "commands/*.md"):
                paths.append(f)
            for f in _recursive_glob(root, "commands/*/command.md"):
                paths.append(f)

        # Settings / hooks
        settings = root / ".claude" / "settings.json"
        if settings.is_file():
            paths.append(settings)
        if recursive:
            for f in _recursive_glob(root, ".claude/settings.json"):
                paths.append(f)

        # Agents
        agents_dir = root / ".claude" / "agents"
        if agents_dir.is_dir():
            for f in sorted(agents_dir.glob("*.md")):
                if f.is_file():
                    paths.append(f)
        if recursive:
            for f in _recursive_glob(root, ".claude/agents/*.md"):
                paths.append(f)

        # MCP configs
        for pattern in [".mcp.json", "**/.mcp.json"]:
            for f in sorted(root.glob(pattern)):
                if f.is_file():
                    paths.append(f)

        # Rules
        rules_dir = root / ".claude" / "rules"
        if rules_dir.is_dir():
            for f in sorted(rules_dir.rglob("*")):
                if f.is_file() and f.suffix in (".md", ".yaml", ".yml"):
                    paths.append(f)

        # Output styles
        styles_dir = root / ".claude" / "output-styles"
        if styles_dir.is_dir():
            for f in sorted(styles_dir.rglob("*")):
                if f.is_file() and f.suffix in (".md", ".yaml", ".yml"):
                    paths.append(f)

        return paths

    def _discover_claude_md(
        self,
        root: Path,
        user_config_dir: Path | None = None,
    ) -> list[ParsedComponent]:
        results: list[ParsedComponent] = []
        seen_paths: set[str] = set()

        # Project-local CLAUDE.md files
        for pattern in ["CLAUDE.md", "**/CLAUDE.md"]:
            for f in sorted(root.glob(pattern)):
                if f.is_file():
                    resolved = str(f.resolve())
                    if resolved not in seen_paths:
                        seen_paths.add(resolved)
                        results.append(parse_file(f, ComponentType.CLAUDE_MD, source_tool="claude"))

        if user_config_dir is None:
            return results

        # User-global CLAUDE.md
        user_global = user_config_dir / "CLAUDE.md"
        if user_global.is_file():
            resolved = str(user_global.resolve())
            if resolved not in seen_paths:
                seen_paths.add(resolved)
                results.append(
                    parse_file(
                        user_global,
                        ComponentType.CLAUDE_MD,
                        name="CLAUDE.md (user-global)",
                        scope=ComponentScope.USER_GLOBAL,
                        source_tool="claude",
                    )
                )

        # User-project CLAUDE.md files
        projects_dir = user_config_dir / "projects"
        if projects_dir.is_dir():
            for project_dir in sorted(projects_dir.iterdir()):
                if not project_dir.is_dir():
                    continue
                project_claude = project_dir / "CLAUDE.md"
                if project_claude.is_file():
                    resolved = str(project_claude.resolve())
                    if resolved not in seen_paths:
                        seen_paths.add(resolved)
                        results.append(
                            parse_file(
                                project_claude,
                                ComponentType.CLAUDE_MD,
                                name=f"CLAUDE.md (user-project: {project_dir.name})",
                                scope=ComponentScope.USER_PROJECT,
                                source_tool="claude",
                            )
                        )

        return results

    def _discover_skills(self, root: Path, *, recursive: bool = False) -> list[ParsedComponent]:
        results = []
        seen_paths: set[str] = set()
        for skills_dir in [root / "skills", root / ".claude" / "skills"]:
            if not skills_dir.is_dir():
                continue
            tool = "claude" if ".claude" in skills_dir.parts else None
            for skill_md in sorted(skills_dir.rglob("SKILL.md")):
                resolved = str(skill_md.resolve())
                if resolved in seen_paths:
                    continue
                seen_paths.add(resolved)
                skill_dir = skill_md.parent
                results.append(
                    parse_file(skill_md, ComponentType.SKILL, name=skill_dir.name, source_tool=tool)
                )
        if recursive:
            for skill_md in _recursive_glob(root, "skills/*/SKILL.md"):
                resolved = str(skill_md.resolve())
                if resolved in seen_paths:
                    continue
                seen_paths.add(resolved)
                results.append(
                    parse_file(
                        skill_md, ComponentType.SKILL, name=skill_md.parent.name, source_tool=None
                    )
                )
        return results

    def _discover_commands(self, root: Path, *, recursive: bool = False) -> list[ParsedComponent]:
        results = []
        seen_paths: set[str] = set()
        for commands_dir in [root / "commands", root / ".claude" / "commands"]:
            if not commands_dir.is_dir():
                continue
            tool = "claude" if ".claude" in commands_dir.parts else None
            for item in sorted(commands_dir.iterdir()):
                if item.is_file() and item.suffix == ".md":
                    seen_paths.add(str(item.resolve()))
                    results.append(parse_file(item, ComponentType.COMMAND, source_tool=tool))
                elif item.is_dir():
                    cmd_md = item / "command.md"
                    if cmd_md.is_file():
                        seen_paths.add(str(cmd_md.resolve()))
                        results.append(
                            parse_file(
                                cmd_md, ComponentType.COMMAND, name=item.name, source_tool=tool
                            )
                        )
        if recursive:
            for f in _recursive_glob(root, "commands/*.md"):
                resolved = str(f.resolve())
                if resolved not in seen_paths:
                    seen_paths.add(resolved)
                    results.append(parse_file(f, ComponentType.COMMAND, source_tool=None))
            for f in _recursive_glob(root, "commands/*/command.md"):
                resolved = str(f.resolve())
                if resolved not in seen_paths:
                    seen_paths.add(resolved)
                    results.append(
                        parse_file(f, ComponentType.COMMAND, name=f.parent.name, source_tool=None)
                    )
        return results

    def _discover_hooks(self, root: Path, *, recursive: bool = False) -> list[ParsedComponent]:
        results = []
        seen_paths: set[str] = set()
        settings = root / ".claude" / "settings.json"
        if settings.is_file():
            seen_paths.add(str(settings.resolve()))
            results.append(
                parse_file(
                    settings, ComponentType.HOOKS, name="settings.json", source_tool="claude"
                )
            )
        if recursive:
            for f in _recursive_glob(root, ".claude/settings.json"):
                resolved = str(f.resolve())
                if resolved not in seen_paths:
                    seen_paths.add(resolved)
                    results.append(
                        parse_file(
                            f, ComponentType.HOOKS, name="settings.json", source_tool="claude"
                        )
                    )
        return results

    def _discover_agents(self, root: Path, *, recursive: bool = False) -> list[ParsedComponent]:
        results = []
        seen_paths: set[str] = set()
        agents_dir = root / ".claude" / "agents"
        if agents_dir.is_dir():
            for f in sorted(agents_dir.glob("*.md")):
                if f.is_file():
                    seen_paths.add(str(f.resolve()))
                    results.append(parse_file(f, ComponentType.AGENT, source_tool="claude"))
        if recursive:
            for f in _recursive_glob(root, ".claude/agents/*.md"):
                resolved = str(f.resolve())
                if resolved not in seen_paths:
                    seen_paths.add(resolved)
                    results.append(parse_file(f, ComponentType.AGENT, source_tool="claude"))
        return results

    def _discover_mcp_configs(self, root: Path) -> list[ParsedComponent]:
        results = []
        for pattern in [".mcp.json", "**/.mcp.json"]:
            for f in sorted(root.glob(pattern)):
                if f.is_file():
                    results.append(parse_file(f, ComponentType.MCP_CONFIG))
        seen_paths: set[str] = set()
        deduped = []
        for c in results:
            resolved = str(Path(c.path).resolve())
            if resolved not in seen_paths:
                seen_paths.add(resolved)
                deduped.append(c)
        return deduped

    def _discover_rules(self, root: Path) -> list[ParsedComponent]:
        results = []
        rules_dir = root / ".claude" / "rules"
        if not rules_dir.is_dir():
            return results
        for f in sorted(rules_dir.rglob("*")):
            if f.is_file() and f.suffix in (".md", ".yaml", ".yml"):
                results.append(parse_file(f, ComponentType.RULE, name=f.stem, source_tool="claude"))
        return results

    def _discover_output_styles(self, root: Path) -> list[ParsedComponent]:
        results = []
        styles_dir = root / ".claude" / "output-styles"
        if not styles_dir.is_dir():
            return results
        for f in sorted(styles_dir.rglob("*")):
            if f.is_file() and f.suffix in (".md", ".yaml", ".yml"):
                results.append(
                    parse_file(f, ComponentType.OUTPUT_STYLE, name=f.stem, source_tool="claude")
                )
        return results
