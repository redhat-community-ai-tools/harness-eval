"""GitHub Copilot setup discoverer."""

from __future__ import annotations

from pathlib import Path

from harness_eval.core.discoverers.base import (
    ToolDiscoverer,
    _json_top_level_keys,
    _recursive_glob,
    is_agent_file,
    parse_file,
)
from harness_eval.core.types import ComponentType, ParsedComponent


class CopilotDiscoverer(ToolDiscoverer):
    """Discovers GitHub Copilot setup components."""

    @property
    def tool_name(self) -> str:
        return "Copilot"

    @property
    def source_tool(self) -> str:
        return "copilot"

    def detect(self, root: Path) -> bool:
        return (
            (root / ".github" / "prompts").is_dir()
            or (root / ".github" / "agents").is_dir()
            or (root / ".github" / "skills").is_dir()
            or (root / ".github" / "copilot-instructions.md").is_file()
            or (root / ".github" / "instructions").is_dir()
            or (root / ".github" / "hooks").is_dir()
            or (root / ".vscode" / "mcp.json").is_file()
        )

    def discover(
        self, root: Path, user_config_dir: Path | None = None, *, recursive: bool = False
    ) -> list[ParsedComponent]:
        results: list[ParsedComponent] = []
        results.extend(self._discover_instructions(root))
        results.extend(self._discover_skills(root, recursive=recursive))
        results.extend(self._discover_commands(root, recursive=recursive))
        results.extend(self._discover_agents(root, recursive=recursive))
        results.extend(self._discover_hooks(root, recursive=recursive))
        results.extend(self._discover_settings(root))
        results.extend(self._discover_mcp(root))
        return results

    def collect_paths(
        self, root: Path, user_config_dir: Path | None = None, *, recursive: bool = False
    ) -> list[Path]:
        paths: list[Path] = []

        instructions = root / ".github" / "copilot-instructions.md"
        if instructions.is_file():
            paths.append(instructions)
        instructions_dir = root / ".github" / "instructions"
        if instructions_dir.is_dir():
            paths.extend(sorted(instructions_dir.rglob("*.instructions.md")))

        # Copilot skills
        for copilot_skills in (
            root / ".github" / "skills",
            root / ".agents" / "skills",
            root / ".claude" / "skills",
        ):
            if copilot_skills.is_dir():
                paths.extend(sorted(copilot_skills.glob("*/SKILL.md")))
        if recursive:
            for f in _recursive_glob(root, ".github/skills/*/SKILL.md"):
                paths.append(f)

        # Copilot commands (prompts)
        copilot_commands = root / ".github" / "prompts"
        if copilot_commands.is_dir():
            for f in sorted(copilot_commands.iterdir()):
                if f.is_file() and f.suffix == ".md":
                    paths.append(f)
        if recursive:
            for f in _recursive_glob(root, ".github/prompts/*.md"):
                paths.append(f)

        # Copilot agents
        copilot_agents = root / ".github" / "agents"
        if copilot_agents.is_dir():
            for f in sorted(copilot_agents.glob("*.md")):
                if f.is_file():
                    paths.append(f)
        if recursive:
            for f in _recursive_glob(root, ".github/agents/*.md"):
                paths.append(f)

        vscode_mcp = root / ".vscode" / "mcp.json"
        if vscode_mcp.is_file():
            paths.append(vscode_mcp)

        hooks_dir = root / ".github" / "hooks"
        if hooks_dir.is_dir():
            paths.extend(sorted(hooks_dir.glob("*.json")))
        for name in ("settings.json", "settings.local.json"):
            settings = root / ".github" / "copilot" / name
            if settings.is_file():
                paths.append(settings)

        return paths

    def _discover_instructions(self, root: Path) -> list[ParsedComponent]:
        instructions = root / ".github" / "copilot-instructions.md"
        results: list[ParsedComponent] = []
        if instructions.is_file():
            results.append(
                parse_file(
                    instructions,
                    ComponentType.CLAUDE_MD,
                    name="copilot-instructions",
                    source_tool="copilot",
                )
            )
        instructions_dir = root / ".github" / "instructions"
        if instructions_dir.is_dir():
            for path in sorted(instructions_dir.rglob("*.instructions.md")):
                results.append(parse_file(path, ComponentType.CLAUDE_MD, source_tool="copilot"))
        return results

    def _discover_settings(self, root: Path) -> list[ParsedComponent]:
        results: list[ParsedComponent] = []
        for name in ("settings.json", "settings.local.json"):
            path = root / ".github" / "copilot" / name
            if path.is_file():
                results.append(
                    parse_file(path, ComponentType.CONFIG, name=name, source_tool="copilot")
                )
        return results

    def _discover_skills(self, root: Path, *, recursive: bool = False) -> list[ParsedComponent]:
        results = []
        seen_paths: set[str] = set()
        for skills_dir in (
            root / ".github" / "skills",
            root / ".agents" / "skills",
            root / ".claude" / "skills",
        ):
            if not skills_dir.is_dir():
                continue
            for skill_md in sorted(skills_dir.glob("*/SKILL.md")):
                seen_paths.add(str(skill_md.resolve()))
                results.append(
                    parse_file(
                        skill_md,
                        ComponentType.SKILL,
                        name=skill_md.parent.name,
                        source_tool="copilot",
                    )
                )
        if recursive:
            for skill_md in _recursive_glob(root, ".github/skills/*/SKILL.md"):
                resolved = str(skill_md.resolve())
                if resolved not in seen_paths:
                    seen_paths.add(resolved)
                    results.append(
                        parse_file(
                            skill_md,
                            ComponentType.SKILL,
                            name=skill_md.parent.name,
                            source_tool="copilot",
                        )
                    )
        return results

    def _discover_hooks(self, root: Path, *, recursive: bool = False) -> list[ParsedComponent]:
        results: list[ParsedComponent] = []
        seen: set[str] = set()
        candidates: list[Path] = []
        hooks_dir = root / ".github" / "hooks"
        if hooks_dir.is_dir():
            candidates.extend(sorted(hooks_dir.glob("*.json")))
        if recursive:
            candidates.extend(_recursive_glob(root, ".github/hooks/*.json"))
        for path in candidates:
            resolved = str(path.resolve())
            if resolved in seen:
                continue
            seen.add(resolved)
            results.append(parse_file(path, ComponentType.HOOKS, source_tool="copilot"))
        return results

    def _discover_commands(self, root: Path, *, recursive: bool = False) -> list[ParsedComponent]:
        results = []
        seen_paths: set[str] = set()
        commands_dir = root / ".github" / "prompts"
        if commands_dir.is_dir():
            for f in sorted(commands_dir.iterdir()):
                if f.is_file() and f.suffix == ".md":
                    seen_paths.add(str(f.resolve()))
                    results.append(
                        parse_file(f, ComponentType.COMMAND, name=f.stem, source_tool="copilot")
                    )
        if recursive:
            for f in _recursive_glob(root, ".github/prompts/*.md"):
                resolved = str(f.resolve())
                if resolved not in seen_paths:
                    seen_paths.add(resolved)
                    results.append(
                        parse_file(f, ComponentType.COMMAND, name=f.stem, source_tool="copilot")
                    )
        return results

    def _discover_agents(self, root: Path, *, recursive: bool = False) -> list[ParsedComponent]:
        results = []
        seen_paths: set[str] = set()
        agents_dir = root / ".github" / "agents"
        if agents_dir.is_dir():
            for f in sorted(agents_dir.glob("*.md")):
                if f.is_file() and is_agent_file(f):
                    seen_paths.add(str(f.resolve()))
                    results.append(parse_file(f, ComponentType.AGENT, source_tool="copilot"))
        if recursive:
            for f in _recursive_glob(root, ".github/agents/*.md"):
                resolved = str(f.resolve())
                if resolved not in seen_paths and is_agent_file(f):
                    seen_paths.add(resolved)
                    results.append(parse_file(f, ComponentType.AGENT, source_tool="copilot"))
        return results

    def _discover_mcp(self, root: Path) -> list[ParsedComponent]:
        path = root / ".vscode" / "mcp.json"
        if not path.is_file():
            return []
        keys = _json_top_level_keys(path)
        if "mcpServers" not in keys and "servers" not in keys:
            return []
        return [
            parse_file(
                path,
                ComponentType.MCP_CONFIG,
                name=".vscode/mcp.json",
                source_tool="copilot",
            )
        ]
