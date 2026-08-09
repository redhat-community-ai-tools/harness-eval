"""GitHub Copilot setup discoverer."""

from __future__ import annotations

from pathlib import Path

from harness_eval.core.discoverers.base import ToolDiscoverer, _recursive_glob, parse_file
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
        )

    def discover(
        self, root: Path, user_config_dir: Path | None = None, *, recursive: bool = False
    ) -> list[ParsedComponent]:
        results: list[ParsedComponent] = []
        results.extend(self._discover_instructions(root))
        results.extend(self._discover_skills(root, recursive=recursive))
        results.extend(self._discover_commands(root, recursive=recursive))
        results.extend(self._discover_agents(root, recursive=recursive))
        return results

    def collect_paths(
        self, root: Path, user_config_dir: Path | None = None, *, recursive: bool = False
    ) -> list[Path]:
        paths: list[Path] = []

        instructions = root / ".github" / "copilot-instructions.md"
        if instructions.is_file():
            paths.append(instructions)

        # Copilot skills
        copilot_skills = root / ".github" / "skills"
        if copilot_skills.is_dir():
            for f in sorted(copilot_skills.rglob("SKILL.md")):
                paths.append(f)
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

        return paths

    def _discover_instructions(self, root: Path) -> list[ParsedComponent]:
        instructions = root / ".github" / "copilot-instructions.md"
        if instructions.is_file():
            return [
                parse_file(
                    instructions,
                    ComponentType.CLAUDE_MD,
                    name="copilot-instructions",
                    source_tool="copilot",
                )
            ]
        return []

    def _discover_skills(self, root: Path, *, recursive: bool = False) -> list[ParsedComponent]:
        results = []
        seen_paths: set[str] = set()
        skills_dir = root / ".github" / "skills"
        if skills_dir.is_dir():
            for skill_md in sorted(skills_dir.rglob("SKILL.md")):
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
                if f.is_file():
                    seen_paths.add(str(f.resolve()))
                    results.append(parse_file(f, ComponentType.AGENT, source_tool="copilot"))
        if recursive:
            for f in _recursive_glob(root, ".github/agents/*.md"):
                resolved = str(f.resolve())
                if resolved not in seen_paths:
                    seen_paths.add(resolved)
                    results.append(parse_file(f, ComponentType.AGENT, source_tool="copilot"))
        return results
