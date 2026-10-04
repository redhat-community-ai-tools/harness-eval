"""Cline setup discoverer."""

from __future__ import annotations

from pathlib import Path

from harness_eval.core.discoverers.base import ToolDiscoverer, _recursive_glob, parse_file
from harness_eval.core.types import ComponentType, ParsedComponent


class ClineDiscoverer(ToolDiscoverer):
    """Discovers Cline setup components.

    Cline supports either a single ``.clinerules`` file or a ``.clinerules/``
    directory of per-topic markdown files. Both map to CLAUDE_MD components.
    """

    @property
    def tool_name(self) -> str:
        return "Cline"

    @property
    def source_tool(self) -> str:
        return "cline"

    def detect(self, root: Path) -> bool:
        target = root / ".clinerules"
        return target.is_file() or target.is_dir() or (root / ".cline").is_dir()

    def discover(
        self, root: Path, user_config_dir: Path | None = None, *, recursive: bool = False
    ) -> list[ParsedComponent]:
        results = self._discover_rules(root, recursive=recursive)
        results.extend(self._discover_skills(root, recursive=recursive))
        results.extend(self._discover_agents_md(root, recursive=recursive))
        return results

    def collect_paths(
        self, root: Path, user_config_dir: Path | None = None, *, recursive: bool = False
    ) -> list[Path]:
        paths: list[Path] = []

        target = root / ".clinerules"
        if target.is_file():
            paths.append(target)
        elif target.is_dir():
            for f in sorted(target.rglob("*.md")):
                if f.is_file():
                    paths.append(f)
        if recursive:
            paths.extend(_recursive_glob(root, ".clinerules"))
            paths.extend(_recursive_glob(root, ".clinerules/*.md"))

        cline_rules = root / ".cline" / "rules"
        if cline_rules.is_dir():
            paths.extend(sorted(cline_rules.rglob("*.md")))
        for skills_dir in (
            root / ".cline" / "skills",
            root / ".clinerules" / "skills",
            root / ".claude" / "skills",
        ):
            if skills_dir.is_dir():
                paths.extend(sorted(skills_dir.glob("*/SKILL.md")))
        agents_md = root / "AGENTS.md"
        if agents_md.is_file():
            paths.append(agents_md)

        return paths

    def _discover_rules(self, root: Path, *, recursive: bool = False) -> list[ParsedComponent]:
        results: list[ParsedComponent] = []
        seen_paths: set[str] = set()

        def _add(f: Path, name: str) -> None:
            if not f.is_file():
                return
            resolved = str(f.resolve())
            if resolved not in seen_paths:
                seen_paths.add(resolved)
                results.append(
                    parse_file(f, ComponentType.CLAUDE_MD, name=name, source_tool="cline")
                )

        target = root / ".clinerules"
        if target.is_file():
            _add(target, ".clinerules")
        elif target.is_dir():
            for f in sorted(target.rglob("*.md")):
                if "skills" in f.parts:
                    continue
                _add(f, f.stem)

        cline_rules = root / ".cline" / "rules"
        if cline_rules.is_dir():
            for f in sorted(cline_rules.rglob("*.md")):
                _add(f, f.stem)

        if recursive:
            for f in _recursive_glob(root, ".clinerules"):
                rel = f.relative_to(root)
                _add(f, str(rel) if rel != Path(".clinerules") else ".clinerules")
            for f in _recursive_glob(root, ".clinerules/*.md"):
                _add(f, f.stem)

        return results

    def _discover_skills(self, root: Path, *, recursive: bool = False) -> list[ParsedComponent]:
        results: list[ParsedComponent] = []
        seen: set[str] = set()
        candidates: list[Path] = []
        for skills_dir in (
            root / ".cline" / "skills",
            root / ".clinerules" / "skills",
            root / ".claude" / "skills",
        ):
            if skills_dir.is_dir():
                candidates.extend(sorted(skills_dir.glob("*/SKILL.md")))
        if recursive:
            for pattern in (
                ".cline/skills/*/SKILL.md",
                ".clinerules/skills/*/SKILL.md",
                ".claude/skills/*/SKILL.md",
            ):
                candidates.extend(_recursive_glob(root, pattern))
        for path in candidates:
            resolved = str(path.resolve())
            if resolved in seen:
                continue
            seen.add(resolved)
            results.append(
                parse_file(path, ComponentType.SKILL, name=path.parent.name, source_tool="cline")
            )
        return results

    def _discover_agents_md(self, root: Path, *, recursive: bool = False) -> list[ParsedComponent]:
        results: list[ParsedComponent] = []
        candidates = [root / "AGENTS.md"]
        if recursive:
            candidates.extend(_recursive_glob(root, "AGENTS.md"))
        seen: set[str] = set()
        for path in candidates:
            if path.is_file() and str(path.resolve()) not in seen:
                seen.add(str(path.resolve()))
                results.append(parse_file(path, ComponentType.CLAUDE_MD, source_tool="agents-md"))
        return results
