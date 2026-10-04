"""Windsurf setup discoverer."""

from __future__ import annotations

from pathlib import Path

from harness_eval.core.discoverers.base import ToolDiscoverer, _recursive_glob, parse_file
from harness_eval.core.types import ComponentType, ParsedComponent


class WindsurfDiscoverer(ToolDiscoverer):
    """Discovers Windsurf setup components.

    Windsurf stores its system instructions as plain markdown, mirroring
    Cursor: a single ``.windsurfrules`` file and/or per-topic files under
    ``.windsurf/rules/``. Both map to CLAUDE_MD components.
    """

    @property
    def tool_name(self) -> str:
        return "Windsurf"

    @property
    def source_tool(self) -> str:
        return "windsurf"

    def detect(self, root: Path) -> bool:
        return (
            (root / ".devin").is_dir()
            or (root / ".windsurf").is_dir()
            or (root / ".windsurfrules").is_file()
        )

    def discover(
        self, root: Path, user_config_dir: Path | None = None, *, recursive: bool = False
    ) -> list[ParsedComponent]:
        results = self._discover_rules(root, recursive=recursive)
        results.extend(self._discover_skills(root, recursive=recursive))
        results.extend(self._discover_workflows(root, recursive=recursive))
        results.extend(self._discover_hooks(root, recursive=recursive))
        results.extend(self._discover_mcp(root))
        results.extend(self._discover_agents_md(root, recursive=recursive))
        return results

    def collect_paths(
        self, root: Path, user_config_dir: Path | None = None, *, recursive: bool = False
    ) -> list[Path]:
        paths: list[Path] = []

        for rules_dir in (root / ".devin" / "rules", root / ".windsurf" / "rules"):
            if rules_dir.is_dir():
                paths.extend(sorted(rules_dir.rglob("*.md")))
        if recursive:
            paths.extend(_recursive_glob(root, ".windsurf/rules/*.md"))

        top = root / ".windsurfrules"
        if top.is_file():
            paths.append(top)
        if recursive:
            paths.extend(_recursive_glob(root, ".windsurfrules"))

        for base in (root / ".devin", root / ".windsurf"):
            for child, pattern in (("skills", "*/SKILL.md"), ("workflows", "*.md")):
                directory = base / child
                if directory.is_dir():
                    paths.extend(sorted(directory.glob(pattern)))
        agents_skills = root / ".agents" / "skills"
        if agents_skills.is_dir():
            paths.extend(sorted(agents_skills.glob("*/SKILL.md")))
        hooks = root / ".windsurf" / "hooks.json"
        if hooks.is_file():
            paths.append(hooks)
        mcp = root / ".windsurf" / "mcp_config.json"
        if mcp.is_file():
            paths.append(mcp)
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
                    parse_file(f, ComponentType.CLAUDE_MD, name=name, source_tool="windsurf")
                )

        for rules_dir in (root / ".devin" / "rules", root / ".windsurf" / "rules"):
            if rules_dir.is_dir():
                for f in sorted(rules_dir.rglob("*.md")):
                    _add(f, f.stem)
        if recursive:
            for f in _recursive_glob(root, ".windsurf/rules/*.md"):
                _add(f, f.stem)

        top = root / ".windsurfrules"
        if top.is_file():
            _add(top, ".windsurfrules")
        if recursive:
            for f in _recursive_glob(root, ".windsurfrules"):
                rel = f.relative_to(root)
                _add(f, str(rel) if rel != Path(".windsurfrules") else ".windsurfrules")

        return results

    def _discover_skills(self, root: Path, *, recursive: bool = False) -> list[ParsedComponent]:
        results: list[ParsedComponent] = []
        seen: set[str] = set()
        candidates: list[Path] = []
        for directory in (
            root / ".devin" / "skills",
            root / ".windsurf" / "skills",
            root / ".agents" / "skills",
        ):
            if directory.is_dir():
                candidates.extend(sorted(directory.glob("*/SKILL.md")))
        if recursive:
            for pattern in (
                ".devin/skills/*/SKILL.md",
                ".windsurf/skills/*/SKILL.md",
                ".agents/skills/*/SKILL.md",
            ):
                candidates.extend(_recursive_glob(root, pattern))
        for path in candidates:
            resolved = str(path.resolve())
            if resolved in seen:
                continue
            seen.add(resolved)
            results.append(
                parse_file(path, ComponentType.SKILL, name=path.parent.name, source_tool="windsurf")
            )
        return results

    def _discover_workflows(self, root: Path, *, recursive: bool = False) -> list[ParsedComponent]:
        results: list[ParsedComponent] = []
        seen: set[str] = set()
        candidates: list[Path] = []
        for directory in (root / ".devin" / "workflows", root / ".windsurf" / "workflows"):
            if directory.is_dir():
                candidates.extend(sorted(directory.glob("*.md")))
        if recursive:
            for pattern in (".devin/workflows/*.md", ".windsurf/workflows/*.md"):
                candidates.extend(_recursive_glob(root, pattern))
        for path in candidates:
            resolved = str(path.resolve())
            if resolved in seen:
                continue
            seen.add(resolved)
            results.append(
                parse_file(path, ComponentType.COMMAND, name=path.stem, source_tool="windsurf")
            )
        return results

    def _discover_hooks(self, root: Path, *, recursive: bool = False) -> list[ParsedComponent]:
        path = root / ".windsurf" / "hooks.json"
        if not path.is_file():
            return []
        return [parse_file(path, ComponentType.HOOKS, source_tool="windsurf")]

    def _discover_mcp(self, root: Path) -> list[ParsedComponent]:
        path = root / ".windsurf" / "mcp_config.json"
        if not path.is_file():
            return []
        return [parse_file(path, ComponentType.MCP_CONFIG, source_tool="windsurf")]

    def _discover_agents_md(self, root: Path, *, recursive: bool = False) -> list[ParsedComponent]:
        results: list[ParsedComponent] = []
        paths = [root / "AGENTS.md"]
        if recursive:
            paths.extend(_recursive_glob(root, "AGENTS.md"))
        seen: set[str] = set()
        for path in paths:
            if path.is_file() and str(path.resolve()) not in seen:
                seen.add(str(path.resolve()))
                results.append(parse_file(path, ComponentType.CLAUDE_MD, source_tool="agents-md"))
        return results
