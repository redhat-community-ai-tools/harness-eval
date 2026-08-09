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
        return (root / ".windsurf").is_dir() or (root / ".windsurfrules").is_file()

    def discover(
        self, root: Path, user_config_dir: Path | None = None, *, recursive: bool = False
    ) -> list[ParsedComponent]:
        return self._discover_rules(root, recursive=recursive)

    def collect_paths(
        self, root: Path, user_config_dir: Path | None = None, *, recursive: bool = False
    ) -> list[Path]:
        paths: list[Path] = []

        rules_dir = root / ".windsurf" / "rules"
        if rules_dir.is_dir():
            for f in sorted(rules_dir.rglob("*.md")):
                if f.is_file():
                    paths.append(f)
        if recursive:
            paths.extend(_recursive_glob(root, ".windsurf/rules/*.md"))

        top = root / ".windsurfrules"
        if top.is_file():
            paths.append(top)
        if recursive:
            paths.extend(_recursive_glob(root, ".windsurfrules"))

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

        rules_dir = root / ".windsurf" / "rules"
        if rules_dir.is_dir():
            for f in sorted(rules_dir.rglob("*.md")):
                if f.is_file():
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
