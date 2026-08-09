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
        return target.is_file() or target.is_dir()

    def discover(
        self, root: Path, user_config_dir: Path | None = None, *, recursive: bool = False
    ) -> list[ParsedComponent]:
        return self._discover_rules(root, recursive=recursive)

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
                _add(f, f.stem)

        if recursive:
            for f in _recursive_glob(root, ".clinerules"):
                rel = f.relative_to(root)
                _add(f, str(rel) if rel != Path(".clinerules") else ".clinerules")
            for f in _recursive_glob(root, ".clinerules/*.md"):
                _add(f, f.stem)

        return results
