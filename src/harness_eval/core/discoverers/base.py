"""Base class and shared utilities for tool-specific discoverers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from harness_eval.core.types import (
    ComponentScope,
    ComponentType,
    ParsedComponent,
)
from harness_eval.utils.parsing import parse_frontmatter
from harness_eval.utils.paths import is_within
from harness_eval.utils.tokens import count_tokens

_EXCLUDE_DIRS = {
    ".git",
    "__pycache__",
    "node_modules",
    ".venv",
    "vendor",
    ".tox",
    "worktrees",
}


def _recursive_glob(root: Path, pattern: str) -> list[Path]:
    """Glob recursively, excluding common non-project directories.

    Skips symlinks that resolve outside the repo root to prevent
    traversal into unrelated directories.
    """
    results = []
    for f in sorted(root.rglob(pattern)):
        if any(excluded in f.parts for excluded in _EXCLUDE_DIRS):
            continue
        if not f.is_file():
            continue
        if f.is_symlink() and not is_within(f, root):
            continue
        results.append(f)
    return results


def parse_file(
    filepath: Path,
    component_type: ComponentType,
    name: str | None = None,
    scope: ComponentScope = ComponentScope.PROJECT,
    source_tool: str | None = None,
) -> ParsedComponent:
    """Parse a single file into a ParsedComponent."""
    content = filepath.read_text(encoding="utf-8", errors="replace")
    frontmatter, _ = parse_frontmatter(content)
    return ParsedComponent(
        component_type=component_type,
        name=name or filepath.stem,
        path=str(filepath),
        content=content,
        frontmatter=frontmatter,
        token_count=count_tokens(content),
        scope=scope,
        source_tool=source_tool,
    )


class ToolDiscoverer(ABC):
    """Base class for tool-specific setup discoverers."""

    @property
    @abstractmethod
    def tool_name(self) -> str:
        """Display name for this tool (e.g., 'Claude Code', 'Cursor')."""

    @property
    @abstractmethod
    def source_tool(self) -> str:
        """Value for ParsedComponent.source_tool (e.g., 'claude', 'cursor')."""

    @abstractmethod
    def detect(self, root: Path) -> bool:
        """Return True if this tool's setup files exist in root."""

    @abstractmethod
    def discover(
        self, root: Path, user_config_dir: Path | None = None, *, recursive: bool = False
    ) -> list[ParsedComponent]:
        """Discover all components for this tool."""

    @abstractmethod
    def collect_paths(
        self, root: Path, user_config_dir: Path | None = None, *, recursive: bool = False
    ) -> list[Path]:
        """Return file paths this discoverer would scan (for watch mode)."""
