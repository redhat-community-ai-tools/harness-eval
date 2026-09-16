"""Base class and shared utilities for tool-specific discoverers."""

from __future__ import annotations

import json
import re
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


def _is_excluded_path(path: Path, root: Path | None = None) -> bool:
    """True if *path* is under a directory we do not scan.

    ``tests/fixtures`` is skipped relative to *root* so a self-scan does not
    treat corpus MCP configs as production, while scanning a fixture directory
    itself still works.
    """
    if any(excluded in path.parts for excluded in _EXCLUDE_DIRS):
        return True
    if root is None:
        return False
    try:
        rel_parts = path.resolve().relative_to(root.resolve()).parts
    except ValueError:
        return False
    for i, part in enumerate(rel_parts[:-1]):
        if part == "tests" and rel_parts[i + 1] == "fixtures":
            return True
    return False


def _recursive_glob(root: Path, pattern: str) -> list[Path]:
    """Glob recursively, excluding common non-project directories.

    Skips symlinks that resolve outside the repo root to prevent
    traversal into unrelated directories.
    """
    results = []
    for f in sorted(root.rglob(pattern)):
        if _is_excluded_path(f, root):
            continue
        if not f.is_file():
            continue
        if f.is_symlink() and not is_within(f, root):
            continue
        results.append(f)
    return results


def _json_top_level_keys(filepath: Path) -> set[str]:
    """Return the set of top-level keys in a JSON file, or empty on any error.

    Used to gate MCP-config discovery so that non-MCP config files (e.g. a
    Gemini settings.json with only editor prefs) are not treated as MCP
    configs and flagged by MCP rules.
    """
    try:
        data = json.loads(filepath.read_text(encoding="utf-8", errors="replace"))
    except (json.JSONDecodeError, ValueError, OSError):
        return set()
    return set(data.keys()) if isinstance(data, dict) else set()


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
        """Return every file path this discoverer would read.

        This feeds the shared setup inventory, which bounds scan limits, seeds
        the fingerprint, and drives watch mode. It must be a superset of the
        paths ``discover`` returns components for: anything missing here is read
        without being measured, and editing it does not change the fingerprint.
        ``test_inventory_covers_every_component`` enforces that.
        """


# Files that live in an agents directory but are not agent definitions: the
# directory README, an index, project meta files. A root-level ``agents/``
# directory is ambiguous (it also holds per-assistant instruction documents
# and agent-framework code), so there a file counts as an agent only when it
# opens with a YAML frontmatter block.
_NOT_AGENT_STEMS = {
    "readme",
    "index",
    "changelog",
    "contributing",
    "license",
    "agents",
    "claude",
    "template",
    "_template",
    "example",
}


def is_agent_file(path: Path, *, strict: bool = False) -> bool:
    stem = path.stem.removesuffix(".agent")
    if stem.lower() in _NOT_AGENT_STEMS:
        return False
    # ALL-CAPS names (README, CUSTOMIZATION_NOTES, WORKFLOW_EXAMPLES, ATTRIBUTION)
    # follow the documentation convention, not the agent one.
    if stem.upper() == stem and any(ch.isalpha() for ch in stem) and len(stem) > 2:
        return False
    try:
        head = path.read_text(encoding="utf-8", errors="replace")[:2048].lstrip("\ufeff")
    except OSError:
        return False
    # A Copilot path-scoped instructions file (``applyTo:`` frontmatter) is a
    # rule, not an agent, wherever it is stored.
    if head.startswith("---") and re.search(r"^applyTo\s*:", head, re.M):
        return False
    if not strict:
        return True
    return head.startswith("---")
