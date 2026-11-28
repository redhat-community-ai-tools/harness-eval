"""Base class and shared utilities for tool-specific discoverers."""

from __future__ import annotations

import json
import re
import tomllib
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path

from harness_eval.core.types import (
    ComponentScope,
    ComponentType,
    ParsedComponent,
)
from harness_eval.utils.jsonc import strip_jsonc
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


def _is_excluded_from_scan(filepath: Path) -> bool:
    """Lazy import: setup.py imports parse_file, so this cannot be a top-level cycle."""
    from harness_eval.core.setup import is_excluded_during_scan

    return is_excluded_during_scan(filepath)


def _json_top_level_keys(filepath: Path) -> set[str]:
    """Return the set of top-level keys in a JSON file, or empty on any error.

    Used to gate MCP-config discovery so that non-MCP config files (e.g. a
    Gemini settings.json with only editor prefs) are not treated as MCP
    configs and flagged by MCP rules.
    """
    if _is_excluded_from_scan(filepath):
        return set()
    try:
        data = json.loads(filepath.read_text(encoding="utf-8", errors="replace"))
    except (json.JSONDecodeError, ValueError, OSError):
        return set()
    return set(data.keys()) if isinstance(data, dict) else set()


def _jsonc_top_level_keys(filepath: Path) -> set[str]:
    """Return top-level keys from JSON or JSONC configuration."""
    keys = _json_top_level_keys(filepath)
    if keys:
        return keys
    if _is_excluded_from_scan(filepath):
        return set()
    try:
        raw = filepath.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return set()
    try:
        data = json.loads(strip_jsonc(raw))
    except (json.JSONDecodeError, ValueError):
        return set()
    return set(data.keys()) if isinstance(data, dict) else set()


def _toml_top_level_keys(filepath: Path) -> set[str]:
    """Return top-level keys from a TOML configuration."""
    if _is_excluded_from_scan(filepath):
        return set()
    try:
        data = tomllib.loads(filepath.read_text(encoding="utf-8", errors="replace"))
    except (OSError, tomllib.TOMLDecodeError):
        return set()
    return set(data.keys()) if isinstance(data, dict) else set()


@dataclass(frozen=True)
class SourceEntry:
    """One row in a discoverer's declarative source table.

    Attributes
    ----------
    pattern:
        Relative path or glob (e.g. ``".cursor/rules/*.mdc"``).
    component_type:
        The :class:`ComponentType` for discovered components.
    recursive:
        When True, also search nested project directories via
        :func:`_recursive_glob`.
    deep:
        When True, use ``rglob`` instead of ``glob`` within the target
        directory.  Useful for rules directories that may contain
        subdirectories.
    source_tool:
        Override for the discoverer's :attr:`~ToolDiscoverer.source_tool`.
        ``None`` uses the discoverer's default.
    name_mode:
        How to compute the component name from the matched file:

        ``"stem"``
            ``f.stem`` — default for rules, commands.
        ``"parent"``
            ``f.parent.name`` — for skills (directory name is the name).
        ``"literal"``
            Use the fixed value in *name_literal*.
        ``"literal_or_relative"``
            Use *name_literal* for root-level matches, the relative path
            for nested matches found via recursive scan.
    name_literal:
        Fixed name for ``name_mode="literal"`` or the root-level fallback
        for ``name_mode="literal_or_relative"``.
    """

    pattern: str
    component_type: ComponentType
    recursive: bool = False
    deep: bool = False
    source_tool: str | None = None
    name_mode: str = "stem"
    name_literal: str | None = None


def _has_glob(pattern: str) -> bool:
    """Return True if *pattern* contains glob metacharacters."""
    return any(c in pattern for c in ("*", "?", "["))


def _split_at_glob(pattern: str) -> tuple[str, str]:
    """Split *pattern* into ``(directory-prefix, glob-suffix)``.

    The split happens at the first path component that contains a glob
    metacharacter.  Returns ``(pattern, "")`` when there is none.
    """
    parts = pattern.split("/")
    for i, part in enumerate(parts):
        if any(c in part for c in ("*", "?", "[")):
            return "/".join(parts[:i]), "/".join(parts[i:])
    return pattern, ""


def parse_file(
    filepath: Path,
    component_type: ComponentType,
    name: str | None = None,
    scope: ComponentScope = ComponentScope.PROJECT,
    source_tool: str | None = None,
) -> ParsedComponent:
    """Parse a single file into a ParsedComponent."""
    if _is_excluded_from_scan(filepath):
        return ParsedComponent(
            component_type=component_type,
            name=name or filepath.stem,
            path=str(filepath),
            content="",
            token_count=0,
            scope=scope,
            source_tool=source_tool,
        )
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
    """Base class for tool-specific setup discoverers.

    Subclasses may either override :meth:`discover` and :meth:`collect_paths`
    directly (the traditional approach), or populate :attr:`source_entries` to
    let the base class derive both methods from a single declarative table.
    Override hooks :meth:`_extra_collect_paths` and :meth:`_extra_discover`
    handle special cases that the table cannot express.
    """

    @property
    @abstractmethod
    def tool_name(self) -> str:
        """Display name for this tool (e.g., 'Claude Code', 'Cursor')."""

    @property
    @abstractmethod
    def source_tool(self) -> str:
        """Value for ParsedComponent.source_tool (e.g., 'claude', 'cursor')."""

    @property
    def discovery_summary(self) -> str:
        """Human-readable summary of paths this discoverer checks.

        Used to auto-generate the README discovery table.  Keep entries
        as backtick-quoted path patterns separated by commas, matching the
        style of the existing "What it discovers" table.

        The default returns an empty string so that third-party
        ``ToolDiscoverer`` subclasses are not forced to implement it.
        """
        return ""

    # --- declarative source table -------------------------------------------

    @property
    def source_entries(self) -> tuple[SourceEntry, ...]:
        """Declarative table of sources this discoverer handles.

        When non-empty, the base class derives :meth:`collect_paths` and
        :meth:`discover` from this table automatically.  Subclasses that
        populate this property can omit those two methods unless they need
        the override hooks :meth:`_extra_collect_paths` and
        :meth:`_extra_discover`.
        """
        return ()

    # --- table-driven helpers -----------------------------------------------

    def _collect_entry_paths(
        self, root: Path, entry: SourceEntry, *, recursive: bool
    ) -> list[Path]:
        """Return files matching one :class:`SourceEntry`."""
        paths: list[Path] = []
        pattern = entry.pattern
        if _has_glob(pattern):
            dir_part, glob_part = _split_at_glob(pattern)
            dir_path = root / dir_part if dir_part else root
            if dir_path.is_dir():
                fn = dir_path.rglob if entry.deep else dir_path.glob
                for f in sorted(fn(glob_part)):
                    if f.is_file() and not _is_excluded_path(f, root):
                        paths.append(f)
        else:
            filepath = root / pattern
            if filepath.is_file():
                paths.append(filepath)
        if entry.recursive and recursive:
            paths.extend(_recursive_glob(root, pattern))
        return paths

    def _entry_name(self, f: Path, root: Path, entry: SourceEntry) -> str:
        """Compute the component name for *f* based on *entry.name_mode*."""
        if entry.name_mode == "parent":
            return f.parent.name
        if entry.name_mode == "literal":
            return entry.name_literal or f.stem
        if entry.name_mode == "literal_or_relative":
            rel = f.relative_to(root)
            if str(rel) == entry.pattern:
                return entry.name_literal or entry.pattern
            return str(rel)
        # default: "stem"
        return f.stem

    def _extra_collect_paths(
        self,
        root: Path,
        user_config_dir: Path | None = None,
        *,
        recursive: bool = False,
    ) -> list[Path]:
        """Override hook for paths not covered by :attr:`source_entries`."""
        return []

    def _extra_discover(
        self,
        root: Path,
        user_config_dir: Path | None = None,
        seen: set[str] | None = None,
        *,
        recursive: bool = False,
    ) -> list[ParsedComponent]:
        """Override hook for components not covered by :attr:`source_entries`."""
        return []

    # --- core discovery methods ---------------------------------------------

    @abstractmethod
    def detect(self, root: Path) -> bool:
        """Return True if this tool's setup files exist in root."""

    def discover(
        self, root: Path, user_config_dir: Path | None = None, *, recursive: bool = False
    ) -> list[ParsedComponent]:
        """Discover all components for this tool.

        When :attr:`source_entries` is populated, the default implementation
        iterates over the table and deduplicates by resolved path.
        Subclasses without a table must override this method.
        """
        if not self.source_entries:
            raise NotImplementedError(
                f"{type(self).__name__} must either populate source_entries or override discover()"
            )
        results: list[ParsedComponent] = []
        seen: set[str] = set()
        for entry in self.source_entries:
            source = entry.source_tool if entry.source_tool is not None else self.source_tool
            for f in self._collect_entry_paths(root, entry, recursive=recursive):
                resolved = str(f.resolve())
                if resolved in seen:
                    continue
                seen.add(resolved)
                name = self._entry_name(f, root, entry)
                results.append(parse_file(f, entry.component_type, name=name, source_tool=source))
        results.extend(self._extra_discover(root, user_config_dir, seen, recursive=recursive))
        return results

    def collect_paths(
        self, root: Path, user_config_dir: Path | None = None, *, recursive: bool = False
    ) -> list[Path]:
        """Return every file path this discoverer would read.

        This feeds the shared setup inventory, which bounds scan limits, seeds
        the fingerprint, and drives watch mode.  It must be a superset of the
        paths ``discover`` returns components for: anything missing here is read
        without being measured, and editing it does not change the fingerprint.
        ``test_inventory_covers_every_component`` enforces that.

        When :attr:`source_entries` is populated, the default implementation
        iterates over the table.  Subclasses without a table must override.
        """
        if not self.source_entries:
            raise NotImplementedError(
                f"{type(self).__name__} must either populate source_entries "
                f"or override collect_paths()"
            )
        paths: list[Path] = []
        for entry in self.source_entries:
            paths.extend(self._collect_entry_paths(root, entry, recursive=recursive))
        paths.extend(self._extra_collect_paths(root, user_config_dir, recursive=recursive))
        return paths


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
    if _is_excluded_from_scan(path):
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
