"""Shared helpers for the v8.1 configuration-integrity rules."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

_ROOT_MARKERS = (".git", "CLAUDE.md", "AGENTS.md", ".claude", ".cursor", ".mcp.json")


_CONFIG_DIRS = {
    ".claude",
    ".cursor",
    ".gemini",
    ".github",
    ".vscode",
    ".windsurf",
    ".codex",
    ".opencode",
    ".agents",
}


def project_root(start: Path) -> Path:
    """Walk up from a component path to the repository root.

    A `.git` directory wins. Otherwise the first ancestor carrying a root
    marker, skipping ancestors that are themselves assistant config
    directories (a `.claude/CLAUDE.md` does not make `.claude/` a root).
    """
    origin = start.resolve()
    cur = origin.parent if origin.is_file() else origin
    ancestors = []
    for _ in range(12):
        ancestors.append(cur)
        if cur.parent == cur:
            break
        cur = cur.parent
    for a in ancestors:
        if (a / ".git").exists():
            return a
    for a in ancestors:
        if a.name in _CONFIG_DIRS:
            continue
        if any((a / m).exists() for m in _ROOT_MARKERS):
            return a
    return origin.parent if origin.is_file() else origin


def expand_project_vars(value: str, root: Path) -> str:
    for var in (
        "$CLAUDE_PROJECT_DIR",
        "${CLAUDE_PROJECT_DIR}",
        "$CURSOR_PROJECT_DIR",
        "${CURSOR_PROJECT_DIR}",
        "$PROJECT_DIR",
        "${PROJECT_DIR}",
        "$PWD",
        "${PWD}",
    ):
        value = value.replace(var, str(root))
    return value


class DuplicateKeyError(ValueError):
    def __init__(self, key: str) -> None:
        super().__init__(key)
        self.key = key


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in pairs:
        if k in out:
            raise DuplicateKeyError(k)
        out[k] = v
    return out


def find_duplicate_keys(text: str) -> list[str]:
    """Return duplicate object keys in a JSON document, in order found (empty if valid)."""
    dupes: list[str] = []

    def hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        seen: dict[str, Any] = {}
        for k, v in pairs:
            if k in seen:
                dupes.append(k)
            seen[k] = v
        return seen

    try:
        json.loads(text, object_pairs_hook=hook)
    except json.JSONDecodeError:
        return []
    return dupes


def is_within(path: Path, root: Path) -> bool:
    try:
        Path(os.path.realpath(path)).relative_to(root.resolve())
        return True
    except ValueError:
        return False
