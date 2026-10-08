"""One directory walk for everything that reads a component's files.

Discovery already filters the inventory with the scan's exclude patterns.
Rules and the component graph that look inside a skill directory used to
``rglob`` on their own, so an excluded file could still be read. They now go
through :func:`iter_files`, which applies the same patterns.
"""

from __future__ import annotations

from pathlib import Path

from harness_eval.core.setup import matches_exclude

_SKIP_PARTS = {".git", "__pycache__"}


def iter_files(
    root_dir: Path | str,
    pattern: str = "*",
    *,
    excludes: tuple[str, ...] = (),
    project_root: Path | str | None = None,
) -> list[Path]:
    """Sorted paths under *root_dir* matching *pattern*, minus ``.git`` and
    ``__pycache__`` contents and anything an exclude pattern matches.
    Directories and symlinks are included; callers filter by kind."""
    root = Path(root_dir)
    if not root.is_dir():
        return []
    base = Path(project_root).resolve() if project_root is not None else root.resolve()
    out: list[Path] = []
    for p in sorted(root.rglob(pattern)):
        if _SKIP_PARTS.intersection(p.parts):
            continue
        if excludes and matches_exclude(str(p), base, excludes):
            continue
        out.append(p)
    return out
