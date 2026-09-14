"""Shared inventory of files that belong to an agent setup."""

from __future__ import annotations

from pathlib import Path

from harness_eval.core.discoverers import get_all_discoverers


def collect_setup_file_paths(
    root: Path,
    user_config_dir: Path | None = None,
    *,
    recursive: bool = False,
) -> list[Path]:
    """Return the deduplicated files exposed by all discoverers."""
    paths: list[Path] = []
    for discoverer in get_all_discoverers():
        paths.extend(
            discoverer.collect_paths(root, user_config_dir=user_config_dir, recursive=recursive)
        )

    seen: set[str] = set()
    unique: list[Path] = []
    for path in paths:
        resolved = str(path.resolve())
        if resolved not in seen:
            seen.add(resolved)
            unique.append(path)
    return unique


__all__ = ["collect_setup_file_paths"]
