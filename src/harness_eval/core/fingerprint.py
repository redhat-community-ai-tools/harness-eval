"""Setup fingerprinting for change detection and deduplication."""

from __future__ import annotations

import hashlib
from pathlib import Path

from harness_eval.core.inventory import collect_setup_file_paths


def _label(filepath: Path, root: Path, user_root: Path | None) -> str:
    """Stable, root-relative label for a file; user-config files get a ``~user/`` prefix."""
    for base, prefix in ((root, ""), (user_root, "~user/")):
        if base is None:
            continue
        try:
            return prefix + filepath.relative_to(base).as_posix()
        except ValueError:
            continue
    return filepath.name


def fingerprint_setup(
    setup_path: str,
    user_config_dir: str | None = None,
    *,
    recursive: bool = False,
    paths: list[Path] | None = None,
) -> str:
    """Hash the shared discoverer inventory for stable change detection.

    *paths* lets a caller that already collected the inventory (``discover_setup``)
    reuse it instead of walking the discoverers a second time.
    """
    root = Path(setup_path)
    if not root.is_dir():
        raise FileNotFoundError(f"Setup path does not exist: {setup_path}")

    user_root = Path(user_config_dir) if user_config_dir else None
    if paths is None:
        paths = collect_setup_file_paths(root, user_config_dir=user_root, recursive=recursive)

    file_hashes: list[tuple[str, str]] = []
    for filepath in paths:
        if filepath.is_file():
            content_hash = hashlib.sha256(filepath.read_bytes()).hexdigest()
            file_hashes.append((_label(filepath, root, user_root), content_hash))

    file_hashes.sort(key=lambda x: x[0])

    combined = hashlib.sha256()
    for rel_path, content_hash in file_hashes:
        combined.update(f"{rel_path}:{content_hash}\n".encode())

    return combined.hexdigest()


def fingerprints_match(a: str, b: str) -> bool:
    return a == b
