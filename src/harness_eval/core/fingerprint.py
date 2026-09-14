"""Setup fingerprinting for change detection and deduplication."""

from __future__ import annotations

import hashlib
from pathlib import Path

from harness_eval.core.inventory import collect_setup_file_paths


def fingerprint_setup(
    setup_path: str,
    user_config_dir: str | None = None,
    *,
    recursive: bool = False,
) -> str:
    """Hash the shared discoverer inventory for stable change detection."""
    root = Path(setup_path)
    if not root.is_dir():
        raise FileNotFoundError(f"Setup path does not exist: {setup_path}")

    file_hashes: list[tuple[str, str]] = []

    for filepath in collect_setup_file_paths(
        root,
        user_config_dir=Path(user_config_dir) if user_config_dir else None,
        recursive=recursive,
    ):
        if filepath.is_file():
            try:
                rel = str(filepath.relative_to(root))
            except ValueError:
                user_root = Path(user_config_dir) if user_config_dir else None
                if user_root is not None:
                    rel = f"~user/{filepath.relative_to(user_root).as_posix()}"
                else:
                    rel = filepath.name
            content_hash = hashlib.sha256(filepath.read_bytes()).hexdigest()
            file_hashes.append((rel, content_hash))

    file_hashes.sort(key=lambda x: x[0])

    combined = hashlib.sha256()
    for rel_path, content_hash in file_hashes:
        combined.update(f"{rel_path}:{content_hash}\n".encode())

    return combined.hexdigest()


def fingerprints_match(a: str, b: str) -> bool:
    return a == b
