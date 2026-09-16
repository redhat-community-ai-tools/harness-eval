"""Shared inventory of files that belong to an agent setup.

This module is the single source of truth for *which files a scan touches*.
Scan limits, fingerprints, and watch mode all read from it, so a file that
``discover_setup`` turns into a component must appear here too. The
``test_inventory_covers_every_component`` regression test enforces that.
"""

from __future__ import annotations

from pathlib import Path

from harness_eval.core.discoverers import get_all_discoverers

# Config directories swept for files no tool-specific discoverer claims.
UNCATEGORIZED_SCAN_DIRS: tuple[str, ...] = (
    ".claude",
    ".cursor",
    ".github",
    ".gemini",
    ".opencode",
    ".codex",
    ".lola",
    "skills",
    "commands",
)

BINARY_SUFFIXES = frozenset(
    {
        ".docx",
        ".doc",
        ".xlsx",
        ".xls",
        ".pptx",
        ".ppt",
        ".pdf",
        ".odt",
        ".ods",
        ".odp",
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".bmp",
        ".ico",
        ".webp",
        ".zip",
        ".gz",
        ".tar",
        ".bz2",
        ".xz",
        ".7z",
        ".rar",
        ".woff",
        ".woff2",
        ".ttf",
        ".otf",
        ".eot",
        ".pyc",
        ".pyo",
        ".so",
        ".dll",
        ".dylib",
        ".o",
        ".a",
        ".exe",
        ".bin",
        ".class",
        ".jar",
        ".war",
        ".mp3",
        ".mp4",
        ".wav",
        ".avi",
        ".mov",
        ".mkv",
        ".sqlite",
        ".db",
        ".sqlite3",
    }
)


def uncategorized_candidate_paths(root: Path) -> list[Path]:
    """Return every readable file under the agent-config directories.

    ``_discover_uncategorized`` parses the subset of these that no tool-specific
    discoverer already claimed. The inventory keeps the full candidate set so a
    file is measured and fingerprinted whether or not a discoverer claims it.
    """
    candidates: list[Path] = []
    for name in UNCATEGORIZED_SCAN_DIRS:
        scan_dir = root / name
        if not scan_dir.is_dir():
            continue
        for f in sorted(scan_dir.rglob("*")):
            if not f.is_file():
                continue
            if ".git" in f.parts or "__pycache__" in f.parts:
                continue
            if f.suffix.lower() in BINARY_SUFFIXES:
                continue
            if f.name.startswith("."):
                continue
            candidates.append(f)
    return candidates


def collect_setup_file_paths(
    root: Path,
    user_config_dir: Path | None = None,
    *,
    recursive: bool = False,
    uncategorized: list[Path] | None = None,
) -> list[Path]:
    """Return the deduplicated files that make up the setup at *root*.

    *uncategorized* lets a caller that already swept the config directories
    (``discover_setup``) reuse the result instead of globbing them twice.
    """
    paths: list[Path] = []
    for discoverer in get_all_discoverers():
        paths.extend(
            discoverer.collect_paths(root, user_config_dir=user_config_dir, recursive=recursive)
        )

    paths.extend(uncategorized_candidate_paths(root) if uncategorized is None else uncategorized)

    # A bare skill directory has no config directories at all; discover_setup
    # still parses its SKILL.md, so the inventory has to cover it.
    bare_skill = root / "SKILL.md"
    if bare_skill.is_file():
        paths.append(bare_skill)

    seen: set[str] = set()
    unique: list[Path] = []
    for path in paths:
        resolved = str(path.resolve())
        if resolved not in seen:
            seen.add(resolved)
            unique.append(path)
    return unique


__all__ = [
    "BINARY_SUFFIXES",
    "UNCATEGORIZED_SCAN_DIRS",
    "collect_setup_file_paths",
    "uncategorized_candidate_paths",
]
