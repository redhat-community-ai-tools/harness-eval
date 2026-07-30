#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# ///
"""Release helper: bump version, move changelog entries, commit, and tag.

Usage:
    uv run scripts/release.py patch   # 0.1.0 -> 0.1.1
    uv run scripts/release.py minor   # 0.1.0 -> 0.2.0
    uv run scripts/release.py major   # 0.1.0 -> 1.0.0
    uv run scripts/release.py 0.3.0   # explicit version

    --dry-run    Show what would happen without making changes.
    --no-commit  Update files but skip git commit and tag.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = ROOT / "pyproject.toml"
CHANGELOG = ROOT / "CHANGELOG.md"
INIT_PY = ROOT / "src" / "harness_eval" / "__init__.py"
TEKTON_TASK = ROOT / "tekton" / "task-harness-eval.yaml"
PLUGIN_MANIFESTS = [
    ROOT / ".claude-plugin" / "marketplace.json",
    ROOT / ".claude-plugin" / "plugin.json",
]


def read_current_version() -> str:
    text = PYPROJECT.read_text()
    match = re.search(r'^version\s*=\s*"(.+?)"', text, re.MULTILINE)
    if not match:
        sys.exit("Could not find version in pyproject.toml")
    return match.group(1)


def bump(current: str, bump_type: str) -> str:
    parts = [int(p) for p in current.split(".")]
    if len(parts) != 3:
        sys.exit(f"Version {current!r} is not semver (X.Y.Z)")

    if bump_type == "patch":
        parts[2] += 1
    elif bump_type == "minor":
        parts[1] += 1
        parts[2] = 0
    elif bump_type == "major":
        parts[0] += 1
        parts[1] = 0
        parts[2] = 0
    else:
        sys.exit(f"Unknown bump type: {bump_type!r}")
    return ".".join(str(p) for p in parts)


def resolve_new_version(arg: str, current: str) -> str:
    if arg in ("patch", "minor", "major"):
        return bump(current, arg)
    if re.match(r"^\d+\.\d+\.\d+$", arg):
        return arg
    sys.exit(f"Invalid version argument: {arg!r}. Use patch/minor/major or X.Y.Z.")


def update_pyproject(new_version: str, dry_run: bool) -> None:
    text = PYPROJECT.read_text()
    updated = re.sub(
        r'^(version\s*=\s*)"(.+?)"',
        rf'\g<1>"{new_version}"',
        text,
        count=1,
        flags=re.MULTILINE,
    )
    if dry_run:
        print(f"  [dry-run] Would update pyproject.toml version to {new_version}")
        return
    PYPROJECT.write_text(updated)


def update_changelog(new_version: str, dry_run: bool) -> bool:
    text = CHANGELOG.read_text()

    unreleased_pattern = re.compile(r"^## \[Unreleased\]\s*$", re.MULTILINE)
    match = unreleased_pattern.search(text)
    if not match:
        print("  No [Unreleased] section found in CHANGELOG.md, skipping.")
        return False

    next_section = re.search(r"^## \[", text[match.end() :], re.MULTILINE)
    if next_section:
        unreleased_content = text[match.end() : match.end() + next_section.start()]
    else:
        unreleased_content = text[match.end() :]

    stripped = unreleased_content.strip()
    if not stripped:
        print("  [Unreleased] section is empty, nothing to move.")
        return False

    today = date.today().isoformat()
    new_header = f"## [{new_version}] - {today}"
    replacement = f"## [Unreleased]\n\n{new_header}\n\n{stripped}\n"

    updated = text[: match.start()] + replacement
    if next_section:
        updated += "\n" + text[match.end() + next_section.start() :]

    if dry_run:
        print(f"  [dry-run] Would move [Unreleased] entries to [{new_version}] - {today}")
        print(f"  [dry-run] Entries:\n{stripped[:200]}...")
        return True

    CHANGELOG.write_text(updated)
    return True


def update_init_py(new_version: str, dry_run: bool) -> None:
    if not INIT_PY.exists():
        return
    text = INIT_PY.read_text()
    updated = re.sub(
        r'__version__\s*=\s*"[^"]+"',
        f'__version__ = "{new_version}"',
        text,
        count=1,
    )
    if dry_run:
        print(f"  [dry-run] Would update __init__.py version to {new_version}")
        return
    INIT_PY.write_text(updated)


def update_tekton_task(new_version: str, dry_run: bool) -> None:
    if not TEKTON_TASK.exists():
        return
    text = TEKTON_TASK.read_text()
    updated = re.sub(
        r'(app\.kubernetes\.io/version:\s*)"[^"]+"',
        rf'\g<1>"{new_version}"',
        text,
        count=1,
    )
    if dry_run:
        print(f"  [dry-run] Would update tekton task version to {new_version}")
        return
    TEKTON_TASK.write_text(updated)


def update_plugin_manifests(new_version: str, dry_run: bool) -> None:
    for manifest in PLUGIN_MANIFESTS:
        if not manifest.exists():
            continue
        text = manifest.read_text()
        updated = re.sub(
            r'"version"\s*:\s*"[^"]+"',
            f'"version": "{new_version}"',
            text,
            count=1,
        )
        if dry_run:
            print(f"  [dry-run] Would update {manifest.name} version to {new_version}")
            continue
        manifest.write_text(updated)


def git_commit_and_tag(new_version: str, dry_run: bool) -> None:
    tag = f"v{new_version}"
    msg = f"release: {tag}"

    if dry_run:
        print(f"  [dry-run] Would commit with message: {msg!r}")
        print(f"  [dry-run] Would create tag: {tag}")
        return

    files_to_add = [str(PYPROJECT), str(CHANGELOG), str(INIT_PY)]
    if TEKTON_TASK.exists():
        files_to_add.append(str(TEKTON_TASK))
    for manifest in PLUGIN_MANIFESTS:
        if manifest.exists():
            files_to_add.append(str(manifest))

    subprocess.run(
        ["git", "add", *files_to_add],
        cwd=ROOT,
        check=True,
    )
    subprocess.run(
        ["git", "commit", "-m", msg],
        cwd=ROOT,
        check=True,
    )
    subprocess.run(
        ["git", "tag", "-a", tag, "-m", msg],
        cwd=ROOT,
        check=True,
    )
    print(f"\n  Committed and tagged {tag}.")

    print(f"  Pushing main and {tag} to origin...")
    subprocess.run(
        ["git", "push", "origin", "main", "--tags"],
        cwd=ROOT,
        check=True,
    )
    print(f"  Pushed. PyPI publish and GitHub Release will be created automatically.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Bump version and cut a release.")
    parser.add_argument(
        "version",
        help="Bump type (patch/minor/major) or explicit version (X.Y.Z).",
    )
    parser.add_argument("--dry-run", action="store_true", help="Preview without changing files.")
    parser.add_argument("--no-commit", action="store_true", help="Update files but skip git.")
    args = parser.parse_args()

    current = read_current_version()
    new_version = resolve_new_version(args.version, current)

    print(f"Release: {current} -> {new_version}")
    print()

    print("1. Updating pyproject.toml...")
    update_pyproject(new_version, args.dry_run)

    print("2. Updating CHANGELOG.md...")
    changelog_updated = update_changelog(new_version, args.dry_run)

    print("3. Updating __init__.py...")
    update_init_py(new_version, args.dry_run)

    print("4. Updating tekton task...")
    update_tekton_task(new_version, args.dry_run)

    print("5. Updating plugin manifests...")
    update_plugin_manifests(new_version, args.dry_run)

    if not changelog_updated and not args.dry_run:
        print("\n  Warning: No changelog entries moved. Consider adding entries before releasing.")

    if not args.no_commit:
        print("6. Committing and tagging...")
        git_commit_and_tag(new_version, args.dry_run)
    else:
        print("6. Skipping git commit/tag (--no-commit).")

    print("\nDone.")


if __name__ == "__main__":
    main()
