#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# ///
"""Generate Claude Code commands/ from .cursor/commands/ source files.

Claude Code commands delegate to skills via the Skill tool.
Cursor commands contain full instructions (no Skill tool available).
This script generates the Claude Code stubs from the Cursor source,
extracting the description from the first paragraph.

Usage:
    uv run scripts/sync_commands.py          # generate
    uv run scripts/sync_commands.py --check  # verify in sync (CI)
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CURSOR_DIR = ROOT / ".cursor" / "commands"
CLAUDE_DIR = ROOT / "commands"

STUB_TEMPLATE = """\
---
description: "{description}"
---

# {title}

Use the Skill tool to invoke `{skill_name}` explicitly.

Pass through any arguments from $ARGUMENTS (e.g., a specific path to evaluate).

If the Skill tool is not available or the skill is not found, tell the user:
- Check that `skills/{skill_name}/SKILL.md` exists in the workspace
- If not, reinstall the harness-eval plugin
"""

SKILL_NAME_MAP = {
    "harness-lint": "lint",
    "harness-review": "review",
    "harness-security": "security",
    "skill-review": "eval-skill",
    "skill-verify": "eval-skill",
}


def extract_description(content: str) -> str:
    lines = content.strip().split("\n")
    for line in lines:
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and not stripped.startswith("---"):
            return stripped.rstrip(".")
    return ""


def extract_title(content: str) -> str:
    for line in content.split("\n"):
        if line.startswith("# "):
            return line[2:].strip()
    return ""


def generate_stub(cursor_content: str, cmd_name: str) -> str:
    title = extract_title(cursor_content)
    description = extract_description(cursor_content)
    skill_name = SKILL_NAME_MAP.get(cmd_name, cmd_name)

    desc_escaped = description.replace('"', '\\"')
    return STUB_TEMPLATE.format(
        description=desc_escaped,
        title=title,
        skill_name=skill_name,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check", action="store_true", help="Check if commands are in sync (exit 1 if not)"
    )
    args = parser.parse_args()

    if not CURSOR_DIR.exists():
        print(f"Source directory not found: {CURSOR_DIR}", file=sys.stderr)
        sys.exit(1)

    CLAUDE_DIR.mkdir(parents=True, exist_ok=True)

    cursor_files = sorted(CURSOR_DIR.glob("*.md"))
    if not cursor_files:
        print("No .md files found in .cursor/commands/", file=sys.stderr)
        sys.exit(1)

    out_of_sync = []
    for cursor_file in cursor_files:
        cmd_name = cursor_file.stem
        cursor_content = cursor_file.read_text()
        stub = generate_stub(cursor_content, cmd_name)
        claude_file = CLAUDE_DIR / cursor_file.name

        if args.check:
            if not claude_file.exists():
                out_of_sync.append(f"  missing: {claude_file.relative_to(ROOT)}")
            elif claude_file.read_text() != stub:
                out_of_sync.append(f"  stale: {claude_file.relative_to(ROOT)}")
        else:
            claude_file.write_text(stub)
            print(f"  generated: {claude_file.relative_to(ROOT)}")

    if args.check and out_of_sync:
        print("Commands out of sync with .cursor/commands/ source:")
        for line in out_of_sync:
            print(line)
        print("\nRun: uv run scripts/sync_commands.py")
        sys.exit(1)
    elif args.check:
        print("Commands are in sync.")


if __name__ == "__main__":
    main()
