#!/usr/bin/env python3
"""Reject additions to changelog sections that already exist on the base branch.

Normal pull requests may add entries under ``[Unreleased]``. Release pull
requests may create a new version section. Existing release sections are
historical records, so adding content to them is almost always accidental.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from dataclasses import dataclass
from difflib import SequenceMatcher
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CHANGELOG = ROOT / "CHANGELOG.md"
SECTION_RE = re.compile(r"^## \[([^]]+)](?:\s+-.*)?\s*$")


@dataclass(frozen=True)
class ChangelogSection:
    """A second-level bracketed changelog section and its body."""

    name: str | None
    header: str | None
    header_line: int | None
    body: tuple[str, ...]
    body_start_line: int


@dataclass(frozen=True)
class Violation:
    """An added line found outside an allowed changelog section."""

    line: int
    section: str
    content: str


def parse_sections(text: str) -> list[ChangelogSection]:
    """Split changelog text into its preamble and version sections."""
    lines = text.splitlines()
    sections: list[ChangelogSection] = []
    name: str | None = None
    header: str | None = None
    header_line: int | None = None
    body_start_line = 1
    body: list[str] = []

    for line_number, line in enumerate(lines, start=1):
        match = SECTION_RE.match(line)
        if match:
            sections.append(
                ChangelogSection(
                    name=name,
                    header=header,
                    header_line=header_line,
                    body=tuple(body),
                    body_start_line=body_start_line,
                )
            )
            name = match.group(1)
            header = line
            header_line = line_number
            body_start_line = line_number + 1
            body = []
        else:
            body.append(line)

    sections.append(
        ChangelogSection(
            name=name,
            header=header,
            header_line=header_line,
            body=tuple(body),
            body_start_line=body_start_line,
        )
    )
    return sections


def _section_key(section: ChangelogSection) -> str:
    return section.name if section.name is not None else "<preamble>"


def validate_changelog(base_text: str, candidate_text: str) -> list[Violation]:
    """Return meaningful additions made to pre-existing historical sections."""
    base_sections = {_section_key(section): section for section in parse_sections(base_text)}
    candidate_sections = parse_sections(candidate_text)
    violations: list[Violation] = []

    for candidate in candidate_sections:
        key = _section_key(candidate)

        # Normal changes belong in Unreleased. A section absent from the base
        # is a newly cut release and is also allowed.
        if candidate.name == "Unreleased" or key not in base_sections:
            continue

        base = base_sections[key]
        if candidate.header != base.header and candidate.header_line is not None:
            violations.append(
                Violation(
                    line=candidate.header_line,
                    section=key,
                    content=candidate.header or "",
                )
            )

        matcher = SequenceMatcher(a=base.body, b=candidate.body, autojunk=False)
        for (
            operation,
            _base_start,
            _base_end,
            candidate_start,
            candidate_end,
        ) in matcher.get_opcodes():
            if operation not in {"insert", "replace"}:
                continue
            for offset in range(candidate_start, candidate_end):
                content = candidate.body[offset]
                if not content.strip():
                    continue
                violations.append(
                    Violation(
                        line=candidate.body_start_line + offset,
                        section=key,
                        content=content,
                    )
                )

    return violations


def _git(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        cwd=ROOT,
        check=check,
        capture_output=True,
        text=True,
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Ensure changelog additions are limited to Unreleased or a new release section."
    )
    parser.add_argument(
        "--base-ref",
        default="origin/main",
        help="Git ref used for the base CHANGELOG.md (default: origin/main).",
    )
    args = parser.parse_args()

    changed = _git("diff", "--quiet", f"{args.base_ref}...HEAD", "--", "CHANGELOG.md", check=False)
    if changed.returncode == 0:
        print("CHANGELOG.md is unchanged; scope validation skipped.")
        return 0
    if changed.returncode != 1:
        sys.stderr.write(changed.stderr)
        return changed.returncode

    try:
        base_text = _git("show", f"{args.base_ref}:CHANGELOG.md").stdout
    except subprocess.CalledProcessError as error:
        sys.stderr.write(error.stderr)
        return error.returncode

    candidate_text = CHANGELOG.read_text(encoding="utf-8")
    violations = validate_changelog(base_text, candidate_text)
    if not violations:
        print("CHANGELOG.md additions are limited to [Unreleased] or a new release section.")
        return 0

    for violation in violations:
        section = violation.section.replace("<preamble>", "the changelog preamble")
        content = (
            violation.content.strip().replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
        )
        print(
            f"::error file=CHANGELOG.md,line={violation.line}::"
            f"Added content to existing section {section}: {content}"
        )
    print("Add changelog entries under [Unreleased] instead.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
