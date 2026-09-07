"""YAML frontmatter and markdown parsing utilities."""

from __future__ import annotations

import re
from dataclasses import dataclass

import yaml

_FRONTMATTER_RE = re.compile(r"^---\s*\n(.*?)\n---\s*\n", re.DOTALL)


def parse_frontmatter(content: str) -> tuple[dict[str, object] | None, str]:
    """Extract YAML frontmatter from markdown content.

    Returns (frontmatter_dict, body) or (None, full_content) if no frontmatter.
    """
    # A UTF-8 byte-order mark before the opening delimiter is invisible to
    # the author and is not part of the frontmatter.
    content = content.lstrip("\ufeff")
    match = _FRONTMATTER_RE.match(content)
    if not match:
        return None, content

    try:
        fm = yaml.safe_load(match.group(1))
        if not isinstance(fm, dict):
            return None, content
        body = content[match.end() :]
        return fm, body
    except yaml.YAMLError:
        return None, content


@dataclass
class FrontmatterResult:
    """Rich frontmatter parse result with line metadata for diagnostics."""

    frontmatter: dict[str, object]
    raw_frontmatter: str
    frontmatter_start_line: int
    body: str
    body_start_line: int
    errors: list[str]


def parse_frontmatter_rich(content: str) -> FrontmatterResult:
    """Extract YAML frontmatter with line number tracking.

    Use this when you need line metadata (for rule diagnostics).
    Use parse_frontmatter() when you just need the dict and body.
    """
    errors: list[str] = []
    content = content.lstrip("\ufeff")
    lines = content.split("\n")

    if not lines or lines[0].strip() != "---":
        return FrontmatterResult(
            frontmatter={},
            raw_frontmatter="",
            frontmatter_start_line=0,
            body=content,
            body_start_line=1,
            errors=[],
        )

    end_idx = None
    for i in range(1, len(lines)):
        if lines[i].strip() == "---":
            end_idx = i
            break

    if end_idx is None:
        errors.append("Frontmatter opening '---' found but no closing '---'")
        return FrontmatterResult(
            frontmatter={},
            raw_frontmatter="",
            frontmatter_start_line=0,
            body=content,
            body_start_line=1,
            errors=errors,
        )

    raw_fm = "\n".join(lines[1:end_idx])
    body = "\n".join(lines[end_idx + 1 :])

    frontmatter: dict[str, object] = {}
    try:
        parsed = yaml.safe_load(raw_fm)
        if isinstance(parsed, dict):
            frontmatter = parsed
        else:
            errors.append("Frontmatter is not a YAML mapping")
    except yaml.YAMLError as e:
        errors.append(f"YAML parse error: {e}")

    return FrontmatterResult(
        frontmatter=frontmatter,
        raw_frontmatter=raw_fm,
        frontmatter_start_line=1,
        body=body,
        body_start_line=end_idx + 2,
        errors=errors,
    )
