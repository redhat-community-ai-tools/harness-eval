"""Shared scanning logic for inspection rules across component types."""

from __future__ import annotations

import re
from collections.abc import Sequence

from harness_eval.core.types import ComponentType
from harness_eval.inspection.types import (
    Location,
    ReportDescriptor,
    RuleContext,
    Severity,
)

TOOL_DIRECTIVE_RE = re.compile(r"(?:use the|run|call|invoke)\s+(\w+)\s+tool", re.IGNORECASE)


def strip_code_blocks(text: str) -> str:
    """Return *text* with fenced code blocks removed."""
    lines = text.split("\n")
    out: list[str] = []
    in_fence = False
    for line in lines:
        if line.strip().startswith("```"):
            in_fence = not in_fence
            continue
        if not in_fence:
            out.append(line)
    return "\n".join(out)


def extract_content_and_path(
    context: RuleContext, target_type: ComponentType
) -> tuple[str, str] | None:
    """Extract raw content and file path from context based on target type."""
    if target_type == ComponentType.SKILL:
        skill = context.skill
        if not skill.raw_content:
            return None
        return skill.raw_content, skill.skill_md_path
    elif target_type == ComponentType.COMMAND:
        cmd = context.command
        if not cmd or not cmd.raw_content:
            return None
        return cmd.raw_content, cmd.command_md_path
    elif target_type == ComponentType.AGENT:
        agent = context.agent
        if not agent or not agent.raw_content:
            return None
        return agent.raw_content, agent.agent_md_path
    return None


def extract_all_skill_md_content(
    context: RuleContext,
) -> list[tuple[str, str]]:
    """Return (content, abs_path) for SKILL.md and all markdown sub-files."""
    from pathlib import Path

    skill = context.skill
    results: list[tuple[str, str]] = []

    if skill.raw_content:
        results.append((skill.raw_content, skill.skill_md_path))

    if skill.dir_path and skill.sub_file_contents:
        skill_dir = Path(skill.dir_path)
        for rel_path, content in skill.sub_file_contents.items():
            if content:
                results.append((content, str(skill_dir / rel_path)))

    return results


_NEGATION_RE = re.compile(
    r"\b(?:not|don'?t|do\s+not|never|avoid|must\s+not|should\s+not|cannot|can'?t)\b",
    re.I,
)


def scan_lines_for_patterns(
    content: str,
    file_path: str,
    context: RuleContext,
    patterns: Sequence[tuple[str, re.Pattern[str]]],
    detected_msg: str,
    code_block_msg: str | None = None,
    example_msg: str | None = None,
    negation_msg: str | None = None,
) -> None:
    """Scan content lines for regex patterns with optional context awareness.

    When code_block_msg is provided, code fences are tracked and matches
    inside them use that message ID with INFO severity.
    When example_msg is provided, matches in quotes or example contexts
    use that message ID with INFO severity.
    When negation_msg is provided, lines containing negation words before
    the pattern match use that message ID with WARNING severity.
    """
    lines = content.split("\n")
    in_code_fence = False

    for i, line in enumerate(lines):
        stripped = line.strip()

        if code_block_msg is not None and stripped.startswith("```"):
            in_code_fence = not in_code_fence
            continue

        for label, pattern in patterns:
            match = pattern.search(line)
            if match:
                if code_block_msg is not None and in_code_fence:
                    message_id = code_block_msg
                    severity_override: Severity | None = Severity.INFO
                elif negation_msg is not None:
                    prefix = line[: match.start()]
                    if _NEGATION_RE.search(prefix):
                        message_id = negation_msg
                        severity_override = Severity.WARNING
                    elif example_msg is not None:
                        is_quoted = stripped.startswith(">") or stripped.startswith('"')
                        is_example = any(
                            w in line.lower()
                            for w in ["for example", "e.g.", "such as", "like:", "instead of"]
                        )
                        if is_quoted or is_example:
                            message_id = example_msg
                            severity_override = Severity.INFO
                        else:
                            message_id = detected_msg
                            severity_override = None
                    else:
                        message_id = detected_msg
                        severity_override = None
                elif example_msg is not None:
                    is_quoted = stripped.startswith(">") or stripped.startswith('"')
                    is_example = any(
                        w in line.lower()
                        for w in ["for example", "e.g.", "such as", "like:", "instead of"]
                    )
                    if is_quoted or is_example:
                        message_id = example_msg
                        severity_override = Severity.INFO
                    else:
                        message_id = detected_msg
                        severity_override = None
                else:
                    message_id = detected_msg
                    severity_override = None

                context.report(
                    ReportDescriptor(
                        message_id=message_id,
                        data={"label": label, "line": str(i + 1)},
                        location=Location(file=file_path, start_line=i + 1),
                        severity_override=severity_override,
                    )
                )
                break


def scan_lines_for_credential_patterns(
    content: str,
    file_path: str,
    context: RuleContext,
    pattern_groups: Sequence[tuple[str, Sequence[re.Pattern[str] | tuple[re.Pattern[str], str]]]],
    code_block_msg: str | None = None,
    suggestion: str | None = None,
) -> None:
    """Scan content lines for credential and command patterns.

    Each group is (message_id, patterns) where patterns can be:
    - Sequence[re.Pattern]: match.group(0) used as data value
    - Sequence[tuple[re.Pattern, str]]: str used as data value

    When code_block_msg is provided, lines inside code fences are skipped.
    When suggestion is provided, it is attached to every reported finding.
    """
    lines = content.split("\n")
    in_code_fence = False

    for i, line in enumerate(lines):
        stripped = line.strip()

        if code_block_msg is not None and stripped.startswith("```"):
            in_code_fence = not in_code_fence
            continue

        if code_block_msg is not None and in_code_fence:
            continue

        for message_id, patterns in pattern_groups:
            for item in patterns:
                if isinstance(item, tuple):
                    pattern, label = item
                else:
                    pattern = item
                    label = None
                match = pattern.search(line)
                if match:
                    context.report(
                        ReportDescriptor(
                            message_id=message_id,
                            data={"match": label or match.group(0), "line": str(i + 1)},
                            location=Location(file=file_path, start_line=i + 1),
                            suggestion=suggestion,
                        )
                    )
                    break
