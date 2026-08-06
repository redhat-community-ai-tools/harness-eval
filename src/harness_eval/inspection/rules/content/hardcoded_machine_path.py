from __future__ import annotations

import re

from harness_eval.core.types import ComponentType
from harness_eval.inspection.types import (
    Location,
    ReportDescriptor,
    RuleCategory,
    RuleContext,
    RuleMeta,
    Severity,
)

# Match /Users/<name>/ or /home/<name>/ with literal name (not variable/placeholder)
_UNIX_PATH_RE = re.compile(r"(?:/Users/|/home/)([A-Za-z][\w.-]*)/")
# Match C:\Users\<name>\ or C:/Users/<name>/
_WIN_PATH_RE = re.compile(r"[Cc]:[/\\]Users[/\\]([A-Za-z][\w.-]*)[/\\]")

# Names that are variables/placeholders, not real usernames
_SKIP_NAMES = {"runner", "user", "username", "USER", "USERNAME"}


def _extract_code_regions(content: str) -> list[str]:
    """Extract text from fenced code blocks, inline code spans, and YAML frontmatter."""
    regions: list[str] = []

    # Fenced code blocks
    for m in re.finditer(r"```[^\n]*\n(.*?)```", content, re.DOTALL):
        regions.append(m.group(1))

    # Inline code spans (backtick-delimited)
    for m in re.finditer(r"`([^`]+)`", content):
        regions.append(m.group(1))

    # YAML frontmatter values (between --- markers at start)
    fm_match = re.match(r"^---\n(.*?)\n---", content, re.DOTALL)
    if fm_match:
        regions.append(fm_match.group(1))

    return regions


def _is_in_url(text: str, match_start: int) -> bool:
    """Check if the match position is inside a URL."""
    line_start = text.rfind("\n", 0, match_start) + 1
    line = text[line_start:match_start]
    return "http://" in line or "https://" in line


class HardcodedMachinePath:
    meta = RuleMeta(
        id="content/hardcoded-machine-path",
        default_severity=Severity.WARNING,
        fixable=False,
        description="Flag machine-specific absolute paths that break portability",
        category=RuleCategory.CONTENT,
        messages={
            "hardcoded_path": (
                "Hardcoded machine-specific path '{{path}}'"
                " -- this will break on other machines."
                " Use $HOME, a relative path, or an environment variable."
            ),
        },
        target_type=ComponentType.SKILL,
    )

    def create(self, context: RuleContext) -> None:
        if context.scan_state.get("hardcoded_machine_path_checked"):
            return
        context.scan_state["hardcoded_machine_path_checked"] = True

        # Check all skills
        for skill in context.all_skills:
            if skill.raw_content:
                self._check_content(context, skill.raw_content, skill.skill_md_path)
            for file_name, file_content in skill.sub_file_contents.items():
                self._check_content(context, file_content, file_name)

        # Check all commands
        for cmd in context.all_commands:
            if cmd.raw_content:
                self._check_content(context, cmd.raw_content, cmd.command_md_path)

    def _check_content(self, context: RuleContext, content: str, file_path: str) -> None:
        # Only check inside code regions (fenced blocks, inline code, frontmatter)
        code_regions = _extract_code_regions(content)
        # Also check JSON content (MCP configs embedded in skill content)
        if content.strip().startswith("{"):
            code_regions.append(content)

        reported_paths: set[str] = set()
        for region in code_regions:
            for pattern in (_UNIX_PATH_RE, _WIN_PATH_RE):
                for match in pattern.finditer(region):
                    name = match.group(1)
                    full_path = match.group(0)

                    # Skip known non-user names
                    if name.lower() in {n.lower() for n in _SKIP_NAMES}:
                        continue

                    # Skip if inside a URL
                    if _is_in_url(region, match.start()):
                        continue

                    if full_path not in reported_paths:
                        reported_paths.add(full_path)
                        context.report(
                            ReportDescriptor(
                                message_id="hardcoded_path",
                                data={"path": full_path},
                                location=Location(file=file_path),
                            )
                        )
