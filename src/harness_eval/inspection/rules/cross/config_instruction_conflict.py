from __future__ import annotations

import json
import re
from pathlib import Path

from harness_eval.core.types import ComponentType
from harness_eval.inspection.rules.security._shared import TOOL_DIRECTIVE_RE
from harness_eval.inspection.types import (
    Location,
    ReportDescriptor,
    RuleCategory,
    RuleContext,
    RuleMeta,
    Severity,
)


def _find_settings_files(search_paths: list[str]) -> list[Path]:
    """Find .claude/settings.json and .claude/settings.local.json by walking up from given dirs."""
    seen_roots: set[Path] = set()
    settings_files: list[Path] = []

    for dir_path in search_paths:
        current = Path(dir_path).resolve()
        while current != current.parent:
            claude_dir = current / ".claude"
            if claude_dir.is_dir() and current not in seen_roots:
                seen_roots.add(current)
                for name in ("settings.json", "settings.local.json"):
                    candidate = claude_dir / name
                    if candidate.is_file():
                        settings_files.append(candidate)
            current = current.parent

    return settings_files


def _parse_deny_entries(settings_files: list[Path]) -> list[tuple[str, str, str]]:
    """Parse permissions.deny from settings files.

    Returns list of (deny_entry, deny_entry, file_path) tuples.
    """
    entries: list[tuple[str, str, str]] = []
    for settings_path in settings_files:
        try:
            data = json.loads(settings_path.read_text())
        except (json.JSONDecodeError, OSError):
            continue
        permissions = data.get("permissions", {})
        if not isinstance(permissions, dict):
            continue
        deny_list = permissions.get("deny", [])
        if not isinstance(deny_list, list):
            continue
        for entry in deny_list:
            if not isinstance(entry, str):
                continue
            entries.append((entry, entry, str(settings_path)))
    return entries


def _extract_instructed_tools(content: str) -> list[str]:
    """Extract tool/command names that the content instructs the agent to use."""
    tools: list[str] = []

    # Extract command lines inside bash/sh/shell fenced blocks
    for block_match in re.finditer(r"```(?:bash|sh|shell)\n(.*?)```", content, re.DOTALL):
        block = block_match.group(1)
        for line in block.strip().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and line.split():
                tools.append(f"Bash({line})")

    # Extract inline code spans that look like commands
    for code_match in re.finditer(r"`([^`]+)`", content):
        code = code_match.group(1).strip()
        if code and not code.startswith("{") and " " in code:
            first_token = code.split()[0]
            if first_token and not first_token.startswith("$"):
                tools.append(f"Bash({code})")

    # Extract explicit tool-use directives like "use the WebFetch tool"
    for m in TOOL_DIRECTIVE_RE.finditer(content):
        tools.append(m.group(1))

    return tools


def _deny_matches_instruction(deny_entry: str, instructed: str) -> bool:
    """Check if a deny entry blocks an instructed tool/command."""
    # Direct tool name match: "WebFetch" denies "WebFetch"
    if deny_entry == instructed:
        return True

    # Bash prefix match: "Bash(git push:*)" denies "Bash(git push)"
    bash_match = re.match(r"Bash\((.+?)(?::\*)?\)", deny_entry)
    if bash_match:
        deny_prefix = bash_match.group(1)
        instr_match = re.match(r"Bash\((.+)\)", instructed)
        if instr_match:
            instr_cmd = instr_match.group(1)
            if instr_cmd.startswith(deny_prefix):
                return True

    # Bare tool name: "Bash" denies any "Bash(...)"
    return not deny_entry.startswith("Bash(") and instructed.startswith(f"{deny_entry}(")


class ConfigInstructionConflict:
    meta = RuleMeta(
        id="cross/config-instruction-conflict",
        scope="PAIRWISE",
        default_severity=Severity.WARNING,
        fixable=False,
        description=(
            "Flag when settings.json permissions.deny blocks tools that instructions direct to use"
        ),
        category=RuleCategory.CROSS_COMPONENT,
        messages={
            "conflict": (
                "'{{component}}' instructs using {{what}}, but settings.json"
                " permissions.deny blocks it ({{deny_entry}})."
                " The agent cannot comply."
            ),
        },
        target_type=ComponentType.SKILL,
        default_suggestion="Remove the deny entry or update the instruction to use an allowed tool.",
    )

    def create(self, context: RuleContext) -> None:
        if context.scan_state.get("config_instruction_conflict_checked"):
            return
        context.scan_state["config_instruction_conflict_checked"] = True

        # Gather skill paths to find settings files.
        # Use all_skills if populated, otherwise fall back to the current skill.
        skills = [s for s in (context.all_skills or [context.skill]) if s is not None]
        skill_paths = [s.dir_path for s in skills]

        settings_files = _find_settings_files(skill_paths)
        if not settings_files:
            return

        deny_entries = _parse_deny_entries(settings_files)
        if not deny_entries:
            return

        # Check skills
        for skill in skills:
            if skill.body:
                instructed = _extract_instructed_tools(skill.body)
                self._check_conflicts(
                    context, skill.dir_name, skill.skill_md_path, instructed, deny_entries
                )

        # Check commands
        for cmd in context.all_commands:
            if cmd.body:
                instructed = _extract_instructed_tools(cmd.body)
                self._check_conflicts(
                    context, cmd.dir_name, cmd.command_md_path, instructed, deny_entries
                )

    def _check_conflicts(
        self,
        context: RuleContext,
        component_name: str,
        file_path: str,
        instructed: list[str],
        deny_entries: list[tuple[str, str, str]],
    ) -> None:
        reported: set[tuple[str, str]] = set()
        for tool in instructed:
            for _, deny_entry, _ in deny_entries:
                if _deny_matches_instruction(deny_entry, tool):
                    key = (component_name, deny_entry)
                    if key not in reported:
                        reported.add(key)
                        context.report(
                            ReportDescriptor(
                                message_id="conflict",
                                data={
                                    "component": component_name,
                                    "what": tool,
                                    "deny_entry": deny_entry,
                                },
                                location=Location(file=file_path),
                            )
                        )
