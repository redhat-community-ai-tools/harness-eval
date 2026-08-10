from __future__ import annotations

import re

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


def _extract_used_tools(body: str) -> tuple[list[str], list[str]]:
    """Extract tools used in a command body. Returns (tool_names, bash_commands)."""
    tools: list[str] = []
    bash_commands: list[str] = []

    # Bash commands in fenced blocks
    for block_match in re.finditer(r"```(?:bash|sh|shell)\n(.*?)```", body, re.DOTALL):
        block = block_match.group(1)
        for line in block.strip().splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                first_token = line.split()[0]
                if first_token:
                    bash_commands.append(first_token)
        if "Bash" not in tools:
            tools.append("Bash")

    # Inline command execution (! prefix in backticks)
    for m in re.finditer(r"`!([^`]+)`", body):
        cmd = m.group(1).strip()
        if cmd:
            first_token = cmd.split()[0]
            bash_commands.append(first_token)
            if "Bash" not in tools:
                tools.append("Bash")

    # Explicit tool directives
    for m in TOOL_DIRECTIVE_RE.finditer(body):
        tool = m.group(1)
        if tool not in tools:
            tools.append(tool)

    return tools, bash_commands


def _is_covered(tool: str, allowed_tools: list[str]) -> bool:
    """Check if a tool is covered by the allowed-tools list."""
    for grant in allowed_tools:
        # Exact match
        if grant == tool:
            return True
        # Bash(*) or Bash(prefix:*) covers Bash
        if tool == "Bash" and grant.startswith("Bash"):
            return True
    return False


def _find_common_prefix(commands: list[str]) -> str | None:
    """Find common prefix if all bash commands share the same base command."""
    if len(commands) < 2:
        return None
    base_names = [cmd.split("/")[-1] for cmd in commands]
    if len(set(base_names)) == 1:
        return base_names[0]
    return None


class CommandAllowedToolsCoverage:
    meta = RuleMeta(
        id="command/allowed-tools-coverage",
        default_severity=Severity.WARNING,
        fixable=False,
        description="Check that command allowed-tools covers the tools the command uses",
        category=RuleCategory.CONTENT,
        messages={
            "under_grant": ("Command uses {{what}} but 'allowed-tools' does not grant it."),
            "over_grant": (
                "Command grants '{{grant}}' but only runs '{{prefix}}' commands"
                " -- narrow to '{{suggestion}}'."
            ),
        },
        target_type=ComponentType.COMMAND,
        default_suggestion="Update the allowed-tools list to match the tools the command uses.",
    )

    def create(self, context: RuleContext) -> None:
        command = context.command
        if command is None:
            return

        allowed_tools = command.frontmatter.get("allowed-tools")
        if allowed_tools is None:
            # No allowed-tools means default permissions; not a defect
            return
        if not isinstance(allowed_tools, list):
            return

        loc = Location(file=command.command_md_path)
        used_tools, bash_commands = _extract_used_tools(command.body)

        # Check under-grant: tool is used but not in allowed-tools
        for tool in used_tools:
            if not _is_covered(tool, allowed_tools):
                context.report(
                    ReportDescriptor(
                        message_id="under_grant",
                        data={"what": tool},
                        location=loc,
                    )
                )

        # Check over-grant: bare Bash or Bash(*) when all commands share a prefix
        if bash_commands and len(bash_commands) >= 2:
            for grant in allowed_tools:
                if grant in ("Bash", "Bash(*)"):
                    prefix = _find_common_prefix(bash_commands)
                    if prefix:
                        context.report(
                            ReportDescriptor(
                                message_id="over_grant",
                                data={
                                    "grant": grant,
                                    "prefix": prefix,
                                    "suggestion": f"Bash({prefix}:*)",
                                },
                                location=loc,
                            )
                        )
