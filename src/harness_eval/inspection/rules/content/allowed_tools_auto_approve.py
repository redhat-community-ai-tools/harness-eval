from __future__ import annotations

from harness_eval.inspection.rules.cross.overpermissive_grants import classify_grant
from harness_eval.inspection.types import (
    Location,
    ReportDescriptor,
    RuleCategory,
    RuleContext,
    RuleMeta,
    Severity,
)

_HIGH_RISK = {"bash"}
_MEDIUM_RISK = {"write", "edit", "notebookedit"}
# Commands whose wildcard is equivalent to an unrestricted shell. Network and
# build tools (curl, make, docker, ssh) are scoped grants, not shell access.
_EXEC_CLASS = {
    "sh",
    "bash",
    "zsh",
    "dash",
    "fish",
    "env",
    "eval",
    "exec",
    "xargs",
    "nohup",
    "timeout",
    "watch",
    "sudo",
    "doas",
    "python",
    "python3",
    "perl",
    "ruby",
    "node",
    "bun",
    "deno",
    "php",
    "lua",
    "awk",
    "gawk",
    "mawk",
    "nawk",
    "sed",
    "find",
    "vim",
    "vi",
    "nvim",
    "less",
    "man",
    "npx",
    "bunx",
    "uvx",
    "pipx",
}


class AllowedToolsAutoApprove:
    meta = RuleMeta(
        id="content/allowed-tools-auto-approve",
        default_severity=Severity.WARNING,
        fixable=False,
        description=(
            "Flag allowed-tools entries that auto-approve dangerous tools. "
            "allowed-tools removes the human confirmation prompt; it widens "
            "the blast radius, not narrows it."
        ),
        category=RuleCategory.CONTENT,
        messages={
            "auto_approve_high": (
                "allowed-tools includes '{{tool}}', which auto-approves shell "
                "execution without user confirmation. This is not a sandbox; it "
                "removes the safety prompt."
            ),
            "auto_approve_medium": (
                "allowed-tools includes '{{tool}}', which auto-approves a scoped "
                "shell command or file writes without user confirmation."
            ),
        },
        default_suggestion="Remove dangerous tools from the allowed-tools list.",
    )

    def create(self, context: RuleContext) -> None:
        skill = context.skill
        if skill is None:
            return
        if not skill.frontmatter:
            return

        allowed = skill.frontmatter.get("allowed-tools")
        if not allowed or not isinstance(allowed, list):
            return

        loc = Location(file=skill.skill_md_path)

        for tool in allowed:
            if not isinstance(tool, str):
                continue
            tool_lower = tool.lower().strip()

            grant = classify_grant(tool.strip())
            unrestricted = tool_lower in _HIGH_RISK or tool_lower in ("bash(*)", "bash(:*)")
            arbitrary = grant is not None and grant[0] in _EXEC_CLASS
            if unrestricted or arbitrary:
                context.report(
                    ReportDescriptor(
                        message_id="auto_approve_high",
                        data={"tool": tool},
                        location=loc,
                    )
                )
            elif tool_lower in _MEDIUM_RISK or tool_lower.startswith("bash("):
                # A scoped shell grant (Bash(npm test:*)) or a file-writing tool.
                context.report(
                    ReportDescriptor(
                        message_id="auto_approve_medium",
                        data={"tool": tool},
                        location=loc,
                    )
                )
