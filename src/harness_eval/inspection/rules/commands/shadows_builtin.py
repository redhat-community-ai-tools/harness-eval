from __future__ import annotations

from harness_eval.core.types import ComponentType
from harness_eval.data import load_builtins
from harness_eval.inspection.types import (
    Location,
    ReportDescriptor,
    RuleCategory,
    RuleContext,
    RuleMeta,
    Severity,
)

BUILTIN_COMMANDS = load_builtins()


class CommandShadowsBuiltin:
    meta = RuleMeta(
        id="command/shadows-builtin",
        default_severity=Severity.WARNING,
        fixable=False,
        description="Command name should not shadow a Claude Code built-in slash command",
        category=RuleCategory.CONTENT,
        messages={
            "shadows": "Command '{{name}}' shadows the built-in /{{name}} command — the built-in will be overridden, which may be unintentional",
        },
        target_type=ComponentType.COMMAND,
        tools=("claude",),
        default_suggestion="Rename the command to avoid shadowing the built-in.",
    )

    def create(self, context: RuleContext) -> None:
        cmd = context.command
        if cmd is None:
            return

        if cmd.dir_name.lower() in BUILTIN_COMMANDS:
            context.report(
                ReportDescriptor(
                    message_id="shadows",
                    data={"name": cmd.dir_name},
                    location=Location(file=cmd.command_md_path, start_line=1),
                )
            )
