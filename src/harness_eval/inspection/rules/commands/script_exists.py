from __future__ import annotations

from pathlib import Path

from harness_eval.core.types import ComponentType
from harness_eval.inspection.types import (
    Location,
    ReportDescriptor,
    RuleCategory,
    RuleContext,
    RuleMeta,
    Severity,
)
from harness_eval.utils.paths import safe_join


class CommandScriptExists:
    meta = RuleMeta(
        id="command/script-exists",
        tier="gating",
        scope="FILE_FS",
        default_severity=Severity.WARNING,
        fixable=False,
        description="Script files referenced in commands should exist",
        category=RuleCategory.CONTENT,
        messages={
            "missing_script": "Command references '{{script}}' but this file does not exist",
        },
        target_type=ComponentType.COMMAND,
        default_suggestion="Create the missing script file or fix the reference path.",
    )

    def create(self, context: RuleContext) -> None:
        cmd = context.command
        if cmd is None or not cmd.script_references:
            return

        cmd_dir = Path(cmd.dir_path)
        project_root = context.scan_state.get("project_root")
        project_root_path = Path(project_root) if project_root else None
        checked: set[str] = set()

        for script in cmd.script_references:
            if script in checked:
                continue
            checked.add(script)

            script_path = safe_join(cmd_dir, script)
            if script_path is not None and script_path.exists():
                continue
            # Only treat as repo-relative when the ref has a path separator.
            # A bare `conftest.py` at the repo root must not mask a missing
            # file next to the command.
            if project_root_path is not None and "/" in script.replace("\\", "/"):
                root_path = safe_join(project_root_path, script)
                if root_path is not None and root_path.exists():
                    continue
            context.report(
                ReportDescriptor(
                    message_id="missing_script",
                    data={"script": script},
                    location=Location(file=cmd.command_md_path),
                )
            )
