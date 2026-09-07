from __future__ import annotations

import re
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

# Tokens the script regex matches that are names, not paths: framework
# names (Node.js, Next.js), placeholders (foo.py, example.sh), `path/to/x`.
_PROSE_MENTION = re.compile(
    r"^(?:[A-Z][\w.-]*\.js|(?:foo|bar|baz|example|sample|placeholder|my[_-]?script|your[_-]?script|script|file|test)\.\w+"
    r"|(?:\./)?path/to/.*)$"
)


def _resolve(base: Path, ref: str) -> Path | None:
    """Resolve *ref* under *base*, allowing `..` as long as the result stays
    inside the project (a command one directory below the scripts it runs)."""
    direct = safe_join(base, ref)
    if direct is not None:
        return direct
    try:
        candidate = (base / ref).resolve()
    except OSError:
        return None
    return candidate if candidate.exists() else None


class CommandScriptExists:
    meta = RuleMeta(
        id="command/script-exists",
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

            if _PROSE_MENTION.match(script):
                continue
            script_path = _resolve(cmd_dir, script)
            if script_path is not None and script_path.exists():
                continue
            # A command runs with the project root as working directory, so
            # `python setup.py` resolves there whether or not it has a slash.
            if project_root_path is not None:
                root_path = _resolve(project_root_path, script)
                if root_path is not None and root_path.exists():
                    continue
            context.report(
                ReportDescriptor(
                    message_id="missing_script",
                    data={"script": script},
                    location=Location(file=cmd.command_md_path),
                )
            )
