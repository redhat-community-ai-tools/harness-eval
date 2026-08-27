"""Flag a hook whose command runs a script path that does not exist.

Hooks execute on lifecycle events with no prompt. A command such as
`uv run "$CLAUDE_PROJECT_DIR/.ai/session-start.py"` or `./scripts/lint.sh`
that points at a missing file fails on every event, silently. Only relative
and project-variable paths are checked; absolute and `~` paths are per-machine.
"""

from __future__ import annotations

import re
import shlex
from pathlib import Path

from harness_eval.core.types import ComponentType
from harness_eval.inspection.rules._config_fs import expand_project_vars, project_root
from harness_eval.inspection.types import (
    Location,
    ReportDescriptor,
    RuleCategory,
    RuleContext,
    RuleMeta,
    Severity,
)

_SCRIPT_EXT = (".py", ".sh", ".bash", ".js", ".ts", ".rb", ".pl", ".mjs", ".cjs")


def script_paths(command: str) -> list[str]:
    try:
        tokens = shlex.split(command)
    except ValueError:
        tokens = command.split()
    out = []
    for t in tokens:
        if t.startswith("-"):
            continue
        if t.endswith(_SCRIPT_EXT) or t.startswith(
            (
                "./",
                "../",
                "$CLAUDE_PROJECT_DIR",
                "${CLAUDE_PROJECT_DIR}",
                "$CURSOR_PROJECT_DIR",
                "$PROJECT_DIR",
            )
        ):
            if re.match(r"^[A-Za-z]+:", t) or t.startswith("/") or t.startswith("~"):
                continue
            out.append(t)
    return out


def _iter_commands(hooks: list[dict]) -> list[str]:
    cmds: list[str] = []

    def walk(o: object) -> None:
        if isinstance(o, dict):
            c = o.get("command")
            if isinstance(c, str):
                cmds.append(c)
            for v in o.values():
                walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)

    walk(hooks)
    return cmds


class HooksCommandScriptExists:
    meta = RuleMeta(
        id="hooks/command-script-exists",
        tier="provisional",
        scope="FILE_FS",
        default_severity=Severity.ERROR,
        fixable=False,
        description="Flag a hook command that references a relative or project-dir script path that does not exist",
        category=RuleCategory.STRUCTURAL,
        messages={
            "missing": "Hook command references '{{path}}', which does not exist in the repository; the hook fails on every event."
        },
        target_type=ComponentType.HOOKS,
        default_suggestion="Commit the script at that path or fix the command.",
    )

    def create(self, context: RuleContext) -> None:
        hd = context.hooks
        if hd is None:
            return
        root = project_root(Path(hd.file_path))
        seen: set[str] = set()
        for cmd in _iter_commands(hd.hooks):
            for p in script_paths(cmd):
                if p in seen:
                    continue
                seen.add(p)
                candidate = Path(expand_project_vars(p, root))
                if not candidate.is_absolute():
                    candidate = root / candidate
                if not candidate.exists():
                    context.report(
                        ReportDescriptor(
                            message_id="missing",
                            data={"path": p},
                            location=Location(file=hd.file_path),
                        )
                    )
