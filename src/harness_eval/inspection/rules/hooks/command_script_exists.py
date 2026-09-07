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
        # A path glued to a shell separator ("script.sh;", "script.sh&&") is
        # still that path; the separator is not part of the file name.
        t = t.rstrip(";&|")
        if not t or t.startswith("-") or any(ch.isspace() for ch in t):
            continue
        # A glob ("*.py" inside a grep), a shell substitution ("RESULT=$(x.sh"),
        # or an assignment is not a path the repository is expected to carry.
        if "*" in t or "$(" in t or "=" in t:
            continue
        # A variable anywhere in a relative path ("./$PKG/hook.sh") resolves at run time.
        if re.search(r"\$\{?[A-Za-z_]", t) and not re.match(
            r"^\$\{?(?:CLAUDE_PROJECT_DIR|CURSOR_PROJECT_DIR|PROJECT_DIR|PWD)\b", t
        ):
            continue
        # Build and install outputs are produced, not committed.
        if re.search(r"(^|/)(node_modules|dist|build|target|out|venv|\.venv)/", t):
            continue
        # Any other variable ($HOME, ~, $root, ${DIR}) is a per-machine or
        # install-time location, not a path this repository can satisfy.
        if t.startswith(("$", "~")) and not re.match(
            r"^\$\{?(?:CLAUDE_PROJECT_DIR|CURSOR_PROJECT_DIR|PROJECT_DIR|PWD)\b", t
        ):
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
        tier="gating",
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
                hooks_dir = Path(hd.file_path).resolve().parent
                if not candidate.is_absolute():
                    if (hooks_dir / candidate).exists():
                        continue
                    candidate = root / candidate
                if not candidate.exists():
                    context.report(
                        ReportDescriptor(
                            message_id="missing",
                            data={"path": p},
                            location=Location(file=hd.file_path),
                        )
                    )
