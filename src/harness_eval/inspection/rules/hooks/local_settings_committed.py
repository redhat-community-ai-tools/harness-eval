"""Flag a committed .claude/settings.local.json.

Claude Code writes per-machine permission decisions to settings.local.json
and adds it to .gitignore on creation. When the file is present in a
repository tree it was committed deliberately or by an older client, and it
carries whatever the author approved on their machine, typically a long
permissions.allow list, into every clone. The condition is a file's presence,
decidable without reading it.
"""

from __future__ import annotations

import json
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


def _allow_count(path: Path) -> int | None:
    try:
        data = json.loads(path.read_text())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    perms = data.get("permissions")
    if not isinstance(perms, dict):
        return 0
    allow = perms.get("allow")
    return len(allow) if isinstance(allow, list) else 0


class HooksLocalSettingsCommitted:
    meta = RuleMeta(
        id="hooks/local-settings-committed",
        tier="gating",
        scope="FILE_FS",
        default_severity=Severity.WARNING,
        fixable=False,
        description=(
            "Flag a .claude/settings.local.json present in the repository tree;"
            " it is a per-machine file that should not be shared"
        ),
        category=RuleCategory.STRUCTURAL,
        messages={
            "committed": (
                "{{file}} is present in the repository. It is a per-machine file"
                " that Claude Code gitignores on creation; here it ships {{n}}"
                " permissions.allow entries to every clone."
            ),
        },
        target_type=ComponentType.HOOKS,
        default_suggestion=(
            "Remove settings.local.json from version control and add it to .gitignore;"
            " move any shared grants into settings.json deliberately."
        ),
    )

    def create(self, context: RuleContext) -> None:
        hooks_data = context.hooks
        if hooks_data is None:
            return
        settings_path = Path(hooks_data.file_path)
        local = settings_path.with_name("settings.local.json")
        key = f"local_settings_committed_checked:{local.resolve()}"
        if context.scan_state.get(key):
            return
        context.scan_state[key] = True
        if not local.is_file():
            return
        n = _allow_count(local)
        context.report(
            ReportDescriptor(
                message_id="committed",
                data={"file": ".claude/settings.local.json", "n": n if n is not None else 0},
                location=Location(file=str(local)),
            )
        )
