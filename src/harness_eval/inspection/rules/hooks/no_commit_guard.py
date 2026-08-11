from __future__ import annotations

import json

from harness_eval.core.types import ComponentType
from harness_eval.inspection.types import (
    Location,
    ReportDescriptor,
    RuleCategory,
    RuleContext,
    RuleMeta,
    Severity,
)


class HooksNoCommitGuard:
    meta = RuleMeta(
        id="hooks/no-commit-guard",
        default_severity=Severity.WARNING,
        fixable=False,
        description=(
            "Flag project settings that define hooks but none guard the git "
            "commit path. A PreToolUse hook matching Bash(git commit*) can "
            "scan staged changes for secrets before they are committed."
        ),
        category=RuleCategory.SECURITY,
        messages={
            "no_guard": (
                "Hooks are configured but no PreToolUse hook guards git commit. "
                "Consider adding a pre-commit hook that scans for secrets."
            ),
        },
        target_type=ComponentType.HOOKS,
        default_suggestion=(
            "Add a PreToolUse hook with matcher 'Bash(git commit*)' that runs a secret scanner."
        ),
    )

    def create(self, context: RuleContext) -> None:
        hooks_data = context.hooks
        if hooks_data is None:
            return

        raw = hooks_data.raw_content
        if not raw or not raw.strip():
            return

        try:
            data = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            return

        if not isinstance(data, dict):
            return

        hooks = data.get("hooks", {})
        if not isinstance(hooks, dict) or not hooks:
            return

        pre_tool = hooks.get("PreToolUse", [])
        if not isinstance(pre_tool, list):
            return

        has_commit_guard = False
        for entry in pre_tool:
            matcher = ""
            if isinstance(entry, dict):
                matcher = entry.get("matcher", "")
            if isinstance(matcher, str) and "commit" in matcher.lower():
                has_commit_guard = True
                break

        if not has_commit_guard:
            context.report(
                ReportDescriptor(
                    message_id="no_guard",
                    location=Location(file=hooks_data.file_path),
                )
            )
