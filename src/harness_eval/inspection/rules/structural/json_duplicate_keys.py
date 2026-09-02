"""Flag duplicate object keys in committed JSON configuration.

`json.loads` keeps the last key, so a `.mcp.json` with two "github" servers or
a settings file with two "permissions" blocks parses cleanly and silently
drops the first definition. Decidable from the file alone.
"""

from __future__ import annotations

from harness_eval.core.types import ComponentType
from harness_eval.inspection.rules._config_fs import find_duplicate_keys
from harness_eval.inspection.types import (
    Location,
    ReportDescriptor,
    RuleCategory,
    RuleContext,
    RuleMeta,
    Severity,
)


def _check(context: RuleContext, raw: str | None, path: str) -> None:
    if not raw or not raw.strip():
        return
    for key in find_duplicate_keys(raw):
        context.report(
            ReportDescriptor(
                message_id="duplicate", data={"key": key}, location=Location(file=path)
            )
        )


class StructuralJsonDuplicateKeysMcp:
    meta = RuleMeta(
        id="mcp/json-duplicate-keys",
        tier="gating",
        default_severity=Severity.ERROR,
        fixable=False,
        description="Flag duplicate object keys in an MCP configuration; the parser silently keeps only the last",
        category=RuleCategory.STRUCTURAL,
        messages={
            "duplicate": "Duplicate JSON key '{{key}}': only the last definition takes effect, the others are silently dropped."
        },
        target_type=ComponentType.MCP_CONFIG,
        default_suggestion="Remove or rename the duplicate key so every definition is used.",
    )

    def create(self, context: RuleContext) -> None:
        _check(context, context.skill.raw_content, context.skill.skill_md_path)


class StructuralJsonDuplicateKeysSettings:
    meta = RuleMeta(
        id="hooks/json-duplicate-keys",
        tier="gating",
        default_severity=Severity.ERROR,
        fixable=False,
        description="Flag duplicate object keys in settings.json; the parser silently keeps only the last",
        category=RuleCategory.STRUCTURAL,
        messages={
            "duplicate": "Duplicate JSON key '{{key}}': only the last definition takes effect, the others are silently dropped."
        },
        target_type=ComponentType.HOOKS,
        default_suggestion="Remove or rename the duplicate key so every definition is used.",
    )

    def create(self, context: RuleContext) -> None:
        if context.hooks is None:
            return
        _check(context, context.hooks.raw_content, context.hooks.file_path)
