"""Flag project settings that switch off the permission prompt.

Two keys in a committed settings.json remove the human from the loop for
everyone who opens the repository: ``permissions.defaultMode`` set to a
non-prompting mode, and ``enableAllProjectMcpServers`` set to true, which
pre-approves every server declared in the project's MCP configuration. Both
are decidable from the settings file alone and both are stronger than any
single permissions.allow entry, because they cover grants that do not yet
exist.
"""

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

_NON_PROMPTING_MODES = {"bypassPermissions", "dontAsk", "acceptEdits"}
_SEVERE_MODES = {"bypassPermissions", "dontAsk"}


class HooksPermissionPromptDisabled:
    meta = RuleMeta(
        id="hooks/permission-prompt-disabled",
        tier="gating",
        default_severity=Severity.ERROR,
        fixable=False,
        description=(
            "Flag committed settings that disable the permission prompt"
            " (permissions.defaultMode) or auto-approve every project MCP server"
            " (enableAllProjectMcpServers)"
        ),
        category=RuleCategory.SECURITY,
        messages={
            "default_mode": (
                "permissions.defaultMode is '{{mode}}', which {{effect}} for every"
                " user who opens this project."
            ),
            "all_mcp": (
                "enableAllProjectMcpServers is true, which pre-approves every server"
                " in the project MCP configuration without a prompt."
            ),
            "skip_dangerous": (
                "skipDangerousModePermissionPrompt is true, which suppresses the"
                " confirmation that guards bypass mode."
            ),
        },
        target_type=ComponentType.HOOKS,
        default_suggestion=(
            "Remove the setting from project-scoped settings.json; keep prompt-bypass"
            " choices in user-scoped settings where they apply only to the person who made them."
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

        loc = Location(file=hooks_data.file_path)

        permissions = data.get("permissions", {})
        if isinstance(permissions, dict):
            mode = permissions.get("defaultMode")
            if isinstance(mode, str) and mode in _NON_PROMPTING_MODES:
                effect = (
                    "skips every permission prompt"
                    if mode in _SEVERE_MODES
                    else "auto-accepts file edits without a prompt"
                )
                context.report(
                    ReportDescriptor(
                        message_id="default_mode",
                        data={"mode": mode, "effect": effect},
                        location=loc,
                    )
                )

        if data.get("enableAllProjectMcpServers") is True:
            context.report(ReportDescriptor(message_id="all_mcp", location=loc))

        if data.get("skipDangerousModePermissionPrompt") is True:
            context.report(ReportDescriptor(message_id="skip_dangerous", location=loc))
