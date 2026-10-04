from __future__ import annotations

from typing import Any

from harness_eval.core.types import ComponentType
from harness_eval.inspection.rules.config._shared import parsed_config
from harness_eval.inspection.types import (
    Location,
    ReportDescriptor,
    RuleCategory,
    RuleContext,
    RuleMeta,
    Severity,
)


def _is_string_list(value: Any) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


class ConfigValidStructure:
    meta = RuleMeta(
        id="config/valid-structure",
        tier="gating",
        scope="FILE",
        default_severity=Severity.ERROR,
        fixable=False,
        description="Validate current Codex, Gemini CLI, OpenCode, and Copilot settings shapes",
        category=RuleCategory.STRUCTURAL,
        messages={
            "parse": "Configuration must be a JSON, JSONC, or TOML object",
            "field_type": "{{field}} must be {{expected}} for {{tool}}",
            "permission_rule": (
                "OpenCode permissions[{{index}}] must contain string action, resource, and effect"
            ),
            "permission_effect": (
                "OpenCode permissions[{{index}}].effect must be allow, deny, or ask"
            ),
        },
        target_type=ComponentType.CONFIG,
        default_suggestion="Use the current configuration schema for this client.",
    )

    def create(self, context: RuleContext) -> None:
        config = context.config
        if config is None:
            return
        loc = Location(file=config.file_path, start_line=1)
        data = parsed_config(config.raw_content)
        if data is None:
            context.report(ReportDescriptor(message_id="parse", location=loc))
            return

        if context.source_tool == "opencode":
            self._opencode(context, data, loc)
        elif context.source_tool == "gemini":
            self._gemini(context, data, loc)
        elif context.source_tool == "codex":
            self._codex(context, data, loc)
        elif context.source_tool == "copilot":
            self._copilot(context, data, loc)

    def _type(
        self,
        context: RuleContext,
        loc: Location,
        data: dict[str, Any],
        field: str,
        expected: str,
        valid: bool,
    ) -> None:
        if field in data and not valid:
            context.report(
                ReportDescriptor(
                    message_id="field_type",
                    data={
                        "field": field,
                        "expected": expected,
                        "tool": context.source_tool or "client",
                    },
                    location=loc,
                )
            )

    def _opencode(self, context: RuleContext, data: dict[str, Any], loc: Location) -> None:
        permissions = data.get("permissions")
        self._type(context, loc, data, "permissions", "an array", isinstance(permissions, list))
        self._type(context, loc, data, "agents", "an object", isinstance(data.get("agents"), dict))
        self._type(
            context,
            loc,
            data,
            "plugins",
            "an array of strings",
            _is_string_list(data.get("plugins")),
        )
        if not isinstance(permissions, list):
            return
        for index, rule in enumerate(permissions):
            if not isinstance(rule, dict) or not all(
                isinstance(rule.get(key), str) for key in ("action", "resource", "effect")
            ):
                context.report(
                    ReportDescriptor(
                        message_id="permission_rule", data={"index": index}, location=loc
                    )
                )
                continue
            if rule["effect"] not in {"allow", "deny", "ask"}:
                context.report(
                    ReportDescriptor(
                        message_id="permission_effect", data={"index": index}, location=loc
                    )
                )

    def _gemini(self, context: RuleContext, data: dict[str, Any], loc: Location) -> None:
        for field in ("mcp", "skills", "hooksConfig", "security"):
            self._type(context, loc, data, field, "an object", isinstance(data.get(field), dict))
        mcp = data.get("mcp")
        if isinstance(mcp, dict):
            for field in ("allowed", "excluded"):
                if field in mcp and not _is_string_list(mcp[field]):
                    context.report(
                        ReportDescriptor(
                            message_id="field_type",
                            data={
                                "field": f"mcp.{field}",
                                "expected": "an array of strings",
                                "tool": "gemini",
                            },
                            location=loc,
                        )
                    )
        skills = data.get("skills")
        if isinstance(skills, dict):
            if "enabled" in skills and not isinstance(skills["enabled"], bool):
                self._type(context, loc, skills, "enabled", "a boolean", False)
            if "disabled" in skills and not _is_string_list(skills["disabled"]):
                self._type(context, loc, skills, "disabled", "an array of strings", False)
        hooks_config = data.get("hooksConfig")
        if isinstance(hooks_config, dict):
            if "enabled" in hooks_config and not isinstance(hooks_config["enabled"], bool):
                self._type(context, loc, hooks_config, "enabled", "a boolean", False)
            if "disabled" in hooks_config and not _is_string_list(hooks_config["disabled"]):
                self._type(context, loc, hooks_config, "disabled", "an array of strings", False)

    def _codex(self, context: RuleContext, data: dict[str, Any], loc: Location) -> None:
        for field in ("approval_policy", "sandbox_mode"):
            self._type(context, loc, data, field, "a string", isinstance(data.get(field), str))
        self._type(
            context,
            loc,
            data,
            "mcp_servers",
            "an object",
            isinstance(data.get("mcp_servers"), dict),
        )

    def _copilot(self, context: RuleContext, data: dict[str, Any], loc: Location) -> None:
        if "hooks" in data:
            self._type(
                context, loc, data, "hooks", "an object", isinstance(data.get("hooks"), dict)
            )
