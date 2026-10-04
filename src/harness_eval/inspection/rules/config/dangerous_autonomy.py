from __future__ import annotations

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


class ConfigDangerousAutonomy:
    meta = RuleMeta(
        id="config/dangerous-autonomy",
        tier="gating",
        scope="FILE",
        default_severity=Severity.ERROR,
        fixable=False,
        description="Detect explicit project settings that remove approval and containment together",
        category=RuleCategory.SECURITY,
        messages={
            "codex_uncontained": (
                "Codex combines approval_policy='never' with sandbox_mode='danger-full-access';"
                " commands can run without approval or sandbox containment"
            ),
            "gemini_trusted_mcp": (
                "Gemini MCP server '{{server}}' sets trust=true, bypassing tool-call confirmation"
            ),
            "opencode_broad_allow": (
                "OpenCode explicitly allows every {{action}} resource; this project rule removes"
                " the approval boundary for a high-impact action"
            ),
        },
        target_type=ComponentType.CONFIG,
        default_suggestion="Keep an approval prompt or narrow the affected capability and resource.",
    )

    def create(self, context: RuleContext) -> None:
        config = context.config
        if config is None:
            return
        data = parsed_config(config.raw_content)
        if data is None:
            return
        loc = Location(file=config.file_path, start_line=1)

        if context.source_tool == "codex":
            if (
                data.get("approval_policy") == "never"
                and data.get("sandbox_mode") == "danger-full-access"
            ):
                context.report(ReportDescriptor(message_id="codex_uncontained", location=loc))
            return

        if context.source_tool == "gemini":
            servers = data.get("mcpServers")
            if isinstance(servers, dict):
                for name, server in servers.items():
                    if isinstance(server, dict) and server.get("trust") is True:
                        context.report(
                            ReportDescriptor(
                                message_id="gemini_trusted_mcp",
                                data={"server": str(name)},
                                location=loc,
                                severity_override=Severity.WARNING,
                            )
                        )
            return

        if context.source_tool == "opencode":
            permissions = data.get("permissions")
            if not isinstance(permissions, list):
                return
            for rule in permissions:
                if not isinstance(rule, dict):
                    continue
                if (
                    rule.get("effect") == "allow"
                    and rule.get("resource") == "*"
                    and rule.get("action") in {"shell", "edit", "external_directory"}
                ):
                    context.report(
                        ReportDescriptor(
                            message_id="opencode_broad_allow",
                            data={"action": str(rule["action"])},
                            location=loc,
                            severity_override=Severity.WARNING,
                        )
                    )
