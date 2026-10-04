from __future__ import annotations

from fnmatch import fnmatchcase
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


def _skill_is_loaded_by(skill_path: str, source_tool: str) -> bool:
    """Limit cross-component findings to skill roots loaded by this client."""
    path = skill_path.replace("\\", "/")
    roots = {
        "gemini": ("/.gemini/skills/", "/.agents/skills/"),
        "opencode": ("/.opencode/skills/", "/.agents/skills/", "/.claude/skills/"),
    }
    return any(root in f"/{path.lstrip('/')}" for root in roots.get(source_tool, ()))


def _last_opencode_effect(rules: list[Any], action: str, resource: str) -> str | None:
    effect: str | None = None
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        rule_action = rule.get("action")
        pattern = rule.get("resource")
        candidate = rule.get("effect")
        if not isinstance(rule_action, str):
            continue
        if not isinstance(pattern, str):
            continue
        if not isinstance(candidate, str):
            continue
        if fnmatchcase(action, rule_action) and fnmatchcase(resource, pattern):
            effect = candidate
    return effect


class ConfigComponentConflict:
    meta = RuleMeta(
        id="cross/config-component-conflict",
        tier="gating",
        scope="SETUP",
        default_severity=Severity.ERROR,
        fixable=False,
        description="Detect configured components made unreachable by settings in the same setup",
        category=RuleCategory.CROSS_COMPONENT,
        messages={
            "skills_disabled": "Gemini skills are discovered but skills.enabled=false disables all of them",
            "skill_disabled": "Gemini skill '{{skill}}' is present but listed in skills.disabled",
            "hooks_disabled": "Gemini hooks are configured but hooksConfig.enabled=false disables them",
            "hook_disabled": (
                "Gemini hook '{{hook}}' is configured but listed in hooksConfig.disabled"
            ),
            "mcp_excluded": "Gemini MCP server '{{server}}' is configured but excluded by mcp settings",
            "mcp_not_allowed": "Gemini MCP server '{{server}}' is configured but absent from mcp.allowed",
            "opencode_skill_denied": (
                "OpenCode skill '{{skill}}' is present but the last matching skill permission denies it"
            ),
        },
        target_type=ComponentType.CONFIG,
        default_suggestion="Remove the dead component or change the setting that makes it unreachable.",
    )

    def create(self, context: RuleContext) -> None:
        config = context.config
        if config is None:
            return
        data = parsed_config(config.raw_content)
        if data is None:
            return
        loc = Location(file=config.file_path, start_line=1)

        if context.source_tool == "gemini":
            self._gemini(context, data, loc)
        elif context.source_tool == "opencode":
            permissions = data.get("permissions")
            if isinstance(permissions, list):
                for skill in context.all_skills:
                    if not _skill_is_loaded_by(skill.skill_md_path, "opencode"):
                        continue
                    if _last_opencode_effect(permissions, "skill", skill.dir_name) == "deny":
                        context.report(
                            ReportDescriptor(
                                message_id="opencode_skill_denied",
                                data={"skill": skill.dir_name},
                                location=loc,
                            )
                        )

    def _gemini(self, context: RuleContext, data: dict[str, Any], loc: Location) -> None:
        skills = data.get("skills")
        if isinstance(skills, dict):
            loaded_skills = [
                skill
                for skill in context.all_skills
                if _skill_is_loaded_by(skill.skill_md_path, "gemini")
            ]
            if skills.get("enabled") is False and loaded_skills:
                context.report(ReportDescriptor(message_id="skills_disabled", location=loc))
            disabled = skills.get("disabled")
            if isinstance(disabled, list):
                disabled_ids = {item for item in disabled if isinstance(item, str)}
                for skill in loaded_skills:
                    if skill.dir_name in disabled_ids:
                        context.report(
                            ReportDescriptor(
                                message_id="skill_disabled",
                                data={"skill": skill.dir_name},
                                location=loc,
                            )
                        )

        hooks_config = data.get("hooksConfig")
        if (
            data.get("hooks")
            and isinstance(hooks_config, dict)
            and hooks_config.get("enabled") is False
        ):
            context.report(ReportDescriptor(message_id="hooks_disabled", location=loc))
        if isinstance(hooks_config, dict) and isinstance(data.get("hooks"), dict):
            disabled = hooks_config.get("disabled")
            disabled_names = (
                {item for item in disabled if isinstance(item, str)}
                if isinstance(disabled, list)
                else set()
            )
            for groups in data["hooks"].values():
                if not isinstance(groups, list):
                    continue
                for group in groups:
                    entries = group.get("hooks") if isinstance(group, dict) else None
                    if not isinstance(entries, list):
                        continue
                    for hook in entries:
                        if not isinstance(hook, dict):
                            continue
                        identity = hook.get("name") or hook.get("command")
                        if isinstance(identity, str) and identity in disabled_names:
                            context.report(
                                ReportDescriptor(
                                    message_id="hook_disabled",
                                    data={"hook": identity},
                                    location=loc,
                                )
                            )

        servers = data.get("mcpServers")
        mcp = data.get("mcp")
        if not isinstance(servers, dict) or not isinstance(mcp, dict):
            return
        excluded = mcp.get("excluded")
        excluded_ids = (
            {item for item in excluded if isinstance(item, str)}
            if isinstance(excluded, list)
            else set()
        )
        allowed = mcp.get("allowed")
        allowed_ids = (
            {item for item in allowed if isinstance(item, str)}
            if isinstance(allowed, list)
            else None
        )
        for server in servers:
            if server in excluded_ids:
                context.report(
                    ReportDescriptor(
                        message_id="mcp_excluded", data={"server": str(server)}, location=loc
                    )
                )
            elif allowed_ids is not None and server not in allowed_ids:
                context.report(
                    ReportDescriptor(
                        message_id="mcp_not_allowed", data={"server": str(server)}, location=loc
                    )
                )
