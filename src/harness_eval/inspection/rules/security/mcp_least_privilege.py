from __future__ import annotations

import re
from pathlib import Path

from harness_eval.data import load_capabilities
from harness_eval.inspection.types import (
    Location,
    ReportDescriptor,
    RuleCategory,
    RuleContext,
    RuleMeta,
    Severity,
)

_caps = load_capabilities()
_CAPABILITY_PATTERNS: dict[str, list[re.Pattern[str]]] = _caps.capability_patterns()
_TOOL_TO_CAPABILITY: dict[str, set[str]] = _caps.tool_to_capability()


def _detect_capabilities(skill_dir: Path) -> dict[str, list[str]]:
    found: dict[str, list[str]] = {}
    for py_file in sorted(skill_dir.rglob("*.py")):
        if ".git" in py_file.parts or "__pycache__" in py_file.parts:
            continue
        try:
            content = py_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for cap, patterns in _CAPABILITY_PATTERNS.items():
            for pat in patterns:
                if pat.search(content):
                    found.setdefault(cap, []).append(py_file.name)
                    break

    for sh_file in sorted(skill_dir.rglob("*.sh")):
        if ".git" in sh_file.parts:
            continue
        found.setdefault("shell", []).append(sh_file.name)

    return found


def _get_allowed_capabilities(frontmatter: dict[str, object]) -> set[str]:
    tools = frontmatter.get("allowed-tools", [])
    if not isinstance(tools, list):
        return set()
    caps: set[str] = set()
    for tool in tools:
        tool_lower = str(tool).lower().strip()
        if tool_lower == "*":
            return {"shell", "network", "file_write", "file_read", "env", "__wildcard__"}
        mapped = _TOOL_TO_CAPABILITY.get(tool_lower, set())
        caps.update(mapped)
    return caps


class McpLeastPrivilege:
    meta: RuleMeta = RuleMeta(
        id="security/mcp-least-privilege",
        default_severity=Severity.WARNING,
        fixable=False,
        description="Check that declared allowed-tools match actual code capabilities",
        category=RuleCategory.SECURITY,
        messages={
            "mcp_underdeclared": "Code uses {{capability}} (in {{files}}) but allowed-tools does not grant it. The tool may fail at runtime or is accessing capabilities beyond its declared scope.",
            "mcp_wildcard": "allowed-tools contains a wildcard (*), granting unrestricted access. Consider declaring specific tools.",
            "mcp_overdeclared": "allowed-tools grants {{capability}} access but no code uses it. Remove unused permissions to follow least-privilege.",
        },
        frameworks={"owasp_agentic": "AG02"},
        default_suggestion="Restrict the MCP server's tool list to only required tools.",
    )

    def create(self, context: RuleContext) -> None:
        skill = context.skill
        if not skill.dir_path or not skill.frontmatter:
            return

        skill_dir = Path(skill.dir_path)
        if not skill_dir.is_dir():
            return

        allowed = _get_allowed_capabilities(skill.frontmatter)
        if "__wildcard__" in allowed:
            context.report(
                ReportDescriptor(
                    message_id="mcp_wildcard",
                    location=Location(file=skill.skill_md_path),
                )
            )
            return

        if not allowed and "allowed-tools" not in skill.frontmatter:
            return

        actual = _detect_capabilities(skill_dir)

        for cap, files in actual.items():
            if cap not in allowed:
                unique_files = sorted(set(files))
                context.report(
                    ReportDescriptor(
                        message_id="mcp_underdeclared",
                        data={
                            "capability": cap,
                            "files": ", ".join(unique_files[:3]),
                        },
                        location=Location(file=skill.skill_md_path),
                    )
                )

        if not actual:
            return

        for cap in allowed:
            if cap not in actual:
                context.report(
                    ReportDescriptor(
                        message_id="mcp_overdeclared",
                        data={"capability": cap},
                        location=Location(file=skill.skill_md_path),
                        severity_override=Severity.INFO,
                    )
                )
