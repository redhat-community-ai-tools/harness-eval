from __future__ import annotations

import json
import re
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

# Tools where bare (unscoped) grants are high-risk because they enable
# arbitrary write, execute, or exfiltration.
_HIGH_RISK_BARE_TOOLS = {"Bash", "Edit", "Write", "WebFetch"}

# Matches Bash(<prefix>*) or Bash(<prefix>:*) with a very short prefix,
# meaning the scope is too broad to be meaningful.
_BROAD_BASH_RE = re.compile(r"^Bash\((.{0,3})\*\)$|^Bash\((.{0,3}):\*\)$")


def _find_settings_files(search_paths: list[str]) -> list[Path]:
    """Find .claude/settings.json and .claude/settings.local.json by walking up."""
    seen_roots: set[Path] = set()
    settings_files: list[Path] = []

    for dir_path in search_paths:
        current = Path(dir_path).resolve()
        while current != current.parent:
            claude_dir = current / ".claude"
            if claude_dir.is_dir() and current not in seen_roots:
                seen_roots.add(current)
                for name in ("settings.json", "settings.local.json"):
                    candidate = claude_dir / name
                    if candidate.is_file():
                        settings_files.append(candidate)
            current = current.parent

    return settings_files


def _classify_entry(entry: str) -> tuple[str, Severity] | None:
    """Classify a single permissions.allow entry. Returns (reason, severity) or None."""
    # Bash(*) — unrestricted shell
    if entry == "Bash(*)":
        return "grants unrestricted shell access", Severity.ERROR

    # Bare high-risk tool name (no parens = all invocations)
    if entry in _HIGH_RISK_BARE_TOOLS and "(" not in entry:
        return f"bare '{entry}' covers all invocations without scoping", Severity.WARNING

    # Broad Bash wildcard with a very short prefix
    m = _BROAD_BASH_RE.match(entry)
    if m:
        prefix = m.group(1) or m.group(2)
        return (
            f"Bash wildcard with {len(prefix)}-char prefix '{prefix}' is too broad",
            Severity.WARNING,
        )

    return None


class OverpermissiveGrants:
    meta = RuleMeta(
        id="cross/overpermissive-grants",
        default_severity=Severity.WARNING,
        fixable=False,
        description=("Flag permissions.allow entries that grant broad or unrestricted tool access"),
        category=RuleCategory.CROSS_COMPONENT,
        messages={
            "overpermissive": (
                "permissions.allow entry '{{entry}}' in {{file}}: {{reason}}."
                " Scope tool grants to specific commands or paths."
            ),
        },
        target_type=ComponentType.SKILL,
        default_suggestion="Scope the permission grant to specific commands or paths.",
    )

    def create(self, context: RuleContext) -> None:
        if context.scan_state.get("overpermissive_grants_checked"):
            return
        context.scan_state["overpermissive_grants_checked"] = True

        skills = context.all_skills if context.all_skills else [context.skill]
        skill_paths = [s.dir_path for s in skills]

        settings_files = _find_settings_files(skill_paths)
        if not settings_files:
            return

        for settings_path in settings_files:
            try:
                data = json.loads(settings_path.read_text())
            except (json.JSONDecodeError, OSError):
                continue

            permissions = data.get("permissions", {})
            if not isinstance(permissions, dict):
                continue

            allow_list = permissions.get("allow", [])
            if not isinstance(allow_list, list):
                continue

            for entry in allow_list:
                if not isinstance(entry, str):
                    continue
                result = _classify_entry(entry)
                if result is not None:
                    reason, severity = result
                    context.report(
                        ReportDescriptor(
                            message_id="overpermissive",
                            data={
                                "entry": entry,
                                "file": settings_path.name,
                                "reason": reason,
                            },
                            location=Location(file=str(settings_path)),
                            severity_override=severity,
                        )
                    )
