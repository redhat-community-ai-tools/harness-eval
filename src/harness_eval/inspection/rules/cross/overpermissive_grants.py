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

# Commands whose wildcard grant is equivalent to Bash(*): each one can run
# arbitrary code through an interpreter, an -exec/-e flag, or a shell escape.
# The reason string is what the finding reports, so it must be true of the
# command as commonly installed rather than of an exotic build.
_ARBITRARY_EXEC_COMMANDS: dict[str, str] = {
    "sh": "is a shell",
    "bash": "is a shell",
    "zsh": "is a shell",
    "dash": "is a shell",
    "fish": "is a shell",
    "env": "runs any command passed as its argument",
    "eval": "evaluates arbitrary shell text",
    "exec": "replaces the shell with any command",
    "xargs": "runs any command over its input",
    "nohup": "runs any command detached",
    "timeout": "runs any command",
    "watch": "runs any command repeatedly",
    "sudo": "runs any command with elevated privileges",
    "doas": "runs any command with elevated privileges",
    "python": "runs arbitrary code with -c or a script",
    "python3": "runs arbitrary code with -c or a script",
    "perl": "runs arbitrary code with -e",
    "ruby": "runs arbitrary code with -e",
    "node": "runs arbitrary code with -e",
    "bun": "runs arbitrary code",
    "deno": "runs arbitrary code",
    "php": "runs arbitrary code with -r",
    "lua": "runs arbitrary code with -e",
    "awk": "runs arbitrary commands via system()",
    "gawk": "runs arbitrary commands via system()",
    "mawk": "runs arbitrary commands via system()",
    "nawk": "runs arbitrary commands via system()",
    "sed": "runs arbitrary commands via the GNU e flag",
    "find": "runs arbitrary commands via -exec",
    "vim": "runs arbitrary commands via :!",
    "vi": "runs arbitrary commands via :!",
    "nvim": "runs arbitrary commands via :!",
    "less": "runs arbitrary commands via !",
    "man": "runs arbitrary commands via the pager",
    "npx": "downloads and runs arbitrary packages",
    "bunx": "downloads and runs arbitrary packages",
    "uvx": "downloads and runs arbitrary packages",
    "pipx": "downloads and runs arbitrary packages",
    "docker": "runs arbitrary containers with host access",
    "podman": "runs arbitrary containers with host access",
    "make": "runs arbitrary recipes",
    "ssh": "runs arbitrary commands on a remote host",
    "curl": "fetches arbitrary URLs and can exfiltrate data",
    "wget": "fetches arbitrary URLs and can exfiltrate data",
}

# Bash(<pattern>) where <pattern> is "<cmd>:*" or "<cmd> *" or "<cmd>*".
# Captures the leading command token, with or without a path prefix.
_BASH_GRANT_RE = re.compile(
    r"^Bash\(\s*(?:[\w./-]*/)?([\w.+-]+)"  # command token, path prefix stripped
    r"(?:\s+(-c|-e|-r|--eval|-exec|run))?"  # optional first argument
    r"(?::\s*\*|\s+\*|\*)\s*\)$"  # wildcard tail
)


def _classify_entry(entry: str) -> tuple[str, Severity] | None:
    """Classify a single permissions.allow entry. Returns (reason, severity) or None.

    Three classes are reported, each decidable from the entry text alone:
    ``Bash(*)`` (unrestricted shell), a bare high-risk tool name, and a
    wildcard grant on a command that can execute arbitrary code. A short
    prefix is not by itself evidence of anything, so ``Bash(git:*)`` and
    ``Bash(ls:*)`` are not reported.
    """
    # Bash(*) -- unrestricted shell
    if entry == "Bash(*)" or entry == "Bash(:*)":
        return "grants unrestricted shell access", Severity.ERROR

    # Bare high-risk tool name (no parens = all invocations)
    if entry in _HIGH_RISK_BARE_TOOLS and "(" not in entry:
        return f"bare '{entry}' covers all invocations without scoping", Severity.WARNING

    m = _BASH_GRANT_RE.match(entry)
    if m:
        cmd = m.group(1).lower()
        first_arg = m.group(2)
        reason = _ARBITRARY_EXEC_COMMANDS.get(cmd)
        # "python -c:*" or "docker run:*" is still an arbitrary-code grant;
        # a narrower first argument such as "python -m pytest:*" is not matched.
        if reason is not None and first_arg is not None:
            reason = f"{reason} and the grant covers that form"
        if reason is not None:
            return (
                f"wildcard grant on '{cmd}' is arbitrary command execution ({cmd} {reason})",
                Severity.ERROR,
            )

    return None


class OverpermissiveGrants:
    meta = RuleMeta(
        id="cross/overpermissive-grants",
        tier="gating",
        scope="FILE",
        default_severity=Severity.WARNING,
        fixable=False,
        description=(
            "Flag permissions.allow entries that grant unrestricted shell access, bare"
            " high-risk tools, or wildcard grants on commands that execute arbitrary code"
        ),
        category=RuleCategory.CROSS_COMPONENT,
        messages={
            "overpermissive": (
                "permissions.allow entry '{{entry}}' in {{file}}: {{reason}}."
                " Scope tool grants to specific commands or paths."
            ),
        },
        target_type=ComponentType.HOOKS,
        default_suggestion="Scope the permission grant to specific commands or paths.",
    )

    def create(self, context: RuleContext) -> None:
        hooks_data = context.hooks
        if hooks_data is None:
            return

        settings_path = Path(hooks_data.file_path)
        candidates = [settings_path]
        local = settings_path.with_name("settings.local.json")
        if local.is_file():
            candidates.append(local)

        for candidate in candidates:
            key = f"overpermissive_grants_checked:{candidate.resolve()}"
            if context.scan_state.get(key):
                continue
            context.scan_state[key] = True

            try:
                data = json.loads(candidate.read_text())
            except (json.JSONDecodeError, OSError, UnicodeDecodeError):
                continue
            if not isinstance(data, dict):
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
                    reason, _severity = result
                    context.report(
                        ReportDescriptor(
                            message_id="overpermissive",
                            data={
                                "entry": entry,
                                "file": candidate.name,
                                "reason": reason,
                            },
                            location=Location(file=str(candidate)),
                        )
                    )
