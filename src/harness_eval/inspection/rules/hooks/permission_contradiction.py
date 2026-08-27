"""Flag permissions.allow entries that permissions.deny also matches.

Claude Code evaluates deny before allow, so an entry that appears in both
lists, or an allow entry covered by a broader deny pattern, is dead
configuration: the author believes something is permitted and it is not.
The condition is decidable from the settings file alone.
"""

from __future__ import annotations

import fnmatch
import json
import re

from harness_eval.core.types import ComponentType
from harness_eval.inspection.types import (
    Location,
    ReportDescriptor,
    RuleCategory,
    RuleContext,
    RuleMeta,
    Severity,
)

_ENTRY_RE = re.compile(r"^(?P<tool>[A-Za-z_][\w]*)(?:\((?P<spec>.*)\))?$")


def _parse_entry(entry: str) -> tuple[str, str | None] | None:
    m = _ENTRY_RE.match(entry.strip())
    if not m:
        return None
    return m.group("tool"), m.group("spec")


def _spec_to_glob(spec: str) -> str:
    """Turn a Claude Code permission spec into an fnmatch glob.

    ``npm:*`` and ``npm *`` both mean "npm followed by anything". A trailing
    ``*`` with no separator is treated the same way.
    """
    spec = spec.strip()
    if spec.endswith(":*"):
        return spec[:-2] + "*"
    return spec


def deny_covers_allow(deny: str, allow: str) -> bool:
    """Return True when the deny entry matches everything the allow entry permits."""
    d = _parse_entry(deny)
    a = _parse_entry(allow)
    if d is None or a is None:
        return False
    d_tool, d_spec = d
    a_tool, a_spec = a
    if d_tool != a_tool:
        return False
    if d_spec is None:
        return True  # bare tool denial covers every invocation
    if a_spec is None:
        return False  # bare allow is wider than a scoped deny
    if d_spec == a_spec:
        return True
    d_glob = _spec_to_glob(d_spec)
    a_glob = _spec_to_glob(a_spec)
    if d_glob == "*":
        return True
    # The allow spec, with its own wildcard treated as a literal, must fall inside the deny glob.
    return fnmatch.fnmatchcase(a_glob.rstrip("*"), d_glob) or fnmatch.fnmatchcase(a_glob, d_glob)


class HooksPermissionContradiction:
    meta = RuleMeta(
        id="hooks/permission-contradiction",
        default_severity=Severity.WARNING,
        fixable=False,
        description=(
            "Flag permissions.allow entries that a permissions.deny entry also matches,"
            " because deny takes precedence and the allow is dead configuration"
        ),
        category=RuleCategory.CROSS_COMPONENT,
        messages={
            "contradiction": (
                "permissions.allow entry '{{allow}}' is covered by permissions.deny"
                " entry '{{deny}}'. Deny wins, so the allow has no effect."
            ),
        },
        target_type=ComponentType.HOOKS,
        default_suggestion="Remove the allow entry or narrow the deny entry so they do not overlap.",
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
        permissions = data.get("permissions", {})
        if not isinstance(permissions, dict):
            return
        allow = permissions.get("allow", [])
        deny = permissions.get("deny", [])
        if not isinstance(allow, list) or not isinstance(deny, list):
            return
        allow = [e for e in allow if isinstance(e, str)]
        deny = [e for e in deny if isinstance(e, str)]
        if not allow or not deny:
            return

        loc = Location(file=hooks_data.file_path)
        for a in allow:
            for d in deny:
                if deny_covers_allow(d, a):
                    context.report(
                        ReportDescriptor(
                            message_id="contradiction",
                            data={"allow": a, "deny": d},
                            location=loc,
                        )
                    )
                    break
