"""Flag a hooks event key that is a case or separator variant of a Claude Code
event (``preToolUse``, ``pre-tool-use``, ``Pretooluse``). Event names are
case-sensitive; the hooks under a misspelt key never run."""

from __future__ import annotations

from harness_eval.core.types import ComponentType
from harness_eval.data import load_hook_events
from harness_eval.inspection.rules.frontmatter._keys import normalize_key
from harness_eval.inspection.types import (
    Location,
    ReportDescriptor,
    RuleCategory,
    RuleContext,
    RuleMeta,
    Severity,
)


class HooksEventNameNearMiss:
    meta = RuleMeta(
        id="hooks/event-name-near-miss",
        tier="provisional",
        effect="block",
        default_severity=Severity.ERROR,
        fixable=False,
        description=(
            "Flag a hooks event key that differs from a Claude Code event name only by "
            "case or separator; the hooks under it never run"
        ),
        category=RuleCategory.STRUCTURAL,
        messages={
            "near_miss": (
                "Hook event '{{event}}' is not a Claude Code event; the hooks under it never "
                "run. Did you mean '{{expected}}'?"
            ),
        },
        target_type=ComponentType.HOOKS,
        default_suggestion="Rename the event key to the exact Claude Code event name.",
    )

    def create(self, context: RuleContext) -> None:
        hooks_data = context.hooks
        if hooks_data is None or context.source_tool not in (None, "claude"):
            return
        normalized_file = str(hooks_data.file_path).replace("\\", "/")
        if "/.cursor/" in normalized_file or normalized_file.startswith(".cursor/"):
            return
        events = load_hook_events()
        known = set(events)
        by_norm = {normalize_key(e): e for e in events}
        loc = Location(file=hooks_data.file_path)
        seen: set[str] = set()
        for hook in hooks_data.hooks:
            event = hook.get("event")
            if not isinstance(event, str) or event in known or event in seen:
                continue
            expected = by_norm.get(normalize_key(event))
            if expected is None:
                continue
            seen.add(event)
            context.report(
                ReportDescriptor(
                    message_id="near_miss",
                    data={"event": event, "expected": expected},
                    location=loc,
                )
            )
