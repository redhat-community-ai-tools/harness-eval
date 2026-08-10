from __future__ import annotations

from harness_eval.core.types import ComponentType
from harness_eval.data import load_tautological_patterns
from harness_eval.inspection.types import (
    Location,
    ReportDescriptor,
    RuleCategory,
    RuleContext,
    RuleMeta,
    Severity,
)

_GENERIC_PATTERNS = load_tautological_patterns(generic_advice_only=True)


class ClaudeMdGenericAdvice:
    meta = RuleMeta(
        id="claude-md/generic-advice",
        default_severity=Severity.WARNING,
        fixable=False,
        description="CLAUDE.md should not contain generic advice Claude already follows by default",
        category=RuleCategory.CONTENT,
        messages={
            "generic": "Line {{line}}: '{{label}}' — Claude does this by default. This instruction wastes tokens every session.",
        },
        target_type=ComponentType.CLAUDE_MD,
        tools=("claude",),
        default_suggestion="Remove the generic instruction or make it project-specific.",
    )

    def create(self, context: RuleContext) -> None:
        claude_md = context.claude_md
        if claude_md is None or not claude_md.raw_content:
            return

        from harness_eval.inspection.rules._context import ContextTracker

        lines = claude_md.raw_content.split("\n")
        tracker = ContextTracker()

        for i, line in enumerate(lines):
            tracker.update(line)

            if tracker.is_fenced():
                continue

            for label, pattern in _GENERIC_PATTERNS:
                if pattern.search(line):
                    context.report(
                        ReportDescriptor(
                            message_id="generic",
                            data={"label": label, "line": str(i + 1)},
                            location=Location(
                                file=claude_md.file_path,
                                start_line=i + 1,
                            ),
                        )
                    )
                    break
