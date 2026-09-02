from __future__ import annotations

import re

from harness_eval.inspection.types import (
    Location,
    ReportDescriptor,
    RuleCategory,
    RuleContext,
    RuleMeta,
    Severity,
)

_HEDGING: list[tuple[str, re.Pattern[str]]] = [
    ("try to", re.compile(r"\btry\s+to\s+\w+", re.I)),
    ("if possible", re.compile(r"\bif\s+(?:at\s+all\s+)?possible\b", re.I)),
    ("you might want to", re.compile(r"\byou\s+might\s+(?:want|wish)\s+to\b", re.I)),
    ("perhaps consider", re.compile(r"\bperhaps\s+(?:consider|you)\b", re.I)),
    ("ideally", re.compile(r"\bideally\s+(?:you\s+)?should\b", re.I)),
    ("it would be nice", re.compile(r"\bit\s+would\s+be\s+(?:nice|good)\s+(?:to|if)\b", re.I)),
    ("consider using", re.compile(r"\bconsider\s+(?:using|adding|implementing)\b", re.I)),
]

_CONDITIONAL_AMBIGUITY: list[tuple[str, re.Pattern[str]]] = [
    ("if needed", re.compile(r"\bif\s+needed\b", re.I)),
    ("if appropriate", re.compile(r"\bif\s+appropriate\b", re.I)),
    ("when relevant", re.compile(r"\bwhen\s+relevant\b", re.I)),
    ("as necessary", re.compile(r"\bas\s+necessary\b", re.I)),
    ("if applicable", re.compile(r"\bif\s+applicable\b", re.I)),
    ("where suitable", re.compile(r"\bwhere\s+suitable\b", re.I)),
]

_ALL_PATTERNS: list[tuple[str, str, re.Pattern[str]]] = [
    ("hedging", label, pat) for label, pat in _HEDGING
] + [("vague condition", label, pat) for label, pat in _CONDITIONAL_AMBIGUITY]

_CATEGORY_ADVICE = {
    "hedging": "State directly for reliable compliance",
    "vague condition": "Specify a testable condition",
}


class ImpreciseInstruction:
    meta = RuleMeta(
        id="quality/imprecise-instruction",
        default_severity=Severity.WARNING,
        fixable=False,
        description="Instructions should use direct, unambiguous language",
        category=RuleCategory.CONTENT,
        messages={
            "imprecise": ("Line {{line}}: '{{match}}' — {{category}}. {{advice}}"),
        },
        default_suggestion="Replace vague language with specific, actionable wording.",
    )

    def create(self, context: RuleContext) -> None:
        skill = context.skill
        if skill is None:
            return
        if not skill.body:
            return

        from harness_eval.inspection.rules._context import ContextTracker

        lines = skill.body.split("\n")
        tracker = ContextTracker()

        for i, line in enumerate(lines):
            tracker.update(line)

            if tracker.is_fenced():
                continue
            if line.lstrip().startswith(">"):
                continue

            for category, label, pattern in _ALL_PATTERNS:
                if pattern.search(line):
                    context.report(
                        ReportDescriptor(
                            message_id="imprecise",
                            data={
                                "line": str(skill.body_start_line + i),
                                "match": label,
                                "category": category,
                                "advice": _CATEGORY_ADVICE[category],
                            },
                            location=Location(
                                file=skill.skill_md_path,
                                start_line=skill.body_start_line + i,
                            ),
                        )
                    )
                    break
