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

_NEGATIVE_KEYWORDS = re.compile(
    r"^\s*[-*]?\s*(?:don'?t|do\s+not|never|avoid|must\s+not|should\s+not|cannot)\s+",
    re.IGNORECASE,
)

_POSITIVE_SIGNALS = re.compile(
    r"\b(?:instead|prefer|rather|alternative|replace\s+with)\b",
    re.IGNORECASE,
)

_USE_AS_ALTERNATIVE = re.compile(
    r"(?:^|[.;])\s*use\s+",
    re.IGNORECASE,
)

_WINDOW = 3


class NegativeOnly:
    meta = RuleMeta(
        id="quality/negative-only",
        default_severity=Severity.WARNING,
        fixable=False,
        description="Prohibitions should include a constructive alternative",
        category=RuleCategory.CONTENT,
        messages={
            "negative_only": (
                "Line {{line}}: '{{match}}' states what not to do without saying what to do instead"
            ),
        },
        default_suggestion="Add what to do instead after each prohibition.",
    )

    def create(self, context: RuleContext) -> None:
        skill = context.skill
        if skill is None:
            return
        if not skill.body:
            return

        lines = skill.body.split("\n")
        in_code_fence = False

        for i, line in enumerate(lines):
            stripped = line.strip()

            if stripped.startswith("```"):
                in_code_fence = not in_code_fence
                continue

            if in_code_fence:
                continue

            if stripped.startswith(">"):
                continue

            match = _NEGATIVE_KEYWORDS.match(stripped)
            if not match:
                continue

            if _POSITIVE_SIGNALS.search(line) or _USE_AS_ALTERNATIVE.search(line):
                continue

            window = lines[i + 1 : i + 1 + _WINDOW]
            has_alternative = any(
                _POSITIVE_SIGNALS.search(w) or _USE_AS_ALTERNATIVE.search(w) for w in window
            )
            if has_alternative:
                continue

            short = stripped[:60] + ("..." if len(stripped) > 60 else "")
            context.report(
                ReportDescriptor(
                    message_id="negative_only",
                    data={
                        "line": str(skill.body_start_line + i),
                        "match": short,
                    },
                    location=Location(
                        file=skill.skill_md_path,
                        start_line=skill.body_start_line + i,
                    ),
                )
            )
