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

_INSTRUCTION_SIGNAL = re.compile(
    r"(?:"
    r"\b(?:always|never|must|should|do\s+not|don'?t|ensure|make\s+sure)\b"
    r"|\b(?:use|prefer|avoid|follow|run|execute|configure|set|add)\s+\w+"
    r")",
    re.I,
)

_MIN_INSTRUCTION_LINES = 5
_MIN_BODY_TOKENS = 50


class ExampleGap:
    meta = RuleMeta(
        id="quality/example-gap",
        default_severity=Severity.INFO,
        fixable=False,
        description="Skills with instructions but no examples are less effective",
        category=RuleCategory.CONTENT,
        messages={
            "no_examples": (
                "Skill has {{instruction_count}} instruction lines but no code examples. "
                "Adding a code block with a concrete example improves compliance."
            ),
        },
        default_suggestion="Add a code block with a concrete usage example.",
    )

    def create(self, context: RuleContext) -> None:
        skill = context.skill
        if not skill.body:
            return

        if skill.tokens < _MIN_BODY_TOKENS:
            return

        lines = skill.body.split("\n")
        has_code_block = False
        instruction_count = 0
        in_code_fence = False

        for line in lines:
            stripped = line.strip()

            if stripped.startswith("```"):
                in_code_fence = not in_code_fence
                has_code_block = True
                continue

            if in_code_fence:
                continue

            if _INSTRUCTION_SIGNAL.search(stripped):
                instruction_count += 1

        if has_code_block:
            return

        if instruction_count < _MIN_INSTRUCTION_LINES:
            return

        context.report(
            ReportDescriptor(
                message_id="no_examples",
                data={"instruction_count": str(instruction_count)},
                location=Location(file=skill.skill_md_path, start_line=1),
            )
        )
