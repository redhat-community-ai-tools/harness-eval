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

_MANIPULATION_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "forced pre-invocation",
        re.compile(
            r"\b(?:MUST|ALWAYS)\s+(?:use|invoke|run|call)\s+(?:this\s+)?(?:before|first|prior)\b"
        ),
    ),
    (
        "blocks without self",
        re.compile(
            r"\b(?:Do\s+NOT|NEVER)\s+(?:proceed|continue|code|work)\s+(?:without|unless)\s+(?:this|running\s+this)\b"
        ),
    ),
    (
        "claims all tasks",
        re.compile(r"\b(?:required|mandatory|essential)\s+for\s+(?:all|every|any)\b", re.I),
    ),
    (
        "hijacks broad category",
        re.compile(
            r"\b(?:any|all|every)\s+(?:creative|coding|development|technical)\s+(?:work|tasks?|requests?)\b",
            re.I,
        ),
    ),
]


class TriggerManipulation:
    meta = RuleMeta(
        id="quality/trigger-manipulation",
        default_severity=Severity.WARNING,
        fixable=False,
        description="Detect triggers that hijack conversations by forcing invocation",
        category=RuleCategory.CONTENT,
        messages={
            "manipulation": (
                "Line {{line}}: '{{match}}' forces this skill into conversations "
                "where it may not be needed. Let the user decide when to invoke."
            ),
        },
        default_suggestion="Replace forced-invocation triggers with descriptive when-to-use guidance.",
    )

    def create(self, context: RuleContext) -> None:
        skill = context.skill
        content_parts = []
        start_line = 1

        if skill.frontmatter:
            desc = skill.frontmatter.get("description", "")
            if isinstance(desc, str) and desc:
                content_parts.append(desc)

        if skill.body:
            start_line = skill.body_start_line
            content_parts.append(skill.body)

        full_content = "\n".join(content_parts)
        if not full_content:
            return

        lines = full_content.split("\n")
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

            for _label, pattern in _MANIPULATION_PATTERNS:
                if pattern.search(line):
                    short = stripped[:60] + ("..." if len(stripped) > 60 else "")
                    context.report(
                        ReportDescriptor(
                            message_id="manipulation",
                            data={
                                "line": str(start_line + i),
                                "match": short,
                            },
                            location=Location(
                                file=skill.skill_md_path,
                                start_line=start_line + i,
                            ),
                        )
                    )
                    break
