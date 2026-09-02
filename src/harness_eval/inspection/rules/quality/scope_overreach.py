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

_OVERREACH_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "universal scope",
        re.compile(r"\brequired\s+for\s+(?:all|every|any)\s+(?:tasks?|work|operations?)\b", re.I),
    ),
    (
        "claims priority",
        re.compile(r"\balways\s+(?:use|invoke|apply|run)\s+(?:this|me)\s+first\b", re.I),
    ),
    (
        "supersedes others",
        re.compile(r"\bsupersedes?\s+(?:all|every|any|other)\b", re.I),
    ),
    (
        "applies to everything",
        re.compile(
            r"\b(?:applies|apply\s+this)\s+to\s+(?:all|every|any)\s+(?:tasks?|projects?|repositories|work)\b",
            re.I,
        ),
    ),
    (
        "demands priority over skills",
        re.compile(r"\bbefore\s+(?:all|any)\s+other\s+skills?\b", re.I),
    ),
]


class ScopeOverreach:
    meta = RuleMeta(
        id="quality/scope-overreach",
        default_severity=Severity.WARNING,
        fixable=False,
        description="Detect skills claiming authority over overly broad scope",
        category=RuleCategory.CONTENT,
        messages={
            "overreach": (
                "Line {{line}}: '{{match}}' claims overly broad scope. "
                "Skills should be specific about when they apply."
            ),
        },
        default_suggestion="Narrow the scope claim to specific file types or task contexts.",
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

            for _label, pattern in _OVERREACH_PATTERNS:
                if pattern.search(line):
                    short = stripped[:60] + ("..." if len(stripped) > 60 else "")
                    context.report(
                        ReportDescriptor(
                            message_id="overreach",
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
                    break
