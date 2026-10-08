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

_STALE_PATTERNS: list[tuple[str, str, re.Pattern[str]]] = [
    (
        "text-davinci-003",
        "Use a currently supported model ID",
        re.compile(r"\btext-davinci-\d+\b", re.I),
    ),
    (
        "gpt-3.5-turbo",
        "Use a currently supported model ID",
        re.compile(r"\bgpt-3\.5-turbo\b", re.I),
    ),
    (
        "code-davinci",
        "Use a currently supported model ID",
        re.compile(r"\bcode-davinci-\d+\b", re.I),
    ),
    (
        "Codex API",
        "Use the current OpenAI Responses API or Codex product documentation",
        re.compile(r"\bcodex\s+api\b", re.I),
    ),
    (
        "OpenAI Completions (legacy)",
        "Use the current OpenAI Responses API unless maintaining a legacy integration",
        re.compile(r"\b/v1/completions\b"),
    ),
    (
        "Claude v1",
        "Use a currently supported Claude model ID",
        re.compile(r"\bclaude-(?:v1|1(?:\.\d)?|instant-v1)\b", re.I),
    ),
    (
        "Claude 2",
        "Use a currently supported Claude model ID",
        re.compile(r"\bclaude-2(?:\.\d)?\b", re.I),
    ),
    (
        "PaLM API",
        "Use the Gemini API",
        re.compile(r"\bpalm[\s-](?:api|2)\b", re.I),
    ),
]


class StaleReferences:
    meta = RuleMeta(
        id="quality/stale-references",
        effect="advice",
        default_severity=Severity.INFO,
        fixable=False,
        description="Detect deprecated models, sunset APIs, and outdated tool references",
        category=RuleCategory.CONTENT,
        messages={
            "stale": ("Line {{line}}: '{{label}}' is outdated. {{replacement}}"),
        },
        default_suggestion="Update the outdated reference to its current replacement.",
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

            for label, replacement, pattern in _STALE_PATTERNS:
                if pattern.search(line):
                    context.report(
                        ReportDescriptor(
                            message_id="stale",
                            data={
                                "line": str(skill.body_start_line + i),
                                "label": label,
                                "replacement": replacement,
                            },
                            location=Location(
                                file=skill.skill_md_path,
                                start_line=skill.body_start_line + i,
                            ),
                        )
                    )
                    break
