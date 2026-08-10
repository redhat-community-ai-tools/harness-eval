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
        "Use claude-sonnet-4-6 or gpt-4o",
        re.compile(r"\btext-davinci-\d+\b", re.I),
    ),
    (
        "gpt-3.5-turbo",
        "Use gpt-4o-mini or claude-haiku-4-5",
        re.compile(r"\bgpt-3\.5-turbo\b", re.I),
    ),
    (
        "code-davinci",
        "Use claude-sonnet-4-6 or gpt-4o",
        re.compile(r"\bcode-davinci-\d+\b", re.I),
    ),
    (
        "Codex API",
        "Use the Chat Completions API",
        re.compile(r"\bcodex\s+api\b", re.I),
    ),
    (
        "OpenAI Completions (legacy)",
        "Use the Chat Completions endpoint",
        re.compile(r"\b/v1/completions\b"),
    ),
    (
        "Claude v1",
        "Use claude-sonnet-4-6 or claude-haiku-4-5",
        re.compile(r"\bclaude-(?:v1|1(?:\.\d)?|instant-v1)\b", re.I),
    ),
    (
        "Claude 2",
        "Use claude-sonnet-4-6 or claude-haiku-4-5",
        re.compile(r"\bclaude-2(?:\.\d)?\b", re.I),
    ),
    (
        "PaLM API",
        "Use the Gemini API",
        re.compile(r"\bpalm[\s-](?:api|2)\b", re.I),
    ),
    (
        "Node 14/16",
        "Use Node 18+ (LTS)",
        re.compile(r"\bnode\s+(?:14|16)\b", re.I),
    ),
    (
        "Python 3.7/3.8",
        "Use Python 3.11+",
        re.compile(r"\bpython\s+3\.(?:7|8)\b", re.I),
    ),
    (
        "create-react-app",
        "Use Vite or Next.js",
        re.compile(r"\bcreate-react-app\b", re.I),
    ),
    (
        "tslint",
        "Use eslint with @typescript-eslint",
        re.compile(r"\btslint\b", re.I),
    ),
    (
        "moment.js",
        "Use date-fns, dayjs, or Temporal",
        re.compile(r"\bmoment(?:\.js|\.tz|\.duration|\s*\()\b", re.I),
    ),
    (
        "request (npm package)",
        "Use fetch, undici, or axios",
        re.compile(r"\brequire\s*\(\s*['\"]request['\"]\s*\)", re.I),
    ),
]


class StaleReferences:
    meta = RuleMeta(
        id="quality/stale-references",
        default_severity=Severity.WARNING,
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
