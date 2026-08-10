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

_SCOPE_GRAB_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "claims universal applicability",
        re.compile(
            r"\b(?:use\s+(?:this|me)\s+for\s+)?(?:any|all|every)\s+"
            r"(?:user\s+)?(?:request|task|question|prompt|interaction)s?"
            r"(?!\s+(?:involving|about|regarding|related\s+to|concerning|for|to|that|where|with|when)\b)",
            re.I,
        ),
    ),
    (
        "demands preference over others",
        re.compile(
            r"\b(?:always\s+)?(?:prefer|prioritize|choose)\s+this\s+"
            r"(?:over|instead\s+of|before)\s+(?:other|all|any)",
            re.I,
        ),
    ),
    (
        "forces unconditional use",
        re.compile(
            r"\balways\s+(?:use|invoke|run|call|activate)\s+(?:this|me)\b",
            re.I,
        ),
    ),
    (
        "suppresses alternatives",
        re.compile(
            r"\b(?:instead\s+of|rather\s+than|not|never)\s+(?:other|any\s+other|alternative)\s+skills?\b",
            re.I,
        ),
    ),
    (
        "claims exclusivity",
        re.compile(
            r"\b(?:only|sole|exclusive)\s+(?:skill|tool|command)\s+for\b",
            re.I,
        ),
    ),
]


class ScopeGrabDescription:
    meta = RuleMeta(
        id="quality/scope-grab-description",
        default_severity=Severity.WARNING,
        fixable=False,
        description=(
            "Flag descriptions that hijack tool routing by claiming universal "
            "applicability or demanding preference over other skills."
        ),
        category=RuleCategory.CONTENT,
        messages={
            "scope_grab": (
                "Description contains scope-grabbing language ({{label}}): "
                "'{{match}}'. A skill description should describe what the skill "
                "does, not demand to be chosen for all requests."
            ),
        },
    )

    def create(self, context: RuleContext) -> None:
        skill = context.skill
        if not skill.frontmatter:
            return

        desc = skill.frontmatter.get("description", "")
        if not isinstance(desc, str) or not desc.strip():
            return

        loc = Location(file=skill.skill_md_path)

        for label, pattern in _SCOPE_GRAB_PATTERNS:
            match = pattern.search(desc)
            if match:
                short = match.group(0)[:60]
                context.report(
                    ReportDescriptor(
                        message_id="scope_grab",
                        data={"label": label, "match": short},
                        location=loc,
                    )
                )
                break
