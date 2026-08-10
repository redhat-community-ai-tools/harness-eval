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

_FIRST_PERSON = re.compile(r"\bI\s+(?:will|can|am|help)\b", re.I)
_SECOND_PERSON = re.compile(r"\bYou\s+(?:can|should|will|may)\b", re.I)

_USE_CASE_PHRASES = [
    "use when",
    "use for",
    "applies to",
    "relevant for",
    "triggered by",
    "invoke when",
    "helpful for",
]

MAX_DESCRIPTION_LENGTH = 1024
MIN_DESCRIPTION_LENGTH = 20


class DescriptionQuality:
    meta: RuleMeta = RuleMeta(
        id="frontmatter/description-quality",
        default_severity=Severity.WARNING,
        fixable=False,
        description="Description should follow Anthropic's best practices for skill discovery",
        category=RuleCategory.FRONTMATTER,
        messages={
            "first_person": "Description uses first-person POV ('{{match}}') — Anthropic recommends third-person for better discovery",
            "second_person": "Description uses second-person POV ('{{match}}') — Anthropic recommends third-person (e.g. 'Processes files' not 'You can process files')",
            "no_use_case": "Description lacks use-case context — include phrases like 'use when', 'applies to', 'relevant for' so the assistant knows when to activate it",
            "too_long": "Description is {{length}} characters — Anthropic's documented limit is 1,024",
            "too_short": "Description is only {{length}} characters — too vague for reliable skill matching",
        },
        default_suggestion="Rewrite the description to clearly state what the skill does and when to use it.",
    )

    def create(self, context: RuleContext) -> None:
        skill = context.skill
        if skill.parse_errors:
            return

        description = skill.frontmatter.get("description", "")
        if not isinstance(description, str) or not description:
            return

        loc = Location(
            file=skill.skill_md_path,
            start_line=skill.frontmatter_start_line or 1,
        )

        match = _FIRST_PERSON.search(description)
        if match:
            context.report(
                ReportDescriptor(
                    message_id="first_person",
                    data={"match": match.group(0)},
                    location=loc,
                )
            )

        match2 = _SECOND_PERSON.search(description)
        if match2:
            context.report(
                ReportDescriptor(
                    message_id="second_person",
                    data={"match": match2.group(0)},
                    location=loc,
                )
            )

        desc_lower = description.lower()
        has_use_case = any(phrase in desc_lower for phrase in _USE_CASE_PHRASES)
        if not has_use_case:
            context.report(
                ReportDescriptor(
                    message_id="no_use_case",
                    location=loc,
                )
            )

        if len(description) > MAX_DESCRIPTION_LENGTH:
            context.report(
                ReportDescriptor(
                    message_id="too_long",
                    data={"length": str(len(description))},
                    location=loc,
                )
            )

        if len(description) < MIN_DESCRIPTION_LENGTH:
            context.report(
                ReportDescriptor(
                    message_id="too_short",
                    data={"length": str(len(description))},
                    location=loc,
                )
            )
