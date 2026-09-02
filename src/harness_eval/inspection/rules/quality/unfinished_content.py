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

_PLACEHOLDER_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "insert placeholder",
        re.compile(
            r"\[(?:INSERT|FILL\s+IN|CHANGE\s+THIS|UPDATE\s+THIS|REPLACE)\s+[^\]]+\]",
            re.I,
        ),
    ),
    ("your-placeholder", re.compile(r"\[YOUR\s+[^\]]+\]", re.I)),
    ("angle-bracket placeholder", re.compile(r"<your[-_][a-z][-_a-z]*[-_]here>", re.I)),
    ("PLACEHOLDER marker", re.compile(r"\[PLACEHOLDER\]", re.I)),
]

_PLACEHOLDER_WORDS = (
    r"(?:YOUR|INSERT|PROJECT|DESCRIPTION|API|KEY|TOKEN|URL|PATH|NAME|TEAM|ORG|COMPANY|REPO)"
)

_UNFINISHED_MARKERS: list[tuple[str, re.Pattern[str]]] = [
    ("TODO marker", re.compile(r"\bTODO\s*:", re.I)),
    ("FIXME marker", re.compile(r"\bFIXME\s*:", re.I)),
    ("XXX marker", re.compile(r"\bXXX\s*:", re.I)),
    (
        "bracket ALL-CAPS placeholder",
        re.compile(rf"\[{_PLACEHOLDER_WORDS}(?:_[A-Z]+)*\]"),
    ),
]

_DEFERRED_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("TBD", re.compile(r"\bTBD\b")),
    ("to be determined", re.compile(r"\bto\s+be\s+(?:determined|decided|defined)\b", re.I)),
    ("coming soon", re.compile(r"\bcoming\s+soon\b", re.I)),
    ("work in progress", re.compile(r"\bwork\s+in\s+progress\b", re.I)),
    ("not yet implemented", re.compile(r"\bnot\s+yet\s+(?:implemented|done|complete)\b", re.I)),
]

_HEADING_RE = re.compile(r"^(#{1,6})\s+\S")


class UnfinishedContent:
    meta = RuleMeta(
        id="quality/unfinished-content",
        default_severity=Severity.WARNING,
        fixable=False,
        description="Detect placeholders, deferred content, and empty sections",
        category=RuleCategory.CONTENT,
        messages={
            "placeholder": "Line {{line}}: '{{match}}' looks like unfilled template text",
            "unfinished": "Line {{line}}: '{{match}}' — unfinished section",
            "deferred": "Line {{line}}: '{{match}}' — deferred content wastes tokens",
            "empty_section": (
                "Line {{line}}: section '{{heading}}' has no content. "
                "Add content or remove the heading."
            ),
        },
        default_suggestion="Complete the placeholder text or remove the empty section.",
    )

    def create(self, context: RuleContext) -> None:
        skill = context.skill
        if skill is None:
            return
        if not skill.raw_content:
            return

        from harness_eval.inspection.rules._context import ContextTracker

        lines = skill.raw_content.split("\n")
        tracker = ContextTracker()

        prev_heading: tuple[int, str, int] | None = None
        prev_heading_had_content = False

        for i, line in enumerate(lines):
            stripped = line.strip()

            tracker.update(line)

            if stripped.startswith("```"):
                if not tracker.is_fenced() and prev_heading is not None:
                    prev_heading_had_content = True
                continue

            if tracker.is_fenced():
                continue

            m = _HEADING_RE.match(stripped)

            if m:
                cur_depth = len(m.group(1))
                if prev_heading is not None and not prev_heading_had_content:
                    _h_line, _h_text, prev_depth = prev_heading
                    if cur_depth <= prev_depth:
                        context.report(
                            ReportDescriptor(
                                message_id="empty_section",
                                data={"line": str(_h_line + 1), "heading": _h_text},
                                location=Location(
                                    file=skill.skill_md_path,
                                    start_line=_h_line + 1,
                                ),
                            )
                        )
                    else:
                        prev_heading_had_content = True
                prev_heading = (i, stripped.lstrip("#").strip(), cur_depth)
                prev_heading_had_content = False
                continue

            if stripped and prev_heading is not None:
                prev_heading_had_content = True

            self._check_line(context, skill, line, stripped, i)

        if prev_heading is not None and not prev_heading_had_content:
            h_line, h_text, _ = prev_heading
            context.report(
                ReportDescriptor(
                    message_id="empty_section",
                    data={"line": str(h_line + 1), "heading": h_text},
                    location=Location(
                        file=skill.skill_md_path,
                        start_line=h_line + 1,
                    ),
                )
            )

    def _check_line(
        self,
        context: RuleContext,
        skill,  # noqa: ANN001
        line: str,
        stripped: str,
        line_idx: int,
    ) -> None:
        if not stripped:
            return

        for _label, pattern in _PLACEHOLDER_PATTERNS:
            m = pattern.search(line)
            if m:
                context.report(
                    ReportDescriptor(
                        message_id="placeholder",
                        data={"line": str(line_idx + 1), "match": m.group(0)},
                        location=Location(file=skill.skill_md_path, start_line=line_idx + 1),
                    )
                )
                return

        for label, pattern in _UNFINISHED_MARKERS:
            m = pattern.search(line)
            if m:
                msg_id = "unfinished" if "marker" in label else "placeholder"
                context.report(
                    ReportDescriptor(
                        message_id=msg_id,
                        data={"line": str(line_idx + 1), "match": m.group(0)},
                        location=Location(file=skill.skill_md_path, start_line=line_idx + 1),
                    )
                )
                return

        for _label, pattern in _DEFERRED_PATTERNS:
            m = pattern.search(line)
            if m:
                context.report(
                    ReportDescriptor(
                        message_id="deferred",
                        data={"line": str(line_idx + 1), "match": m.group(0)},
                        location=Location(file=skill.skill_md_path, start_line=line_idx + 1),
                    )
                )
                return
