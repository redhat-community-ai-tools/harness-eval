from __future__ import annotations

import re
from pathlib import Path

from harness_eval.core.types import ComponentType
from harness_eval.inspection.types import (
    Location,
    ReportDescriptor,
    RuleCategory,
    RuleContext,
    RuleMeta,
    Severity,
)
from harness_eval.utils.similarity import tfidf_similarity

_MEMORY_FILES = ["CLAUDE.md", "AGENTS.md", "GEMINI.md"]
_MIN_FILE_LENGTH = 200
_DRIFT_LOW = 0.75
_DRIFT_HIGH = 0.97
_MAX_FINDINGS = 5

_HEADING_RE = re.compile(r"^(#{1,6})\s+(.+)$", re.MULTILINE)


def _split_sections(content: str) -> dict[str, str]:
    """Split markdown into sections by heading."""
    sections: dict[str, str] = {}
    headings = list(_HEADING_RE.finditer(content))
    if not headings:
        return {"(root)": content}

    # Content before first heading
    if headings[0].start() > 0:
        preamble = content[: headings[0].start()].strip()
        if preamble:
            sections["(root)"] = preamble

    for i, match in enumerate(headings):
        heading = match.group(2).strip()
        start = match.end()
        end = headings[i + 1].start() if i + 1 < len(headings) else len(content)
        body = content[start:end].strip()
        if body:
            sections[heading] = body

    return sections


class MultiAssistantDrift:
    meta = RuleMeta(
        id="cross/multi-assistant-drift",
        tier="gating",
        scope="PAIRWISE",
        default_severity=Severity.WARNING,
        fixable=False,
        description=(
            "Flag diverged copies of assistant memory files (CLAUDE.md, AGENTS.md, GEMINI.md)"
        ),
        category=RuleCategory.CROSS_COMPONENT,
        messages={
            "drift": (
                "Section '{{heading}}' differs between {{file_a}} and {{file_b}}"
                " -- these look like diverged copies."
                " Different assistants are getting different instructions."
            ),
        },
        target_type=ComponentType.SKILL,
        default_suggestion="Sync the diverged sections between assistant memory files.",
    )

    def create(self, context: RuleContext) -> None:
        if context.scan_state.get("multi_assistant_drift_checked"):
            return
        context.scan_state["multi_assistant_drift_checked"] = True

        # Walk up from current skill to find project root
        root = self._find_project_root(context.skill.dir_path)
        if not root:
            return

        # Load memory files
        files: dict[str, tuple[str, str]] = {}  # name -> (path, content)
        for name in _MEMORY_FILES:
            filepath = root / name
            if filepath.is_file():
                content = filepath.read_text(encoding="utf-8", errors="replace")
                if len(content) >= _MIN_FILE_LENGTH:
                    files[name] = (str(filepath), content)

        if len(files) < 2:
            return

        # Compare sections pairwise
        findings_count = 0
        file_names = list(files.keys())

        for i in range(len(file_names)):
            for j in range(i + 1, len(file_names)):
                if findings_count >= _MAX_FINDINGS:
                    return

                name_a = file_names[i]
                name_b = file_names[j]
                path_a, content_a = files[name_a]
                _path_b, content_b = files[name_b]

                sections_a = _split_sections(content_a)
                sections_b = _split_sections(content_b)

                # Find matching section headings
                common_headings = set(sections_a.keys()) & set(sections_b.keys())
                for heading in sorted(common_headings):
                    if findings_count >= _MAX_FINDINGS:
                        return

                    text_a = sections_a[heading]
                    text_b = sections_b[heading]

                    if not text_a.strip() or not text_b.strip():
                        continue

                    sim = tfidf_similarity(text_a, text_b)
                    if _DRIFT_LOW <= sim < _DRIFT_HIGH:
                        findings_count += 1
                        context.report(
                            ReportDescriptor(
                                message_id="drift",
                                data={
                                    "heading": heading,
                                    "file_a": name_a,
                                    "file_b": name_b,
                                },
                                location=Location(file=path_a),
                            )
                        )

    def _find_project_root(self, skill_path: str) -> Path | None:
        """Walk up from skill path to find project root (has .git or memory files)."""
        current = Path(skill_path).resolve()
        while current != current.parent:
            if (current / ".git").is_dir():
                return current
            if any((current / f).is_file() for f in _MEMORY_FILES):
                return current
            current = current.parent
        return None
