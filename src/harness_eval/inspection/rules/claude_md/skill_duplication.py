from __future__ import annotations

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

OVERLAP_THRESHOLD = 0.80


class ClaudeMdSkillDuplication:
    meta = RuleMeta(
        id="claude-md/skill-duplication",
        scope="PAIRWISE",
        default_severity=Severity.WARNING,
        fixable=False,
        description="CLAUDE.md should not duplicate content that's already in skills",
        category=RuleCategory.CONTENT,
        messages={
            "overlap": "CLAUDE.md section '{{section}}' has {{pct}}% similarity with skill '{{skill}}' — consider removing the duplicate content from CLAUDE.md since the skill loads on demand",
            "overlap_cursor": "Rules section '{{section}}' has {{pct}}% similarity with skill '{{skill}}' — consider removing the duplicate content from the rule file since the skill loads on demand",
        },
        target_type=ComponentType.CLAUDE_MD,
        default_suggestion="Remove the duplicated content from CLAUDE.md.",
    )

    def create(self, context: RuleContext) -> None:
        cmd = context.claude_md
        if cmd is None or not context.all_skills:
            return

        for section in cmd.sections:
            section_text = section.get("content", "")
            if len(section_text.split()) < 20:
                continue

            for skill in context.all_skills:
                if not skill.body or len(skill.body.split()) < 20:
                    continue

                similarity = tfidf_similarity(section_text, skill.body)
                if similarity >= OVERLAP_THRESHOLD:
                    msg_id = "overlap_cursor" if context.source_tool == "cursor" else "overlap"
                    context.report(
                        ReportDescriptor(
                            message_id=msg_id,
                            data={
                                "section": section.get("header", "(untitled)"),
                                "pct": str(int(similarity * 100)),
                                "skill": skill.dir_name,
                            },
                            location=Location(file=cmd.file_path, start_line=1),
                        )
                    )
