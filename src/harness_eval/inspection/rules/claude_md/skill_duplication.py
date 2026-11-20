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
from harness_eval.utils.similarity import build_tfidf_index

OVERLAP_THRESHOLD = 0.80

_STATE_KEY = "_skill_body_index"


class ClaudeMdSkillDuplication:
    meta = RuleMeta(
        id="claude-md/skill-duplication",
        effect="advice",
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

        if _STATE_KEY not in context.scan_state:
            skill_texts = {
                s.dir_name: s.body
                for s in context.all_skills
                if s.body and len(s.body.split()) >= 20
            }
            context.scan_state[_STATE_KEY] = build_tfidf_index(skill_texts)
        index = context.scan_state[_STATE_KEY]

        for section in cmd.sections:
            section_text = section.get("content", "")
            if len(section_text.split()) < 20:
                continue

            sims = index.query(section_text)
            for skill_name, similarity in sims.items():
                if similarity >= OVERLAP_THRESHOLD:
                    msg_id = "overlap_cursor" if context.source_tool == "cursor" else "overlap"
                    context.report(
                        ReportDescriptor(
                            message_id=msg_id,
                            data={
                                "section": section.get("header", "(untitled)"),
                                "pct": str(int(similarity * 100)),
                                "skill": skill_name,
                            },
                            location=Location(file=cmd.file_path, start_line=1),
                        )
                    )
