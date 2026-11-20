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


class CommandSkillOverlap:
    meta = RuleMeta(
        id="command/skill-overlap",
        effect="advice",
        scope="PAIRWISE",
        default_severity=Severity.WARNING,
        fixable=False,
        description="Detect commands that duplicate content already in a skill",
        category=RuleCategory.CONTENT,
        messages={
            "overlap": "Command '{{command}}' has {{pct}}% similarity with skill '{{skill}}' — consider whether both are needed",
        },
        target_type=ComponentType.COMMAND,
        default_suggestion="Remove the duplicate content or convert the command to invoke the skill.",
    )

    def create(self, context: RuleContext) -> None:
        cmd = context.command
        if cmd is None or not cmd.body or not context.all_skills:
            return

        if len(cmd.body.split()) < 20:
            return

        if _STATE_KEY not in context.scan_state:
            skill_texts = {
                s.dir_name: s.body
                for s in context.all_skills
                if s.body and len(s.body.split()) >= 20
            }
            context.scan_state[_STATE_KEY] = build_tfidf_index(skill_texts)
        index = context.scan_state[_STATE_KEY]

        sims = index.query(cmd.body)
        for skill_name, similarity in sims.items():
            if similarity >= OVERLAP_THRESHOLD:
                context.report(
                    ReportDescriptor(
                        message_id="overlap",
                        data={
                            "command": cmd.dir_name,
                            "pct": str(int(similarity * 100)),
                            "skill": skill_name,
                        },
                        location=Location(file=cmd.command_md_path, start_line=1),
                    )
                )
