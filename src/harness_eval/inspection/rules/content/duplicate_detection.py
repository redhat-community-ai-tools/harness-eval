from __future__ import annotations

from harness_eval.inspection.types import (
    Location,
    ReportDescriptor,
    RuleCategory,
    RuleContext,
    RuleMeta,
    Severity,
)
from harness_eval.utils.similarity import build_similarity_matrix

SIMILARITY_THRESHOLD = 0.85

_STATE_KEY = "content/duplicate-detection"


class DuplicateDetection:
    meta: RuleMeta = RuleMeta(
        id="content/duplicate-detection",
        effect="advice",
        scope="PAIRWISE",
        default_severity=Severity.WARNING,
        fixable=False,
        description="Detect near-duplicate skills",
        category=RuleCategory.CONTENT,
        messages={
            "duplicate": "{{similarity}}% similar to '{{other}}' — consider merging",
        },
        default_suggestion="Merge near-duplicate skills into one.",
    )

    def create(self, context: RuleContext) -> None:
        skill = context.skill
        if skill is None:
            return
        if not skill.body:
            return

        if _STATE_KEY not in context.scan_state:
            texts = {s.dir_name: s.body for s in context.all_skills if s.body}
            context.scan_state[_STATE_KEY] = {
                "matrix": build_similarity_matrix(texts),
                "reported": set(),
            }
        state = context.scan_state[_STATE_KEY]
        matrix = state["matrix"]

        skill_key = skill.dir_name

        for other in context.all_skills:
            if other.dir_name == skill_key or not other.body:
                continue

            pair = tuple(sorted([skill_key, other.dir_name]))
            if pair in state["reported"]:
                continue

            similarity = matrix.get(skill_key, other.dir_name)
            if similarity >= SIMILARITY_THRESHOLD:
                state["reported"].add(pair)
                context.report(
                    ReportDescriptor(
                        message_id="duplicate",
                        data={
                            "similarity": str(int(similarity * 100)),
                            "other": other.dir_name,
                        },
                        location=Location(
                            file=skill.skill_md_path,
                            start_line=1,
                        ),
                    )
                )
