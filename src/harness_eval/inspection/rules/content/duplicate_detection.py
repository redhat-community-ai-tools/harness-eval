from __future__ import annotations

from harness_eval.inspection.types import (
    Location,
    ReportDescriptor,
    RuleCategory,
    RuleContext,
    RuleMeta,
    Severity,
)
from harness_eval.utils.similarity import tfidf_similarity

SIMILARITY_THRESHOLD = 0.85

_STATE_KEY = "content/duplicate-detection"


class DuplicateDetection:
    meta: RuleMeta = RuleMeta(
        id="content/duplicate-detection",
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
        if not skill.body:
            return

        if _STATE_KEY not in context.scan_state:
            context.scan_state[_STATE_KEY] = {"texts": {}, "reported": set()}
        state = context.scan_state[_STATE_KEY]

        skill_key = skill.dir_name
        state["texts"][skill_key] = skill.body

        for other_name, other_text in state["texts"].items():
            if other_name == skill_key:
                continue

            pair = tuple(sorted([skill_key, other_name]))
            if pair in state["reported"]:
                continue

            similarity = tfidf_similarity(skill.body, other_text)
            if similarity >= SIMILARITY_THRESHOLD:
                state["reported"].add(pair)
                context.report(
                    ReportDescriptor(
                        message_id="duplicate",
                        data={
                            "similarity": str(int(similarity * 100)),
                            "other": other_name,
                        },
                        location=Location(
                            file=skill.skill_md_path,
                            start_line=1,
                        ),
                    )
                )
