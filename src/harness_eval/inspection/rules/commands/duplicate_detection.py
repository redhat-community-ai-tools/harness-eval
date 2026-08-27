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

SIMILARITY_THRESHOLD = 0.85

_STATE_KEY = "command/duplicate-detection"


class CommandDuplicateDetection:
    meta = RuleMeta(
        id="command/duplicate-detection",
        scope="PAIRWISE",
        default_severity=Severity.WARNING,
        fixable=False,
        description="Detect near-duplicate commands",
        category=RuleCategory.CONTENT,
        messages={
            "duplicate": "{{similarity}}% similar to command '{{other}}' — consider merging",
        },
        target_type=ComponentType.COMMAND,
        default_suggestion="Merge near-duplicate commands into one.",
    )

    def create(self, context: RuleContext) -> None:
        cmd = context.command
        if cmd is None or not cmd.body:
            return

        if _STATE_KEY not in context.scan_state:
            context.scan_state[_STATE_KEY] = {"texts": {}, "reported": set()}
        state = context.scan_state[_STATE_KEY]

        cmd_key = cmd.dir_name
        state["texts"][cmd_key] = cmd.body

        for other_name, other_text in state["texts"].items():
            if other_name == cmd_key:
                continue

            pair = tuple(sorted([cmd_key, other_name]))
            if pair in state["reported"]:
                continue

            similarity = tfidf_similarity(cmd.body, other_text)
            if similarity >= SIMILARITY_THRESHOLD:
                state["reported"].add(pair)
                context.report(
                    ReportDescriptor(
                        message_id="duplicate",
                        data={
                            "similarity": str(int(similarity * 100)),
                            "other": other_name,
                        },
                        location=Location(file=cmd.command_md_path, start_line=1),
                    )
                )
