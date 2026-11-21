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
from harness_eval.utils.similarity import build_similarity_matrix

SIMILARITY_THRESHOLD = 0.85

_STATE_KEY = "command/duplicate-detection"


class CommandDuplicateDetection:
    meta = RuleMeta(
        id="command/duplicate-detection",
        effect="advice",
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
            texts = {c.dir_name: c.body for c in context.all_commands if c.body and c.body.strip()}
            context.scan_state[_STATE_KEY] = {
                "matrix": build_similarity_matrix(texts),
                "reported": set(),
            }
        state = context.scan_state[_STATE_KEY]
        matrix = state["matrix"]

        cmd_key = cmd.dir_name

        for other in context.all_commands:
            if other.dir_name == cmd_key or not other.body:
                continue

            pair = tuple(sorted([cmd_key, other.dir_name]))
            if pair in state["reported"]:
                continue

            similarity = matrix.get(cmd_key, other.dir_name)
            if similarity >= SIMILARITY_THRESHOLD:
                state["reported"].add(pair)
                context.report(
                    ReportDescriptor(
                        message_id="duplicate",
                        data={
                            "similarity": str(int(similarity * 100)),
                            "other": other.dir_name,
                        },
                        location=Location(file=cmd.command_md_path, start_line=1),
                    )
                )
