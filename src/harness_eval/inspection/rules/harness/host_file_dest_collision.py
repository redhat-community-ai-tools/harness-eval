"""Two host files must not be delivered to the same sandbox path.

Host files are copied into the sandbox in declaration order. When two
entries name the same destination, the second silently overwrites the
first and the agent runs with whichever was listed last. Optional entries
are excluded: an optional source may legitimately be absent, so whether it
collides depends on the host at run time.
"""

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


def _nth_line_of(raw: str, needle: str, n: int) -> int | None:
    seen = 0
    for i, line in enumerate(raw.splitlines(), 1):
        if needle in line:
            seen += 1
            if seen == n:
                return i
    return None


class HarnessHostFileDestCollision:
    meta = RuleMeta(
        id="harness/host-file-dest-collision",
        tier="provisional",
        scope="FILE",
        default_severity=Severity.ERROR,
        fixable=False,
        description="Two non-optional host files must not map to the same sandbox destination",
        category=RuleCategory.STRUCTURAL,
        messages={
            "collision": (
                "host_files entries '{{first}}' and '{{second}}' both deliver to '{{dest}}'; "
                "the later entry overwrites the earlier one"
            ),
        },
        target_type=ComponentType.HARNESS,
        default_suggestion="Give each host file a distinct destination or drop the duplicate.",
    )

    def create(self, context: RuleContext) -> None:
        harness = context.harness
        if harness is None or harness.fields is None:
            return
        seen: dict[str, str] = {}
        for hf in harness.fields.host_files:
            if hf.optional:
                continue
            if hf.dest in seen:
                context.report(
                    ReportDescriptor(
                        message_id="collision",
                        data={"first": seen[hf.dest], "second": hf.src, "dest": hf.dest},
                        location=Location(
                            file=harness.file_path,
                            start_line=_nth_line_of(harness.raw_content, hf.dest, 2),
                        ),
                    )
                )
                continue
            seen[hf.dest] = hf.src
