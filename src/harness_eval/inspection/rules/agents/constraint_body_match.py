from __future__ import annotations

import re

from harness_eval.core.types import ComponentType
from harness_eval.inspection.types import (
    Location,
    ReportDescriptor,
    RuleCategory,
    RuleContext,
    RuleMeta,
    Severity,
)

_CONSTRAINT_MAPPINGS: list[tuple[re.Pattern, str, str]] = [
    (re.compile(r"\b(?:cannot|do not|must not|never)\s+push\b", re.I), "Bash(git push *)", "push"),
    (
        re.compile(
            r"\b(?:cannot|do not|must not|never)\s+(?:create|open)\s+(?:a\s+)?(?:PR|pull request)",
            re.I,
        ),
        "Bash(gh pr create *)",
        "create PRs",
    ),
    (
        re.compile(r"\b(?:cannot|do not|must not|never)\s+merge\b", re.I),
        "Bash(gh pr merge *)",
        "merge",
    ),
    (
        re.compile(
            r"\b(?:cannot|do not|must not|never)\s+(?:write|modify|edit)\s+(?:files?|code)\b", re.I
        ),
        "Write",
        "write files",
    ),
    (
        re.compile(r"\b(?:cannot|do not|must not|never)\s+(?:use\s+)?sed\b", re.I),
        "Bash(sed *)",
        "use sed",
    ),
    (
        re.compile(r"\b(?:cannot|do not|must not|never)\s+delete\b", re.I),
        "Bash(rm *)",
        "delete files",
    ),
    (
        re.compile(r"\b(?:cannot|do not|must not|never)\s+install\b", re.I),
        "Bash(pip install *)",
        "install packages",
    ),
    (
        re.compile(r"\b(?:cannot|do not|must not|never)\s+commit\b", re.I),
        "Bash(git commit *)",
        "commit",
    ),
]


class ConstraintBodyMatch:
    meta: RuleMeta = RuleMeta(
        id="agent/constraint-body-match",
        default_severity=Severity.WARNING,
        fixable=False,
        description="Body constraints should be backed by disallowedTools entries",
        category=RuleCategory.CONTENT,
        messages={
            "unmatched_constraint": "Body states '{{constraint}}' but no matching disallowedTools entry found — constraint relies on agent compliance, not enforcement",
        },
        target_type=ComponentType.AGENT,
        default_suggestion="Update the agent body to match its declared constraints.",
    )

    def create(self, context: RuleContext) -> None:
        agent = context.agent
        if not agent or not agent.body:
            return

        disallowed_str = " ".join(agent.disallowed_tools).lower()

        for line_idx, line in enumerate(agent.body.split("\n")):
            for pattern, expected_tool, label in _CONSTRAINT_MAPPINGS:
                if pattern.search(line):
                    tool_base = expected_tool.split("(")[0].lower()
                    if tool_base not in disallowed_str:
                        context.report(
                            ReportDescriptor(
                                message_id="unmatched_constraint",
                                data={"constraint": label},
                                location=Location(
                                    file=agent.agent_md_path,
                                    start_line=(agent.body_start_line or 1) + line_idx,
                                ),
                            )
                        )
                    break
