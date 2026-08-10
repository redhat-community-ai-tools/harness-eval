from __future__ import annotations

import re

from harness_eval.core.types import ComponentType
from harness_eval.data import load_tool_names
from harness_eval.inspection.types import (
    Location,
    ReportDescriptor,
    RuleCategory,
    RuleContext,
    RuleMeta,
    Severity,
)


class HooksMatcherMatchesNoTool:
    meta = RuleMeta(
        id="hooks/matcher-matches-no-tool",
        default_severity=Severity.WARNING,
        fixable=False,
        description="Flag hook matchers that match no known tool name",
        category=RuleCategory.STRUCTURAL,
        messages={
            "no_match": (
                "Matcher '{{matcher}}' matches no known tool name -- this hook will never fire."
            ),
            "case_mismatch": (
                "Matcher '{{matcher}}' matches no tool"
                " -- tool matchers are case-sensitive; did you mean '{{suggestion}}'?"
            ),
            "invalid_regex": (
                "Matcher '{{matcher}}' is not a valid regex -- this hook will never fire."
            ),
        },
        target_type=ComponentType.HOOKS,
        default_suggestion="Fix the matcher pattern to match a valid tool name.",
    )

    def create(self, context: RuleContext) -> None:
        hooks_data = context.hooks
        if hooks_data is None:
            return

        tool_names = load_tool_names()
        loc = Location(file=hooks_data.file_path)

        for hook in hooks_data.hooks:
            matcher = hook.get("matcher")
            if matcher is None:
                continue

            # Wildcard and empty string match everything
            if matcher == "*" or matcher == "":
                continue

            # Try to compile as regex
            try:
                pattern = re.compile(matcher)
            except re.error:
                context.report(
                    ReportDescriptor(
                        message_id="invalid_regex",
                        data={"matcher": matcher},
                        location=loc,
                    )
                )
                continue

            # Test against known tool names
            matches_something = False
            for name in tool_names:
                if pattern.search(name):
                    matches_something = True
                    break

            # Test against mcp__ prefix pattern
            if not matches_something and pattern.search("mcp__example__tool"):
                matches_something = True

            if matches_something:
                continue

            # Check for case mismatch
            matcher_lower = matcher.lower()
            suggestion = None
            for name in tool_names:
                if name.lower() == matcher_lower:
                    suggestion = name
                    break

            if suggestion:
                context.report(
                    ReportDescriptor(
                        message_id="case_mismatch",
                        data={"matcher": matcher, "suggestion": suggestion},
                        location=loc,
                    )
                )
            else:
                context.report(
                    ReportDescriptor(
                        message_id="no_match",
                        data={"matcher": matcher},
                        location=loc,
                    )
                )
