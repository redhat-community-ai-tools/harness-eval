"""Edge case tests for the suppression system."""

from __future__ import annotations

from harness_eval.inspection.suppression import is_suppressed, parse_suppressions


class TestParseSuppressions:
    def test_file_wide_single_rule(self) -> None:
        content = "<!-- evaluator-ignore: security/no-prompt-injection -->\n# Hello"
        sups = parse_suppressions(content)
        assert "security/no-prompt-injection" in sups.get(None, set())

    def test_file_wide_multiple_rules(self) -> None:
        content = "<!-- evaluator-ignore: rule-a, rule-b, rule-c -->\n# Hello"
        sups = parse_suppressions(content)
        assert sups[None] == {"rule-a", "rule-b", "rule-c"}

    def test_next_line_suppression(self) -> None:
        content = "line 1\n<!-- evaluator-ignore-next-line: my-rule -->\nflagged line"
        sups = parse_suppressions(content)
        assert "my-rule" in sups.get(3, set())

    def test_empty_content(self) -> None:
        sups = parse_suppressions("")
        assert sups == {}

    def test_no_suppression_comments(self) -> None:
        sups = parse_suppressions("# Just markdown\nNo suppressions here.")
        assert sups == {}

    def test_case_insensitive(self) -> None:
        content = "<!-- EVALUATOR-IGNORE: my-rule -->\n"
        sups = parse_suppressions(content)
        assert "my-rule" in sups.get(None, set())

    def test_whitespace_in_rule_list(self) -> None:
        content = "<!-- evaluator-ignore:  rule-a ,  rule-b  -->\n"
        sups = parse_suppressions(content)
        assert sups[None] == {"rule-a", "rule-b"}


class TestIsSuppressed:
    def test_file_wide_suppresses_any_line(self) -> None:
        sups = {None: {"my-rule"}}
        assert is_suppressed(sups, "my-rule", 1)
        assert is_suppressed(sups, "my-rule", 100)

    def test_line_specific(self) -> None:
        sups = {5: {"my-rule"}}
        assert is_suppressed(sups, "my-rule", 5)
        assert not is_suppressed(sups, "my-rule", 4)

    def test_unrelated_rule_not_suppressed(self) -> None:
        sups = {None: {"rule-a"}}
        assert not is_suppressed(sups, "rule-b", 1)

    def test_empty_suppressions(self) -> None:
        assert not is_suppressed({}, "any-rule", 1)

    def test_none_line(self) -> None:
        sups = {None: {"my-rule"}}
        assert is_suppressed(sups, "my-rule", None)
