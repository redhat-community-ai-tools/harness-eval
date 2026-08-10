"""Tests for declarative YAML rule loading."""

from __future__ import annotations

from pathlib import Path

import pytest

from harness_eval.inspection.engine import lint
from harness_eval.inspection.registry import clear_rules, get_rule
from harness_eval.inspection.rules import register_all_rules
from harness_eval.inspection.yaml_rules import load_yaml_rules_from_dir


@pytest.fixture(autouse=True)
def _reset_registry():
    clear_rules()
    register_all_rules()
    yield
    clear_rules()
    register_all_rules()


class TestYamlRuleLoading:
    def test_loads_valid_yaml_rule(self, tmp_path: Path) -> None:
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "test-rule.yaml").write_text(
            "id: custom/test-rule\n"
            "severity: warning\n"
            "description: Test rule\n"
            "suggestion: Fix the issue\n"
            "target: skill\n"
            "category: content\n"
            "patterns:\n"
            "  - label: dangerous pattern\n"
            "    regex: 'rm\\s+-rf'\n"
            "message: Found '{{label}}' on line {{line}}\n"
        )
        count = load_yaml_rules_from_dir(rules_dir)
        assert count == 1
        rule = get_rule("custom/test-rule")
        assert rule is not None
        assert rule.meta.default_severity.value == "warning"
        assert rule.meta.default_suggestion == "Fix the issue"

    def test_yaml_rule_fires_on_matching_content(self, tmp_path: Path) -> None:
        rules_dir = tmp_path / "yaml-rules"
        rules_dir.mkdir()
        (rules_dir / "rm-rf.yaml").write_text(
            "id: custom/rm-rf-check\n"
            "severity: error\n"
            "description: Flags rm -rf in skills\n"
            "suggestion: Remove the destructive command\n"
            "target: skill\n"
            "category: security\n"
            "patterns:\n"
            "  - label: rm -rf\n"
            "    regex: 'rm\\s+-rf'\n"
            "message: Found '{{label}}' on line {{line}}\n"
        )
        load_yaml_rules_from_dir(rules_dir)

        skill_dir = tmp_path / "test-skill"
        skill_dir.mkdir()
        (skill_dir / "SKILL.md").write_text(
            "---\nname: test\ndescription: Test skill\n---\n\nRun rm -rf /tmp/cache to clean up."
        )
        result = lint(str(skill_dir))
        custom_findings = [d for d in result.diagnostics if d.rule_id == "custom/rm-rf-check"]
        assert len(custom_findings) >= 1

    def test_yaml_rule_does_not_fire_on_clean_content(self, tmp_path: Path) -> None:
        rules_dir = tmp_path / "yaml-rules"
        rules_dir.mkdir()
        (rules_dir / "rm-rf.yaml").write_text(
            "id: custom/rm-rf-clean\n"
            "severity: error\n"
            "description: Flags rm -rf\n"
            "target: skill\n"
            "category: security\n"
            "patterns:\n"
            "  - label: rm -rf\n"
            "    regex: 'rm\\s+-rf'\n"
            "message: Found '{{label}}'\n"
        )
        load_yaml_rules_from_dir(rules_dir)

        skill_dir = tmp_path / "clean-skill"
        skill_dir.mkdir()
        (skill_dir / "SKILL.md").write_text(
            "---\nname: clean\ndescription: Clean skill\n---\n\nJust a normal skill."
        )
        result = lint(str(skill_dir))
        custom_findings = [d for d in result.diagnostics if d.rule_id == "custom/rm-rf-clean"]
        assert len(custom_findings) == 0

    def test_skips_invalid_yaml(self, tmp_path: Path) -> None:
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "bad.yaml").write_text("not: valid: yaml: [[[")
        count = load_yaml_rules_from_dir(rules_dir)
        assert count == 0

    def test_skips_rule_without_patterns(self, tmp_path: Path) -> None:
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "no-patterns.yaml").write_text(
            "id: custom/no-patterns\nseverity: warning\ndescription: Missing patterns\n"
        )
        count = load_yaml_rules_from_dir(rules_dir)
        assert count == 0

    def test_empty_dir_loads_zero(self, tmp_path: Path) -> None:
        rules_dir = tmp_path / "empty"
        rules_dir.mkdir()
        count = load_yaml_rules_from_dir(rules_dir)
        assert count == 0
