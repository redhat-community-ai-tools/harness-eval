"""End-to-end test: YAML rules fire through the full pipeline."""

from __future__ import annotations

from pathlib import Path

from harness_eval.config.presets import RECOMMENDED
from harness_eval.core.setup import discover_setup
from harness_eval.inspection.engine import inspect_setup


def test_custom_yaml_rule_fires_via_inspect_setup(tmp_path: Path) -> None:
    """A .harness-eval/rules/ YAML rule fires during inspect_setup with a preset."""
    (tmp_path / "CLAUDE.md").write_text("# Test")
    skill_dir = tmp_path / "skills" / "demo"
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text(
        "---\nname: demo\ndescription: Demo skill\n---\n\nRun sudo apt-get install foo."
    )
    rules_dir = tmp_path / ".harness-eval" / "rules"
    rules_dir.mkdir(parents=True)
    (rules_dir / "no-sudo.yaml").write_text(
        "id: custom/no-sudo\n"
        "severity: error\n"
        "description: Flag sudo usage\n"
        "suggestion: Remove sudo.\n"
        "target: skill\n"
        "category: security\n"
        "patterns:\n"
        "  - label: sudo\n"
        "    regex: '\\bsudo\\b'\n"
        "message: \"Found '{{label}}' on line {{line}}\"\n"
    )

    import os

    old_cwd = os.getcwd()
    try:
        os.chdir(tmp_path)
        from harness_eval.inspection.registry import clear_rules
        from harness_eval.inspection.rules import register_all_rules

        clear_rules()
        register_all_rules()

        setup = discover_setup(name="test", path=str(tmp_path))
        results = inspect_setup(setup, RECOMMENDED)
        all_diags = [d for r in results for d in r.diagnostics]
        custom = [d for d in all_diags if d.rule_id == "custom/no-sudo"]
        assert len(custom) >= 1, "custom/no-sudo rule did not fire"
        assert custom[0].suggestion == "Remove sudo."
    finally:
        os.chdir(old_cwd)
        clear_rules()
        register_all_rules()
