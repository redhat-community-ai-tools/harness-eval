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


def test_custom_yaml_rule_loads_from_scan_path_not_cwd(tmp_path: Path) -> None:
    """YAML rules next to the scan target load even when cwd is elsewhere."""
    (tmp_path / "CLAUDE.md").write_text("# Test")
    skill_dir = tmp_path / "skills" / "demo"
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text(
        "---\nname: demo\ndescription: Demo skill\n---\n\nRun sudo apt-get install foo."
    )
    rules_dir = tmp_path / ".harness-eval" / "rules"
    rules_dir.mkdir(parents=True)
    (rules_dir / "no-sudo.yaml").write_text(
        "id: custom/no-sudo-scan-path\n"
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

    from harness_eval.inspection.registry import clear_rules, get_rule
    from harness_eval.inspection.rules import register_all_rules

    clear_rules()
    register_all_rules()
    assert get_rule("custom/no-sudo-scan-path") is None

    try:
        setup = discover_setup(name="test", path=str(tmp_path))
        results = inspect_setup(setup, RECOMMENDED, load_target_yaml=True)
        all_diags = [d for r in results for d in r.diagnostics]
        custom = [d for d in all_diags if d.rule_id == "custom/no-sudo-scan-path"]
        assert len(custom) >= 1, "custom YAML rule did not load from the scan path"
        assert get_rule("custom/no-sudo-scan-path") is None
    finally:
        clear_rules()
        register_all_rules()


def test_custom_yaml_rule_from_target_is_opt_in(tmp_path: Path) -> None:
    """Target YAML is not loaded unless load_target_yaml=True."""
    (tmp_path / "CLAUDE.md").write_text("# Test")
    skill_dir = tmp_path / "skills" / "demo"
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text(
        "---\nname: demo\ndescription: Demo skill\n---\n\nRun sudo apt-get install foo."
    )
    rules_dir = tmp_path / ".harness-eval" / "rules"
    rules_dir.mkdir(parents=True)
    (rules_dir / "no-sudo.yaml").write_text(
        "id: custom/no-sudo-opt-in\n"
        "severity: error\n"
        "description: Flag sudo usage\n"
        "target: skill\n"
        "category: security\n"
        "patterns:\n"
        "  - label: sudo\n"
        "    regex: '\\bsudo\\b'\n"
        "message: \"Found '{{label}}' on line {{line}}\"\n"
    )

    from harness_eval.inspection.registry import clear_rules, get_rule
    from harness_eval.inspection.rules import register_all_rules

    clear_rules()
    register_all_rules()
    try:
        setup = discover_setup(name="test", path=str(tmp_path))
        results = inspect_setup(setup, RECOMMENDED)
        all_diags = [d for r in results for d in r.diagnostics]
        assert [d for d in all_diags if d.rule_id == "custom/no-sudo-opt-in"] == []
        assert get_rule("custom/no-sudo-opt-in") is None
    finally:
        clear_rules()
        register_all_rules()


def test_custom_yaml_rules_do_not_leak_across_scans(tmp_path: Path) -> None:
    """YAML loaded for project A must not still be registered for project B."""
    from harness_eval.inspection.registry import clear_rules, get_rule
    from harness_eval.inspection.rules import register_all_rules

    project_a = tmp_path / "a"
    skill_a = project_a / "skills" / "demo"
    skill_a.mkdir(parents=True)
    (project_a / "CLAUDE.md").write_text("# A")
    (skill_a / "SKILL.md").write_text(
        "---\nname: demo\ndescription: Demo skill\n---\n\nRun sudo apt-get install foo."
    )
    rules_a = project_a / ".harness-eval" / "rules"
    rules_a.mkdir(parents=True)
    (rules_a / "no-sudo.yaml").write_text(
        "id: custom/no-sudo-leak\n"
        "severity: error\n"
        "description: Flag sudo usage\n"
        "target: skill\n"
        "category: security\n"
        "patterns:\n"
        "  - label: sudo\n"
        "    regex: '\\bsudo\\b'\n"
        "message: \"Found '{{label}}' on line {{line}}\"\n"
    )

    project_b = tmp_path / "b"
    skill_b = project_b / "skills" / "demo"
    skill_b.mkdir(parents=True)
    (project_b / "CLAUDE.md").write_text("# B")
    (skill_b / "SKILL.md").write_text(
        "---\nname: demo\ndescription: Demo skill\n---\n\nRun sudo apt-get install foo."
    )

    clear_rules()
    register_all_rules()
    try:
        setup_a = discover_setup(name="a", path=str(project_a))
        results_a = inspect_setup(setup_a, RECOMMENDED, load_target_yaml=True)
        assert any(d.rule_id == "custom/no-sudo-leak" for r in results_a for d in r.diagnostics)
        assert get_rule("custom/no-sudo-leak") is None

        setup_b = discover_setup(name="b", path=str(project_b))
        results_b = inspect_setup(setup_b, RECOMMENDED)
        assert [
            d for r in results_b for d in r.diagnostics if d.rule_id == "custom/no-sudo-leak"
        ] == []
    finally:
        clear_rules()
        register_all_rules()
