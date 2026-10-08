"""Tests for Cursor IDE file discovery and evaluation."""

from __future__ import annotations

from pathlib import Path

from harness_eval.analysis.budget import analyze_budget
from harness_eval.analysis.system import analyze_system
from harness_eval.core.setup import discover_setup
from harness_eval.core.types import ComponentType
from harness_eval.inspection.engine import inspect_setup, lint_claude_md, lint_hooks
from harness_eval.output.report import format_terminal

FIXTURES_DIR = Path(__file__).parent / "fixtures"


class TestCursorDiscovery:
    def test_discover_mdc_rules(self) -> None:
        setup = discover_setup(name="cursor", path=str(FIXTURES_DIR / "sample-cursor-setup"))
        claude_md = setup.by_type(ComponentType.CLAUDE_MD)
        mdc_names = {c.name for c in claude_md}
        assert "coding-standards" in mdc_names
        assert "security" in mdc_names

    def test_discover_cursorrules(self) -> None:
        setup = discover_setup(name="cursor", path=str(FIXTURES_DIR / "sample-cursor-setup"))
        claude_md = setup.by_type(ComponentType.CLAUDE_MD)
        names = {c.name for c in claude_md}
        assert ".cursorrules" in names

    def test_discover_cursor_commands(self) -> None:
        setup = discover_setup(name="cursor", path=str(FIXTURES_DIR / "sample-cursor-setup"))
        commands = setup.by_type(ComponentType.COMMAND)
        names = {c.name for c in commands}
        assert "deploy" in names

    def test_discover_cursor_skills(self) -> None:
        setup = discover_setup(name="cursor", path=str(FIXTURES_DIR / "sample-cursor-setup"))
        skills = setup.by_type(ComponentType.SKILL)
        names = {c.name for c in skills}
        assert "code-review" in names

    def test_discover_cursor_hooks(self) -> None:
        setup = discover_setup(name="cursor", path=str(FIXTURES_DIR / "sample-cursor-setup"))
        hooks = setup.by_type(ComponentType.HOOKS)
        assert len(hooks) >= 1
        assert any("hooks.json" in c.name for c in hooks)

    def test_detect_tools_cursor_only(self) -> None:
        setup = discover_setup(name="cursor", path=str(FIXTURES_DIR / "sample-cursor-setup"))
        assert "Cursor" in setup.detected_tools
        assert "Claude Code" not in setup.detected_tools

    def test_detect_tools_both(self) -> None:
        setup = discover_setup(name="mixed", path=str(FIXTURES_DIR / "sample-mixed-setup"))
        assert "Claude Code" in setup.detected_tools
        assert "Cursor" in setup.detected_tools

    def test_mdc_content_is_parsed(self) -> None:
        setup = discover_setup(name="cursor", path=str(FIXTURES_DIR / "sample-cursor-setup"))
        claude_md = setup.by_type(ComponentType.CLAUDE_MD)
        coding = next(c for c in claude_md if c.name == "coding-standards")
        assert "PEP 8" in coding.content
        assert coding.token_count > 0

    def test_cursorrules_frontmatter_parsed(self) -> None:
        setup = discover_setup(name="cursor", path=str(FIXTURES_DIR / "sample-cursor-setup"))
        claude_md = setup.by_type(ComponentType.CLAUDE_MD)
        rules = next(c for c in claude_md if c.name == ".cursorrules")
        assert rules.frontmatter is not None
        assert rules.frontmatter.get("name") == "project-rules"


class TestCursorLinting:
    def test_lint_mdc_file(self) -> None:
        mdc_path = str(
            FIXTURES_DIR / "sample-cursor-setup" / ".cursor" / "rules" / "coding-standards.mdc"
        )
        result = lint_claude_md(mdc_path)
        assert result.target_name is not None

    def test_lint_cursor_hooks(self) -> None:
        hooks_path = str(FIXTURES_DIR / "sample-cursor-setup" / ".cursor" / "hooks.json")
        result = lint_hooks(hooks_path)
        assert result.error_count == 0

    def test_inspect_cursor_setup(self) -> None:
        setup = discover_setup(name="cursor", path=str(FIXTURES_DIR / "sample-cursor-setup"))
        results = inspect_setup(setup)
        assert len(results) > 0
        target_types = {r.target_type for r in results}
        assert "claude_md" in target_types
        assert "skill" in target_types

    def test_inspect_mixed_setup(self) -> None:
        setup = discover_setup(name="mixed", path=str(FIXTURES_DIR / "sample-mixed-setup"))
        results = inspect_setup(setup)
        assert len(results) > 0


class TestCursorSourceTool:
    def test_cursor_components_have_source_tool(self) -> None:
        setup = discover_setup(name="cursor", path=str(FIXTURES_DIR / "sample-cursor-setup"))
        for comp in setup.components:
            if ".cursor" in comp.path or ".cursorrules" in comp.path:
                assert comp.source_tool == "cursor", f"{comp.path} should have source_tool='cursor'"

    def test_mixed_setup_has_both_source_tools(self) -> None:
        setup = discover_setup(name="mixed", path=str(FIXTURES_DIR / "sample-mixed-setup"))
        claude_comps = [c for c in setup.components if c.source_tool == "claude"]
        cursor_comps = [c for c in setup.components if c.source_tool == "cursor"]
        assert len(claude_comps) > 0
        assert len(cursor_comps) > 0


class TestCursorBudget:
    def test_cursor_non_always_apply_is_on_demand(self) -> None:
        setup = discover_setup(name="cursor", path=str(FIXTURES_DIR / "sample-cursor-setup"))
        budget = analyze_budget(setup)
        assert budget.on_demand_tokens > 0

    def test_cursor_always_apply_is_always_loaded(self) -> None:
        setup = discover_setup(name="cursor", path=str(FIXTURES_DIR / "sample-cursor-setup"))
        budget = analyze_budget(setup)
        assert budget.always_loaded_tokens > 0


class TestCursorReport:
    def test_cursor_only_report_labels(self) -> None:
        setup = discover_setup(name="cursor", path=str(FIXTURES_DIR / "sample-cursor-setup"))
        system = analyze_system(setup)
        results = inspect_setup(setup)
        output = format_terminal(system, results)
        assert "Cursor Rules" in output

    def test_cursor_budget_label(self) -> None:
        setup = discover_setup(name="cursor", path=str(FIXTURES_DIR / "sample-cursor-setup"))
        system = analyze_system(setup)
        results = inspect_setup(setup)
        output = format_terminal(system, results)
        assert "cursor rules, hooks" in output


class TestDeduplication:
    def test_no_duplicate_components(self) -> None:
        setup = discover_setup(name="cursor", path=str(FIXTURES_DIR / "sample-cursor-setup"))
        paths = [c.path for c in setup.components]
        resolved = [str(Path(p).resolve()) for p in paths]
        assert len(resolved) == len(set(resolved))
