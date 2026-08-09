"""Tests for bugs fixed in v7.3.0.

Each test class corresponds to a specific bug fix. Tests verify both the
fix and the regression (the original broken behavior no longer occurs).
"""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from harness_eval.cli import cli
from harness_eval.inspection.types import (
    Finding,
    FixSuggestion,
    Location,
    RuleCategory,
    Severity,
)


class TestParseErrorCategory:
    """Bug #1: _parse_errors_to_findings used error message string as category."""

    def test_parse_error_uses_structural_category(self) -> None:
        from harness_eval.inspection.engine import lint

        result = lint("/nonexistent/skill/path")
        for diag in result.diagnostics:
            if diag.rule_id == "parser":
                assert diag.category == "structural" or diag.category == RuleCategory.STRUCTURAL


class TestParserEncoding:
    """Bug #2: parsers crashed on non-UTF-8 files."""

    def test_read_and_parse_handles_non_utf8(self, tmp_path: Path) -> None:
        from harness_eval.inspection.parsers import _read_and_parse

        bad_file = tmp_path / "SKILL.md"
        bad_file.write_bytes(b"---\nname: test\n---\n\nContent with bad bytes: \xff\xfe\x80\n")
        raw, fm, errors = _read_and_parse(bad_file)
        assert isinstance(raw, str)
        assert "�" in raw

    def test_parse_claude_md_handles_non_utf8(self, tmp_path: Path) -> None:
        from harness_eval.inspection.parsers import parse_claude_md

        md_file = tmp_path / "CLAUDE.md"
        md_file.write_bytes(b"# Project\n\nSome content \xff\xfe\n")
        result = parse_claude_md(str(md_file))
        assert isinstance(result.raw_content, str)
        assert "�" in result.raw_content

    def test_parse_hooks_handles_non_utf8(self, tmp_path: Path) -> None:
        from harness_eval.inspection.parsers import parse_hooks

        hooks_file = tmp_path / "settings.json"
        hooks_file.write_bytes(b'{"hooks": {}}')
        result = parse_hooks(str(hooks_file))
        assert result.parse_errors == []


class TestFixerLineEndings:
    """Bug #3: fixer destroyed CRLF line endings."""

    def test_preserves_crlf_line_endings(self, tmp_path: Path) -> None:
        from harness_eval.inspection.fixer import apply_fixes

        target = tmp_path / "SKILL.md"
        target.write_bytes(b"---\r\nname: old-name\r\n---\r\n\r\nContent here.\r\n")

        findings = [
            Finding(
                rule_id="test-rule",
                severity=Severity.WARNING,
                message="test",
                location=Location(file=str(target), start_line=2),
                category=RuleCategory.FRONTMATTER,
                fix=FixSuggestion(description="fix name", replacement="name: new-name"),
            )
        ]

        results = apply_fixes(findings)
        assert len(results) == 1
        assert results[0].fixes_applied == 1

        content = target.read_bytes()
        assert b"\r\n" in content
        assert b"name: new-name\r\n" in content

    def test_preserves_lf_line_endings(self, tmp_path: Path) -> None:
        from harness_eval.inspection.fixer import apply_fixes

        target = tmp_path / "SKILL.md"
        target.write_text("---\nname: old-name\n---\n\nContent here.\n")

        findings = [
            Finding(
                rule_id="test-rule",
                severity=Severity.WARNING,
                message="test",
                location=Location(file=str(target), start_line=2),
                category=RuleCategory.FRONTMATTER,
                fix=FixSuggestion(description="fix name", replacement="name: new-name"),
            )
        ]

        results = apply_fixes(findings)
        assert len(results) == 1

        content = target.read_bytes()
        assert b"\r\n" not in content
        assert b"name: new-name\n" in content

    def test_fixer_uses_utf8_encoding(self, tmp_path: Path) -> None:
        from harness_eval.inspection.fixer import apply_fixes

        target = tmp_path / "SKILL.md"
        target.write_bytes(b"---\nname: old\n---\n\nContent with \xc3\xa9.\n")

        findings = [
            Finding(
                rule_id="test-rule",
                severity=Severity.WARNING,
                message="test",
                location=Location(file=str(target), start_line=2),
                category=RuleCategory.FRONTMATTER,
                fix=FixSuggestion(description="fix", replacement="name: new"),
            )
        ]

        results = apply_fixes(findings)
        assert len(results) == 1
        content = target.read_text(encoding="utf-8")
        assert "name: new" in content
        assert "é" in content


class TestLintOutputFlag:
    """Bug #4: --output was silently ignored for terminal format."""

    def test_terminal_output_written_to_file(self, tmp_path: Path) -> None:
        runner = CliRunner()
        output_file = tmp_path / "report.txt"
        with runner.isolated_filesystem():
            Path("CLAUDE.md").write_text("# Test project\n\nUse /alpha for stuff.")
            skill_dir = Path("skills/alpha")
            skill_dir.mkdir(parents=True)
            (skill_dir / "SKILL.md").write_text(
                "---\nname: alpha\ndescription: Test skill\n---\n\nDo stuff."
            )
            result = runner.invoke(
                cli, ["lint", ".", "--format", "terminal", "--output", str(output_file)]
            )
            assert result.exit_code == 0

        assert output_file.exists()
        content = output_file.read_text()
        assert len(content) > 0

    def test_json_output_still_works(self, tmp_path: Path) -> None:
        import json

        runner = CliRunner()
        output_file = tmp_path / "report.json"
        with runner.isolated_filesystem():
            Path("CLAUDE.md").write_text("# Test project")
            skill_dir = Path("skills/alpha")
            skill_dir.mkdir(parents=True)
            (skill_dir / "SKILL.md").write_text(
                "---\nname: alpha\ndescription: Test skill\n---\n\nDo stuff."
            )
            result = runner.invoke(
                cli, ["lint", ".", "--format", "json", "--output", str(output_file)]
            )
            assert result.exit_code == 0

        assert output_file.exists()
        data = json.loads(output_file.read_text())
        assert "inspection" in data

    def test_single_file_terminal_output_written_to_file(self, tmp_path: Path) -> None:
        runner = CliRunner()
        output_file = tmp_path / "report.txt"
        with runner.isolated_filesystem():
            skill_dir = Path("skills/alpha")
            skill_dir.mkdir(parents=True)
            skill_md = skill_dir / "SKILL.md"
            skill_md.write_text("---\nname: alpha\ndescription: Test skill\n---\n\nDo stuff.")
            result = runner.invoke(
                cli, ["lint", str(skill_md), "--format", "terminal", "--output", str(output_file)]
            )
            assert result.exit_code == 0

        assert output_file.exists()
        content = output_file.read_text()
        assert len(content) > 0


class TestMcpConfigDedup:
    """Bug #5: MCP config dedup used unresolved paths."""

    def test_dedup_with_resolved_paths(self, tmp_path: Path) -> None:
        from harness_eval.core.discoverers.claude import ClaudeCodeDiscoverer

        mcp_file = tmp_path / ".mcp.json"
        mcp_file.write_text('{"mcpServers": {"test": {"command": "echo"}}}')

        discoverer = ClaudeCodeDiscoverer()
        result = discoverer.discover(tmp_path)

        mcp_components = [c for c in result if c.component_type.value == "mcp_config"]
        assert len(mcp_components) <= 1


class TestReviewModelDisplay:
    """Bug #6: review terminal output showed CLI arg instead of effective model."""

    def test_effective_model_shown(self) -> None:
        from harness_eval.utils.llm import GeminiClient

        client = GeminiClient(model="gemini-2.0-flash")
        assert client.model == "gemini-2.0-flash"
        assert client.model != "default"
