"""Tests for command/allowed-tools-coverage rule."""

from __future__ import annotations

from pathlib import Path

from harness_eval.inspection.engine import lint_command

RULE_ID = "command/allowed-tools-coverage"
RULE_CONFIG = {RULE_ID: "warning"}


def _write_command(tmp_path: Path, content: str, name: str = "test-cmd") -> str:
    cmd_dir = tmp_path / name
    cmd_dir.mkdir(parents=True, exist_ok=True)
    (cmd_dir / "command.md").write_text(content)
    return str(cmd_dir)


def _diags_for(result, rule_id: str = RULE_ID):
    return [d for d in result.diagnostics if d.rule_id == rule_id]


class TestUnderGrant:
    def test_flags_bash_not_in_allowed_tools(self, tmp_path: Path) -> None:
        path = _write_command(
            tmp_path,
            "---\nallowed-tools:\n  - Read\n---\n\n```bash\ngit status\n```\n",
        )
        result = lint_command(path, RULE_CONFIG)
        diags = _diags_for(result)
        assert len(diags) >= 1
        assert any("Bash" in d.message for d in diags)

    def test_flags_tool_directive_not_in_allowed_tools(self, tmp_path: Path) -> None:
        path = _write_command(
            tmp_path,
            "---\nallowed-tools:\n  - Bash\n---\n\nUse the WebFetch tool to check the URL.\n",
        )
        result = lint_command(path, RULE_CONFIG)
        diags = _diags_for(result)
        assert len(diags) >= 1
        assert any("WebFetch" in d.message for d in diags)


class TestOverGrant:
    def test_flags_broad_bash_with_single_command_prefix(self, tmp_path: Path) -> None:
        path = _write_command(
            tmp_path,
            "---\nallowed-tools:\n  - Bash\n---\n\n```bash\ngit status\ngit log\ngit diff\n```\n",
            name="git-cmd",
        )
        result = lint_command(path, RULE_CONFIG)
        diags = _diags_for(result)
        over = [d for d in diags if "narrow" in d.message]
        assert len(over) >= 1

    def test_no_over_grant_with_mixed_commands(self, tmp_path: Path) -> None:
        body = (
            "---\nallowed-tools:\n  - Bash\n---\n\n"
            "```bash\ngit status\nnpm install\npython run.py\n```\n"
        )
        path = _write_command(tmp_path, body, name="mixed-cmd")
        result = lint_command(path, RULE_CONFIG)
        diags = _diags_for(result)
        over = [d for d in diags if "narrow" in d.message]
        assert len(over) == 0


class TestNoFinding:
    def test_no_finding_without_allowed_tools(self, tmp_path: Path) -> None:
        path = _write_command(
            tmp_path,
            "---\ndescription: A command\n---\n\nUse the WebFetch tool.\n",
            name="no-at",
        )
        result = lint_command(path, RULE_CONFIG)
        diags = _diags_for(result)
        assert len(diags) == 0

    def test_no_under_grant_when_covered(self, tmp_path: Path) -> None:
        path = _write_command(
            tmp_path,
            "---\nallowed-tools:\n  - Bash\n  - Read\n---\n\n```bash\nls -la\n```\n",
            name="covered-cmd",
        )
        result = lint_command(path, RULE_CONFIG)
        diags = _diags_for(result)
        under = [d for d in diags if "does not grant" in d.message]
        assert len(under) == 0

    def test_bash_prefix_grant_covers_bash(self, tmp_path: Path) -> None:
        path = _write_command(
            tmp_path,
            '---\nallowed-tools:\n  - "Bash(git:*)"\n---\n\n```bash\ngit status\n```\n',
            name="prefix-cmd",
        )
        result = lint_command(path, RULE_CONFIG)
        diags = _diags_for(result)
        under = [d for d in diags if "does not grant" in d.message]
        assert len(under) == 0
