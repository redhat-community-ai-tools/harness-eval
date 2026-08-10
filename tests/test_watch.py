"""Tests for watch mode functionality."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from harness_eval.cli import cli
from harness_eval.core.setup import collect_setup_file_paths
from harness_eval.watch import (
    _build_filter,
    _get_watch_directories,
    run_watch,
)


class TestCollectSetupFilePaths:
    def test_finds_claude_md(self, tmp_path: Path) -> None:
        claude_md = tmp_path / "CLAUDE.md"
        claude_md.write_text("# Instructions")

        paths = collect_setup_file_paths(tmp_path)
        resolved = [str(p.resolve()) for p in paths]
        assert str(claude_md.resolve()) in resolved

    def test_finds_skills(self, tmp_path: Path) -> None:
        skill_dir = tmp_path / "skills" / "my-skill"
        skill_dir.mkdir(parents=True)
        skill_md = skill_dir / "SKILL.md"
        skill_md.write_text("---\nname: my-skill\n---\nBody")

        paths = collect_setup_file_paths(tmp_path)
        resolved = [str(p.resolve()) for p in paths]
        assert str(skill_md.resolve()) in resolved

    def test_finds_settings_json(self, tmp_path: Path) -> None:
        claude_dir = tmp_path / ".claude"
        claude_dir.mkdir()
        settings = claude_dir / "settings.json"
        settings.write_text("{}")

        paths = collect_setup_file_paths(tmp_path)
        resolved = [str(p.resolve()) for p in paths]
        assert str(settings.resolve()) in resolved

    def test_finds_agents(self, tmp_path: Path) -> None:
        agents_dir = tmp_path / ".claude" / "agents"
        agents_dir.mkdir(parents=True)
        agent_md = agents_dir / "reviewer.md"
        agent_md.write_text("# Reviewer agent")

        paths = collect_setup_file_paths(tmp_path)
        resolved = [str(p.resolve()) for p in paths]
        assert str(agent_md.resolve()) in resolved

    def test_finds_mcp_config(self, tmp_path: Path) -> None:
        mcp = tmp_path / ".mcp.json"
        mcp.write_text("{}")

        paths = collect_setup_file_paths(tmp_path)
        resolved = [str(p.resolve()) for p in paths]
        assert str(mcp.resolve()) in resolved

    def test_finds_commands(self, tmp_path: Path) -> None:
        cmd_dir = tmp_path / "commands"
        cmd_dir.mkdir()
        cmd_md = cmd_dir / "review.md"
        cmd_md.write_text("# Review command")

        paths = collect_setup_file_paths(tmp_path)
        resolved = [str(p.resolve()) for p in paths]
        assert str(cmd_md.resolve()) in resolved

    def test_finds_subdir_commands(self, tmp_path: Path) -> None:
        cmd_dir = tmp_path / "commands" / "my-cmd"
        cmd_dir.mkdir(parents=True)
        cmd_md = cmd_dir / "command.md"
        cmd_md.write_text("# My command")

        paths = collect_setup_file_paths(tmp_path)
        resolved = [str(p.resolve()) for p in paths]
        assert str(cmd_md.resolve()) in resolved

    def test_deduplicates_paths(self, tmp_path: Path) -> None:
        claude_md = tmp_path / "CLAUDE.md"
        claude_md.write_text("# Instructions")

        paths = collect_setup_file_paths(tmp_path)
        resolved = [str(p.resolve()) for p in paths]
        # Each path should appear only once
        assert len(resolved) == len(set(resolved))

    def test_finds_rules(self, tmp_path: Path) -> None:
        rules_dir = tmp_path / ".claude" / "rules"
        rules_dir.mkdir(parents=True)
        rule_md = rules_dir / "my-rule.md"
        rule_md.write_text("# Rule")

        paths = collect_setup_file_paths(tmp_path)
        resolved = [str(p.resolve()) for p in paths]
        assert str(rule_md.resolve()) in resolved

    def test_finds_output_styles(self, tmp_path: Path) -> None:
        styles_dir = tmp_path / ".claude" / "output-styles"
        styles_dir.mkdir(parents=True)
        style_md = styles_dir / "concise.md"
        style_md.write_text("# Style")

        paths = collect_setup_file_paths(tmp_path)
        resolved = [str(p.resolve()) for p in paths]
        assert str(style_md.resolve()) in resolved

    def test_finds_cursor_skills(self, tmp_path: Path) -> None:
        skill_dir = tmp_path / ".cursor" / "skills" / "my-skill"
        skill_dir.mkdir(parents=True)
        skill_md = skill_dir / "SKILL.md"
        skill_md.write_text("---\nname: test\n---\nBody")

        paths = collect_setup_file_paths(tmp_path)
        resolved = [str(p.resolve()) for p in paths]
        assert str(skill_md.resolve()) in resolved

    def test_finds_cursor_hooks(self, tmp_path: Path) -> None:
        cursor_dir = tmp_path / ".cursor"
        cursor_dir.mkdir(exist_ok=True)
        hooks = cursor_dir / "hooks.json"
        hooks.write_text("{}")

        paths = collect_setup_file_paths(tmp_path)
        resolved = [str(p.resolve()) for p in paths]
        assert str(hooks.resolve()) in resolved

    def test_finds_cursor_mcp(self, tmp_path: Path) -> None:
        cursor_dir = tmp_path / ".cursor"
        cursor_dir.mkdir(exist_ok=True)
        mcp = cursor_dir / "mcp.json"
        mcp.write_text("{}")

        paths = collect_setup_file_paths(tmp_path)
        resolved = [str(p.resolve()) for p in paths]
        assert str(mcp.resolve()) in resolved

    def test_empty_directory(self, tmp_path: Path) -> None:
        paths = collect_setup_file_paths(tmp_path)
        assert paths == []

    def test_finds_user_global_claude_md(self, tmp_path: Path) -> None:
        """User-global CLAUDE.md is included when user_config_dir is provided."""
        user_dir = tmp_path / "user-config"
        user_dir.mkdir()
        user_claude = user_dir / "CLAUDE.md"
        user_claude.write_text("# User global config")

        project_root = tmp_path / "project"
        project_root.mkdir()

        paths = collect_setup_file_paths(project_root, user_config_dir=user_dir)
        resolved = [str(p.resolve()) for p in paths]
        assert str(user_claude.resolve()) in resolved

    def test_finds_user_project_claude_md(self, tmp_path: Path) -> None:
        """User-project CLAUDE.md is included when user_config_dir is provided."""
        user_dir = tmp_path / "user-config"
        project_dir = user_dir / "projects" / "my-project"
        project_dir.mkdir(parents=True)
        project_claude = project_dir / "CLAUDE.md"
        project_claude.write_text("# User project config")

        project_root = tmp_path / "project"
        project_root.mkdir()

        paths = collect_setup_file_paths(project_root, user_config_dir=user_dir)
        resolved = [str(p.resolve()) for p in paths]
        assert str(project_claude.resolve()) in resolved


class TestBuildFilter:
    def test_accepts_watched_file(self, tmp_path: Path) -> None:
        watched = tmp_path / "CLAUDE.md"
        watched.write_text("# Test")
        filt = _build_filter([watched])
        # watchfiles passes (Change, str) tuples; Change is an enum but
        # _build_filter only uses the path, so we can pass any value.
        assert filt("modified", str(watched.resolve())) is True

    def test_rejects_unwatched_file(self, tmp_path: Path) -> None:
        watched = tmp_path / "CLAUDE.md"
        watched.write_text("# Test")
        other = tmp_path / "README.md"
        other.write_text("# Other")
        filt = _build_filter([watched])
        assert filt("modified", str(other.resolve())) is False

    def test_empty_watch_list(self, tmp_path: Path) -> None:
        filt = _build_filter([])
        assert filt("modified", str(tmp_path / "anything.md")) is False


class TestGetWatchDirectories:
    def test_returns_parent_dirs(self, tmp_path: Path) -> None:
        paths = [
            tmp_path / "CLAUDE.md",
            tmp_path / "skills" / "foo" / "SKILL.md",
        ]
        dirs = _get_watch_directories(paths)
        assert tmp_path in dirs
        assert tmp_path / "skills" / "foo" in dirs


class TestCLIWatchFlag:
    def test_cli_accepts_watch_flag(self) -> None:
        """The --watch flag is accepted by lint without error."""
        runner = CliRunner()
        with runner.isolated_filesystem():
            Path("CLAUDE.md").write_text("# Test")
            # Mock run_watch to avoid actually starting the watcher
            with patch("harness_eval.watch.run_watch") as mock_watch:
                result = runner.invoke(cli, ["harness-lint", ".", "--watch"])
                assert result.exit_code == 0
                mock_watch.assert_called_once()

    def test_watch_flag_passes_options(self) -> None:
        """The --watch flag forwards preset and format options."""
        runner = CliRunner()
        with runner.isolated_filesystem():
            Path("CLAUDE.md").write_text("# Test")
            with patch("harness_eval.watch.run_watch") as mock_watch:
                result = runner.invoke(
                    cli,
                    ["harness-lint", ".", "--watch", "--preset", "strict"],
                )
                assert result.exit_code == 0
                mock_watch.assert_called_once_with(
                    path=".",
                    preset="strict",
                    fmt="terminal",
                    user_config=None,
                    recursive=False,
                )


class TestCLIWatchWithIncompatibleFlags:
    def test_watch_with_fix_warns(self) -> None:
        """Using --watch with --fix prints a warning."""
        runner = CliRunner()
        with runner.isolated_filesystem():
            Path("CLAUDE.md").write_text("# Test")
            with patch("harness_eval.watch.run_watch"):
                result = runner.invoke(
                    cli,
                    ["harness-lint", ".", "--watch", "--fix"],
                )
                assert result.exit_code == 0
                assert (
                    "--fix is ignored in watch mode" in result.output
                    or "--fix is ignored in watch mode" in (result.stderr or "")
                )

    def test_watch_with_fail_on_error_warns(self) -> None:
        """Using --watch with --fail-on-error prints a warning."""
        runner = CliRunner()
        with runner.isolated_filesystem():
            Path("CLAUDE.md").write_text("# Test")
            with patch("harness_eval.watch.run_watch"):
                result = runner.invoke(
                    cli,
                    ["harness-lint", ".", "--watch", "--fail-on-error"],
                )
                assert result.exit_code == 0
                assert (
                    "--fail-on-error is ignored in watch mode" in result.output
                    or "--fail-on-error is ignored in watch mode" in (result.stderr or "")
                )


class TestRunWatch:
    def test_raises_without_watchfiles(self, tmp_path: Path) -> None:
        """run_watch raises ClickException when watchfiles is not installed."""
        import click

        (tmp_path / "CLAUDE.md").write_text("# Test")
        with (
            patch.dict("sys.modules", {"watchfiles": None}),
            pytest.raises(click.exceptions.ClickException, match="watchfiles"),
        ):
            run_watch(
                path=str(tmp_path),
                preset="recommended",
                fmt="terminal",
                user_config=None,
            )

    def test_raises_on_empty_directory(self, tmp_path: Path) -> None:
        """run_watch raises ClickException when no setup files are found."""
        import types

        import click

        fake_watchfiles = types.ModuleType("watchfiles")
        fake_watchfiles.watch = lambda *a, **kw: iter([])  # type: ignore[attr-defined]

        with (
            patch.dict("sys.modules", {"watchfiles": fake_watchfiles}),
            pytest.raises(click.exceptions.ClickException, match="No agent setup files found"),
        ):
            run_watch(
                path=str(tmp_path),
                preset="recommended",
                fmt="terminal",
                user_config=None,
            )

    def test_raises_on_file_path(self, tmp_path: Path) -> None:
        """run_watch raises ClickException when given a file instead of a directory."""
        import click

        f = tmp_path / "CLAUDE.md"
        f.write_text("# Test")
        with pytest.raises(click.exceptions.ClickException, match="not a directory"):
            run_watch(
                path=str(f),
                preset="recommended",
                fmt="terminal",
                user_config=None,
            )
