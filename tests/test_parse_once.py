"""Parse-once: lint_* reuse a Parsed* object and parsers accept discovery file paths."""

from __future__ import annotations

from pathlib import Path

from harness_eval.inspection.engine import lint, lint_command
from harness_eval.inspection.parsers import parse_command
from harness_eval.inspection.types import ParsedSkill


def test_lint_skips_disk_when_parsed_is_passed(tmp_path: Path) -> None:
    """A pre-parsed skill is used even if the path does not exist on disk."""
    parsed = ParsedSkill(
        dir_path=str(tmp_path / "ghost"),
        dir_name="ghost",
        skill_md_path=str(tmp_path / "ghost" / "SKILL.md"),
        raw_content=(
            "---\nname: ghost\ndescription: A ghost skill for parse-once tests.\n---\n\nBody.\n"
        ),
        frontmatter={"name": "ghost", "description": "A ghost skill for parse-once tests."},
        raw_frontmatter="name: ghost\ndescription: A ghost skill for parse-once tests.\n",
        frontmatter_start_line=1,
        body="Body.\n",
        body_start_line=4,
        files=["SKILL.md"],
        tokens=20,
    )
    result = lint("/does/not/exist", parsed=parsed)
    assert result.target_name == "ghost"
    assert result.target_type == "skill"


def test_parse_command_file_path_matches_directory(tmp_path: Path) -> None:
    """Discovery stores command.md; the parser accepts that file or its directory."""
    cmd_dir = tmp_path / "review"
    cmd_dir.mkdir()
    (cmd_dir / "command.md").write_text("---\ndescription: Review the change\n---\n\nRun tests.\n")
    from_file = parse_command(str(cmd_dir / "command.md"))
    from_dir = parse_command(str(cmd_dir))
    assert from_file.dir_name == from_dir.dir_name == "review"
    assert from_file.command_md_path == from_dir.command_md_path
    assert from_file.body == from_dir.body


def test_lint_command_accepts_preparsed(tmp_path: Path) -> None:
    cmd_dir = tmp_path / "ship"
    cmd_dir.mkdir()
    (cmd_dir / "command.md").write_text("---\ndescription: Ship it\n---\n\nDeploy.\n")
    parsed = parse_command(str(cmd_dir / "command.md"))
    result = lint_command("/does/not/exist", parsed=parsed)
    assert result.target_name == "ship"
    assert result.target_type == "command"
