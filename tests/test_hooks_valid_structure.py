"""Tests for hooks/valid-structure rule."""

from __future__ import annotations

import json
from pathlib import Path

from harness_eval.inspection.engine import lint_hooks

RULE_ID = "hooks/valid-structure"
RULE_CONFIG = {RULE_ID: "warning"}


def _write_settings(tmp_path: Path, settings: dict) -> str:
    path = tmp_path / "settings.json"
    path.write_text(json.dumps(settings))
    return str(path)


class TestHooksValidStructure:
    def test_flags_missing_command(self, tmp_path: Path) -> None:
        """A hook entry with no command is ignored by the runtime."""
        path = _write_settings(tmp_path, {"hooks": {"PreToolUse": [{"matcher": "Bash"}]}})
        result = lint_hooks(path, RULE_CONFIG)
        diags = [d for d in result.diagnostics if d.rule_id == RULE_ID]
        assert len(diags) == 1
        assert "no command" in diags[0].message.lower()

    def test_flags_empty_command(self, tmp_path: Path) -> None:
        path = _write_settings(tmp_path, {"hooks": {"Stop": [{"command": ""}]}})
        result = lint_hooks(path, RULE_CONFIG)
        diags = [d for d in result.diagnostics if d.rule_id == RULE_ID]
        assert len(diags) == 1

    def test_clean_hook_passes(self, tmp_path: Path) -> None:
        """Simple echo command should not flag."""
        path = _write_settings(
            tmp_path,
            {"hooks": {"PostToolUse": [{"hooks": [{"type": "command", "command": "echo done"}]}]}},
        )
        result = lint_hooks(path, RULE_CONFIG)
        diags = [d for d in result.diagnostics if d.rule_id == RULE_ID]
        assert len(diags) == 0

    def test_dangerous_command_not_flagged_here(self, tmp_path: Path) -> None:
        """rm -rf belongs to hooks/dangerous-command, not this rule."""
        path = _write_settings(
            tmp_path,
            {
                "hooks": {
                    "PreToolUse": [{"hooks": [{"type": "command", "command": "rm -rf /tmp/build"}]}]
                }
            },
        )
        result = lint_hooks(path, RULE_CONFIG)
        diags = [d for d in result.diagnostics if d.rule_id == RULE_ID]
        assert len(diags) == 0

    def test_missing_script_not_flagged_here(self, tmp_path: Path) -> None:
        """Missing script paths are owned by hooks/command-script-exists, not this rule."""
        claude_dir = tmp_path / ".claude"
        claude_dir.mkdir()
        settings = {
            "hooks": {
                "PreToolUse": [
                    {"hooks": [{"type": "command", "command": "scripts/check.py --strict"}]}
                ]
            }
        }
        settings_path = claude_dir / "settings.json"
        settings_path.write_text(json.dumps(settings))
        result = lint_hooks(str(settings_path), RULE_CONFIG)
        diags = [d for d in result.diagnostics if d.rule_id == RULE_ID]
        assert not any("does not exist" in d.message for d in diags)
