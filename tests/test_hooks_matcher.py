"""Tests for hooks/matcher-matches-no-tool rule."""

from __future__ import annotations

import json
from pathlib import Path

from harness_eval.inspection.engine import lint_hooks

RULE_CONFIG = {"hooks/matcher-matches-no-tool": "warning"}


def _make_hooks_settings(tmp_path: Path, hooks_list: list[dict]) -> str:
    settings_dir = tmp_path / ".claude"
    settings_dir.mkdir(parents=True, exist_ok=True)
    settings_path = settings_dir / "settings.json"
    # Convert list of {matcher, ...} to the hooks format
    hooks_config = {"PreToolUse": []}
    for hook in hooks_list:
        hooks_config["PreToolUse"].append(
            {
                "matcher": hook.get("matcher", ""),
                "hooks": [{"type": "command", "command": "echo test"}],
            }
        )
    settings_path.write_text(json.dumps({"hooks": hooks_config}))
    return str(settings_path)


class TestHooksMatcherMatchesNoTool:
    def test_flags_case_mismatch(self, tmp_path: Path) -> None:
        path = _make_hooks_settings(tmp_path, [{"matcher": "bash"}])
        result = lint_hooks(path, RULE_CONFIG)
        diags = [d for d in result.diagnostics if d.rule_id == "hooks/matcher-matches-no-tool"]
        assert len(diags) == 1
        assert "case-sensitive" in diags[0].message
        assert "Bash" in diags[0].message

    def test_flags_nonexistent_tool(self, tmp_path: Path) -> None:
        path = _make_hooks_settings(tmp_path, [{"matcher": "NonexistentTool"}])
        result = lint_hooks(path, RULE_CONFIG)
        diags = [d for d in result.diagnostics if d.rule_id == "hooks/matcher-matches-no-tool"]
        assert len(diags) == 1
        assert "never fire" in diags[0].message

    def test_flags_invalid_regex(self, tmp_path: Path) -> None:
        path = _make_hooks_settings(tmp_path, [{"matcher": "[invalid"}])
        result = lint_hooks(path, RULE_CONFIG)
        diags = [d for d in result.diagnostics if d.rule_id == "hooks/matcher-matches-no-tool"]
        assert len(diags) == 1
        assert "not a valid regex" in diags[0].message

    def test_skips_valid_matcher(self, tmp_path: Path) -> None:
        path = _make_hooks_settings(tmp_path, [{"matcher": "Bash"}])
        result = lint_hooks(path, RULE_CONFIG)
        diags = [d for d in result.diagnostics if d.rule_id == "hooks/matcher-matches-no-tool"]
        assert len(diags) == 0

    def test_skips_wildcard(self, tmp_path: Path) -> None:
        path = _make_hooks_settings(tmp_path, [{"matcher": "*"}])
        result = lint_hooks(path, RULE_CONFIG)
        diags = [d for d in result.diagnostics if d.rule_id == "hooks/matcher-matches-no-tool"]
        assert len(diags) == 0

    def test_skips_mcp_pattern(self, tmp_path: Path) -> None:
        path = _make_hooks_settings(tmp_path, [{"matcher": "mcp__.*"}])
        result = lint_hooks(path, RULE_CONFIG)
        diags = [d for d in result.diagnostics if d.rule_id == "hooks/matcher-matches-no-tool"]
        assert len(diags) == 0

    def test_skips_empty_string(self, tmp_path: Path) -> None:
        path = _make_hooks_settings(tmp_path, [{"matcher": ""}])
        result = lint_hooks(path, RULE_CONFIG)
        diags = [d for d in result.diagnostics if d.rule_id == "hooks/matcher-matches-no-tool"]
        assert len(diags) == 0
