"""Tests for content/undeclared-env-var rule."""

from __future__ import annotations

from pathlib import Path

from harness_eval.inspection.engine import lint

RULE_CONFIG = {"content/undeclared-env-var": "warning"}


def _make_skill(tmp_path: Path, name: str, body: str, script: str | None = None) -> str:
    # Create .git to mark project root
    (tmp_path / ".git").mkdir(exist_ok=True)

    skill_dir = tmp_path / "skills" / name
    skill_dir.mkdir(parents=True, exist_ok=True)
    (skill_dir / "SKILL.md").write_text(
        f"---\nname: {name}\ndescription: Test skill\n---\n\n{body}"
    )
    if script:
        (skill_dir / "run.sh").write_text(script)
    return str(skill_dir)


class TestUndeclaredEnvVar:
    def test_flags_undeclared_shell_var(self, tmp_path: Path) -> None:
        body = '```bash\ncurl -H "Authorization: $MY_CUSTOM_TOKEN" https://api.example.com\n```'
        path = _make_skill(tmp_path, "shell-var", body)
        result = lint(path, RULE_CONFIG)
        diags = [d for d in result.diagnostics if d.rule_id == "content/undeclared-env-var"]
        assert len(diags) >= 1
        assert any("MY_CUSTOM_TOKEN" in d.message for d in diags)

    def test_skips_standard_vars(self, tmp_path: Path) -> None:
        body = "```bash\necho $HOME $PATH $USER\n```"
        path = _make_skill(tmp_path, "std-var", body)
        result = lint(path, RULE_CONFIG)
        diags = [d for d in result.diagnostics if d.rule_id == "content/undeclared-env-var"]
        assert len(diags) == 0

    def test_skips_github_vars(self, tmp_path: Path) -> None:
        body = "```bash\necho $GITHUB_WORKSPACE $GITHUB_TOKEN\n```"
        path = _make_skill(tmp_path, "gh-var", body)
        result = lint(path, RULE_CONFIG)
        diags = [d for d in result.diagnostics if d.rule_id == "content/undeclared-env-var"]
        assert len(diags) == 0

    def test_skips_provider_keys(self, tmp_path: Path) -> None:
        body = "```bash\nexport KEY=$ANTHROPIC_API_KEY\n```"
        path = _make_skill(tmp_path, "provider-key", body)
        result = lint(path, RULE_CONFIG)
        diags = [d for d in result.diagnostics if d.rule_id == "content/undeclared-env-var"]
        assert len(diags) == 0

    def test_skips_var_with_default(self, tmp_path: Path) -> None:
        body = '```bash\nVAL="${MY_CUSTOM_VAR:-default_value}"\n```'
        path = _make_skill(tmp_path, "default-var", body)
        result = lint(path, RULE_CONFIG)
        diags = [d for d in result.diagnostics if d.rule_id == "content/undeclared-env-var"]
        assert len(diags) == 0

    def test_skips_documented_var(self, tmp_path: Path) -> None:
        (tmp_path / ".git").mkdir(exist_ok=True)
        (tmp_path / "CLAUDE.md").write_text("Set MY_CUSTOM_TOKEN to your API token before running.")
        body = '```bash\ncurl -H "$MY_CUSTOM_TOKEN" https://api.example.com\n```'
        skill_dir = tmp_path / "skills" / "doc-var"
        skill_dir.mkdir(parents=True)
        (skill_dir / "SKILL.md").write_text(f"---\nname: doc-var\ndescription: Test\n---\n\n{body}")
        result = lint(str(skill_dir), RULE_CONFIG)
        diags = [d for d in result.diagnostics if d.rule_id == "content/undeclared-env-var"]
        assert len(diags) == 0

    def test_flags_python_environ(self, tmp_path: Path) -> None:
        body = "The script reads the config."
        script = 'import os\nval = os.environ["SPECIAL_CONFIG"]\n'
        path = _make_skill(tmp_path, "py-env", body, script=script)
        result = lint(path, RULE_CONFIG)
        diags = [d for d in result.diagnostics if d.rule_id == "content/undeclared-env-var"]
        assert len(diags) >= 1
        assert any("SPECIAL_CONFIG" in d.message for d in diags)
