"""Tests for the configuration-integrity rules."""

from __future__ import annotations

import json
import os
from pathlib import Path

from harness_eval.inspection.engine import lint, lint_claude_md, lint_hooks, lint_mcp_config
from harness_eval.inspection.rules._config_fs import find_duplicate_keys
from harness_eval.inspection.rules.claude_md.include_exists import imports_in
from harness_eval.inspection.rules.hooks.command_script_exists import script_paths


def _ids(result, rule):
    return [d for d in result.diagnostics if d.rule_id == rule]


def test_duplicate_keys_helper():
    assert sorted(find_duplicate_keys('{"a":1,"a":2,"b":{"c":1,"c":2}}')) == ["a", "c"]
    assert find_duplicate_keys('{"a":1}') == []
    assert find_duplicate_keys("{bad") == []


def test_mcp_duplicate_keys(tmp_path: Path):
    (tmp_path / "CLAUDE.md").write_text("# p")
    p = tmp_path / ".mcp.json"
    p.write_text('{"mcpServers":{"gh":{"command":"a"},"gh":{"command":"b"}}}')
    assert (
        len(
            _ids(
                lint_mcp_config(str(p), {"mcp/json-duplicate-keys": "error"}),
                "mcp/json-duplicate-keys",
            )
        )
        == 1
    )


def test_settings_duplicate_keys(tmp_path: Path):
    d = tmp_path / ".claude"
    d.mkdir()
    p = d / "settings.json"
    p.write_text('{"permissions":{"allow":[]},"permissions":{"deny":[]}}')
    assert (
        len(
            _ids(
                lint_hooks(str(p), {"hooks/json-duplicate-keys": "error"}),
                "hooks/json-duplicate-keys",
            )
        )
        == 1
    )


def test_imports_in():
    assert imports_in(
        "@docs/a.md and @README.md, mail me@x.com\n```\n@decorator\n```\n@handle"
    ) == ["docs/a.md", "README.md"]


def test_include_exists(tmp_path: Path):
    (tmp_path / "README.md").write_text("r")
    p = tmp_path / "CLAUDE.md"
    p.write_text("@README.md\n@docs/missing.md\n@~/private.md\n")
    d = _ids(
        lint_claude_md(str(p), {"claude-md/include-exists": "error"}), "claude-md/include-exists"
    )
    assert len(d) == 1 and "docs/missing.md" in d[0].message


def test_script_paths():
    assert script_paths('uv run "$CLAUDE_PROJECT_DIR/.ai/start.py" --x') == [
        "$CLAUDE_PROJECT_DIR/.ai/start.py"
    ]
    assert script_paths("./scripts/lint.sh && echo ok") == ["./scripts/lint.sh"]
    assert script_paths("python /usr/bin/tool.py") == []
    assert script_paths("npm test") == []


def test_command_script_exists(tmp_path: Path):
    d = tmp_path / ".claude"
    d.mkdir()
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts" / "ok.sh").write_text("#!/bin/sh")
    p = d / "settings.json"
    p.write_text(
        json.dumps(
            {
                "hooks": {
                    "PreToolUse": [
                        {
                            "matcher": "Bash",
                            "hooks": [
                                {"type": "command", "command": "./scripts/ok.sh"},
                                {"type": "command", "command": "./scripts/gone.sh"},
                            ],
                        }
                    ]
                }
            }
        )
    )
    d2 = _ids(
        lint_hooks(str(p), {"hooks/command-script-exists": "error"}), "hooks/command-script-exists"
    )
    assert len(d2) == 1 and "gone.sh" in d2[0].message


def test_endpoint_integrity(tmp_path: Path):
    (tmp_path / "CLAUDE.md").write_text("# p")
    p = tmp_path / ".mcp.json"
    p.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "local": {"command": "./server.py"},
                    "loop": {"url": "http://localhost:3000/sse"},
                    "remote": {"url": "http://evil.example/sse"},
                    "creds": {"url": "https://user:tok@host.example/mcp"},
                    "fine": {"url": "https://host.example/mcp"},
                }
            }
        )
    )
    d = _ids(lint_mcp_config(str(p), {"mcp/endpoint-integrity": "error"}), "mcp/endpoint-integrity")
    msgs = " ".join(x.message for x in d)
    assert (
        len(d) == 3
        and "local" in msgs
        and "remote" in msgs
        and "creds" in msgs
        and "'loop'" not in msgs
    )


def _skill(tmp_path: Path) -> Path:
    (tmp_path / ".git").mkdir()
    sd = tmp_path / ".claude" / "skills" / "s1"
    sd.mkdir(parents=True)
    (sd / "SKILL.md").write_text("---\nname: s1\ndescription: x. Use when y.\n---\nbody\n")
    return sd


def test_credential_file_present(tmp_path: Path):
    sd = _skill(tmp_path)
    (sd / ".env").write_text("A=1")
    (sd / ".env.example").write_text("A=")
    (sd / "k.pem").write_text("x")
    d = _ids(
        lint(str(sd / "SKILL.md"), {"security/credential-file-present": "error"}),
        "security/credential-file-present",
    )
    assert sorted(x.message.split("'")[1] for x in d) == [".env", "k.pem"]


def test_symlink_escape(tmp_path: Path):
    sd = _skill(tmp_path)
    (sd / "scripts").mkdir()
    os.symlink("/etc/hostname", sd / "scripts" / "run.sh")
    (tmp_path / "inside.txt").write_text("x")
    os.symlink(tmp_path / "inside.txt", sd / "scripts" / "ok.txt")
    d = _ids(
        lint(str(sd / "SKILL.md"), {"structural/symlink-escape": "error"}),
        "structural/symlink-escape",
    )
    assert len(d) == 1 and "run.sh" in d[0].message


def test_project_root_skips_config_dir(tmp_path: Path):
    from harness_eval.inspection.rules._config_fs import project_root

    d = tmp_path / ".claude"
    d.mkdir()
    (d / "CLAUDE.md").write_text("# nested")
    (tmp_path / "CLAUDE.md").write_text("# root")
    assert project_root(d / "settings.json") == tmp_path.resolve()
