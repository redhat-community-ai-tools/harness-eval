"""Regression fixtures for the false-positive classes the corpus audit found
in 7.14.0 (one test per class, each written as the audit refuted it)."""

from __future__ import annotations

import json
from pathlib import Path

from harness_eval.core.setup import discover_setup
from harness_eval.core.types import ComponentType
from harness_eval.inspection.engine import (
    lint,
    lint_agent,
    lint_command,
    lint_hooks,
    lint_mcp_config,
)
from harness_eval.inspection.parsers import parse_skill

CHECK = "${CLAUDE_PROJECT_DIR:-.}/.claude/hooks/check.py"


def _diags(result, rule_id: str):
    return [d for d in result.diagnostics if d.rule_id == rule_id]


def _settings(tmp_path: Path, data: dict) -> str:
    d = tmp_path / ".claude"
    d.mkdir(parents=True, exist_ok=True)
    p = d / "settings.json"
    p.write_text(json.dumps(data))
    return str(p)


class TestAgentDiscovery:
    def test_readme_in_agents_dir_is_not_an_agent(self, tmp_path: Path) -> None:
        d = tmp_path / ".claude" / "agents"
        d.mkdir(parents=True)
        (d / "README.md").write_text("# Agents\n")
        (d / "reviewer.md").write_text("---\ndescription: reviews\n---\nbody\n")
        names = {c.name for c in discover_setup("t", str(tmp_path)).by_type(ComponentType.AGENT)}
        assert "reviewer" in names
        assert "README" not in names

    def test_root_agents_dir_requires_frontmatter(self, tmp_path: Path) -> None:
        d = tmp_path / "agents"
        d.mkdir()
        (d / "claude.md").write_text("# Instructions for Claude\n")
        (d / "planner.md").write_text("---\ndescription: plans\n---\nbody\n")
        names = {c.name for c in discover_setup("t", str(tmp_path)).by_type(ComponentType.AGENT)}
        assert names == {"planner"}


class TestMcpConfigFormats:
    def test_plugin_flat_server_map_is_valid(self, tmp_path: Path) -> None:
        p = tmp_path / ".mcp.json"
        p.write_text(
            json.dumps(
                {"firebase": {"command": "npx", "args": ["-y", "firebase-tools@1.0.0", "mcp"]}}
            )
        )
        result = lint_mcp_config(str(p), {"mcp/valid-config": "warning"})
        assert _diags(result, "mcp/valid-config") == []

    def test_gemini_http_url_is_a_transport(self, tmp_path: Path) -> None:
        p = tmp_path / ".mcp.json"
        p.write_text(json.dumps({"mcpServers": {"c": {"httpUrl": "https://mcp.example/sse"}}}))
        result = lint_mcp_config(str(p), {"mcp/valid-config": "warning"})
        assert _diags(result, "mcp/valid-config") == []

    def test_jsonc_config_is_not_invalid_json(self, tmp_path: Path) -> None:
        p = tmp_path / ".mcp.json"
        p.write_text('{\n  // comment\n  "mcpServers": {"s": {"command": "x",}},\n}\n')
        result = lint_mcp_config(str(p), {"mcp/valid-config": "warning"})
        assert _diags(result, "mcp/valid-config") == []

    def test_docker_pull_policy_value_is_not_the_image(self, tmp_path: Path) -> None:
        p = tmp_path / ".mcp.json"
        p.write_text(
            json.dumps(
                {
                    "mcpServers": {
                        "s": {
                            "command": "docker",
                            "args": [
                                "run",
                                "--rm",
                                "-i",
                                "--pull",
                                "missing",
                                "ghcr.io/x/y@sha256:" + "a" * 64,
                            ],
                        }
                    }
                }
            )
        )
        result = lint_mcp_config(str(p), {"mcp/unpinned-package": "warning"})
        assert _diags(result, "mcp/unpinned-package") == []


class TestHookMatcherEvents:
    def _hooks(self, tmp_path: Path, event: str, matcher: str) -> str:
        return _settings(
            tmp_path,
            {
                "hooks": {
                    event: [{"matcher": matcher, "hooks": [{"type": "command", "command": "echo"}]}]
                }
            },
        )

    def test_session_start_matcher_is_not_a_tool_name(self, tmp_path: Path) -> None:
        result = lint_hooks(
            self._hooks(tmp_path, "SessionStart", "startup"),
            {"hooks/matcher-matches-no-tool": "warning"},
        )
        assert _diags(result, "hooks/matcher-matches-no-tool") == []

    def test_multiedit_is_a_known_tool(self, tmp_path: Path) -> None:
        result = lint_hooks(
            self._hooks(tmp_path, "PreToolUse", "MultiEdit"),
            {"hooks/matcher-matches-no-tool": "warning"},
        )
        assert _diags(result, "hooks/matcher-matches-no-tool") == []

    def test_mcp_literal_matcher_is_not_dead(self, tmp_path: Path) -> None:
        result = lint_hooks(
            self._hooks(tmp_path, "PreToolUse", "mcp__github__create_issue"),
            {"hooks/matcher-matches-no-tool": "warning"},
        )
        assert _diags(result, "hooks/matcher-matches-no-tool") == []

    def test_case_mismatch_still_flagged_on_tool_event(self, tmp_path: Path) -> None:
        result = lint_hooks(
            self._hooks(tmp_path, "PreToolUse", "bash"),
            {"hooks/matcher-matches-no-tool": "warning"},
        )
        assert len(_diags(result, "hooks/matcher-matches-no-tool")) == 1


class TestHookScriptPaths:
    def test_default_value_expansion_and_args(self, tmp_path: Path) -> None:
        (tmp_path / ".claude" / "hooks").mkdir(parents=True)
        (tmp_path / ".claude" / "hooks" / "check.py").write_text("")
        (tmp_path / "scripts").mkdir()
        (tmp_path / "scripts" / "standup.sh").write_text("")
        path = _settings(
            tmp_path,
            {
                "hooks": {
                    "Stop": [
                        {
                            "hooks": [
                                {
                                    "type": "command",
                                    "command": "python " + CHECK,
                                }
                            ]
                        },
                        {
                            "hooks": [
                                {
                                    "type": "command",
                                    "command": './scripts/standup.sh standup && echo "done"',
                                }
                            ]
                        },
                        {
                            "hooks": [
                                {
                                    "type": "command",
                                    "command": "node $HOME/.claude/hooks/dist/x.mjs",
                                }
                            ]
                        },
                    ]
                }
            },
        )
        result = lint_hooks(
            path,
            {"hooks/command-script-exists": "error"},
            scan_state={"project_root": str(tmp_path)},
        )
        assert _diags(result, "hooks/command-script-exists") == []

    def test_missing_project_script_still_flagged(self, tmp_path: Path) -> None:
        path = _settings(
            tmp_path,
            {"hooks": {"Stop": [{"hooks": [{"type": "command", "command": "./scripts/gone.sh"}]}]}},
        )
        result = lint_hooks(
            path,
            {"hooks/command-script-exists": "error"},
            scan_state={"project_root": str(tmp_path)},
        )
        assert len(_diags(result, "hooks/command-script-exists")) == 1


class TestSkillFrontmatter:
    def test_no_frontmatter_is_reported_once(self, tmp_path: Path) -> None:
        d = tmp_path / ".claude" / "skills" / "bare"
        d.mkdir(parents=True)
        (d / "SKILL.md").write_text("# Bare skill\n\nDo things.\n")
        result = lint(
            str(d),
            {"frontmatter/format-valid": "warning", "frontmatter/description-required": "error"},
        )
        assert len(_diags(result, "frontmatter/format-valid")) == 1
        assert _diags(result, "frontmatter/description-required") == []

    def test_example_env_files_are_not_secrets(self, tmp_path: Path) -> None:
        d = tmp_path / ".claude" / "skills" / "infra"
        (d / "assets").mkdir(parents=True)
        (d / "SKILL.md").write_text("---\nname: infra\ndescription: d\n---\nbody\n")
        (d / "assets" / ".env.queue.example").write_text("KEY=\n")
        (d / "assets" / ".env.local").write_text("KEY=1\n")
        result = lint(str(d), {"security/credential-file-present": "error"})
        diags = _diags(result, "security/credential-file-present")
        assert len(diags) == 1
        assert ".env.local" in diags[0].message


class TestSkillReferences:
    def _repo(self, tmp_path: Path) -> None:
        (tmp_path / ".claude-plugin").mkdir()
        (tmp_path / ".claude-plugin" / "plugin.json").write_text(json.dumps({"name": "mine"}))
        # A root-level skill directory that discovery does not lint but that exists.
        (tmp_path / "skills" / "foo").mkdir(parents=True)
        (tmp_path / "skills" / "foo" / "SKILL.md").write_text(
            "---\nname: foo\ndescription: d\n---\n"
        )
        (tmp_path / ".claude" / "commands").mkdir(parents=True)
        (tmp_path / ".claude" / "commands" / "deploy.md").write_text(
            "---\ndescription: d\n---\nrun\n"
        )

    def test_agent_namespaced_and_external_references(self, tmp_path: Path) -> None:
        self._repo(tmp_path)
        agent = tmp_path / ".claude" / "agents" / "a.md"
        agent.parent.mkdir(parents=True)
        agent.write_text(
            "---\ndescription: d\nskills: [mine:foo, superpowers:debugging, ghost]\n---\nbody\n"
        )
        result = lint_agent(
            str(agent),
            {"agent/referenced-skills-exist": "error"},
            scan_state={"project_root": str(tmp_path)},
        )
        diags = _diags(result, "agent/referenced-skills-exist")
        assert [d.message for d in diags] == [
            "Agent references skill 'ghost' but no SKILL.md found for it"
        ]

    def test_command_slash_tokens_resolve_against_commands_and_builtins(
        self, tmp_path: Path
    ) -> None:
        self._repo(tmp_path)
        cmd = tmp_path / ".claude" / "commands" / "ship.md"
        cmd.write_text(
            "---\ndescription: d\n---\nRun /deploy, then /clear, score /100, then /ghost now\n"
        )
        skills = [parse_skill(str(tmp_path / "skills" / "foo"))]
        result = lint_command(
            str(cmd),
            {"command/references-nonexistent-skill": "warning"},
            all_skills=skills,
            scan_state={"project_root": str(tmp_path)},
        )
        diags = _diags(result, "command/references-nonexistent-skill")
        assert len(diags) == 1
        assert "'ghost'" in diags[0].message


class TestSecondRound:
    def test_cursor_rule_imports_resolve_from_project_root(self, tmp_path: Path) -> None:
        from harness_eval.inspection.engine import lint_claude_md

        (tmp_path / "docs").mkdir()
        (tmp_path / "docs" / "guide.md").write_text("# guide\n")
        rules = tmp_path / ".cursor" / "rules"
        rules.mkdir(parents=True)
        (rules / "main.mdc").write_text(
            "---\nalwaysApply: true\n---\nSee @docs/guide.md and @docs/missing.md\n"
        )
        result = lint_claude_md(str(rules / "main.mdc"), {"claude-md/include-exists": "error"})
        diags = _diags(result, "claude-md/include-exists")
        assert len(diags) == 1
        assert "missing.md" in diags[0].message

    def test_mcp_command_relative_to_config_directory(self, tmp_path: Path) -> None:
        plugin = tmp_path / "plugins" / "p"
        (plugin / "scripts").mkdir(parents=True)
        (plugin / "scripts" / "launch.sh").write_text("#!/bin/sh\n")
        cfg = plugin / ".mcp.json"
        cfg.write_text(json.dumps({"mcpServers": {"s": {"command": "./scripts/launch.sh"}}}))
        result = lint_mcp_config(str(cfg), {"mcp/endpoint-integrity": "error"})
        assert _diags(result, "mcp/endpoint-integrity") == []

    def test_placeholder_token_with_hyphen(self, tmp_path: Path) -> None:
        cfg = tmp_path / ".mcp.json"
        cfg.write_text(
            json.dumps(
                {
                    "mcpServers": {
                        "slack": {
                            "command": "x",
                            "env": {"SLACK_BOT_TOKEN": "xoxb-your-token-here"},
                        }
                    }
                }
            )
        )
        result = lint_mcp_config(str(cfg), {"mcp/no-plaintext-secrets": "error"})
        assert _diags(result, "mcp/no-plaintext-secrets") == []

    def test_cursor_hook_script_relative_to_hooks_file(self, tmp_path: Path) -> None:
        d = tmp_path / ".cursor"
        (d / "hooks").mkdir(parents=True)
        (d / "hooks" / "run.sh").write_text("")
        p = d / "hooks.json"
        p.write_text(
            json.dumps(
                {"hooks": {"Stop": [{"hooks": [{"type": "command", "command": "./hooks/run.sh"}]}]}}
            )
        )
        result = lint_hooks(
            str(p),
            {"hooks/command-script-exists": "error"},
            scan_state={"project_root": str(tmp_path)},
        )
        assert _diags(result, "hooks/command-script-exists") == []

    def test_path_style_skill_reference(self, tmp_path: Path) -> None:
        (tmp_path / "skills" / "presentation" / "structure").mkdir(parents=True)
        (tmp_path / "skills" / "presentation" / "structure" / "SKILL.md").write_text(
            "---\nname: s\ndescription: d\n---\n"
        )
        agent = tmp_path / ".claude" / "agents" / "a.md"
        agent.parent.mkdir(parents=True)
        agent.write_text("---\ndescription: d\nskills: [presentation/structure]\n---\nbody\n")
        result = lint_agent(
            str(agent),
            {"agent/referenced-skills-exist": "error"},
            scan_state={"project_root": str(tmp_path)},
        )
        assert _diags(result, "agent/referenced-skills-exist") == []


class TestThirdRound:
    def test_scoped_shell_in_allowed_tools_is_not_unrestricted(self, tmp_path: Path) -> None:
        d = tmp_path / ".claude" / "skills" / "s"
        d.mkdir(parents=True)
        (d / "SKILL.md").write_text(
            "---\nname: s\ndescription: d\n"
            "allowed-tools: [Bash(npx sequant worktree:*), Bash(curl *), Bash(python:*)]\n---\n"
        )
        result = lint(str(d), {"content/allowed-tools-auto-approve": "warning"})
        high = [
            x
            for x in _diags(result, "content/allowed-tools-auto-approve")
            if "shell execution" in x.message
        ]
        assert [x.message.split("'")[1] for x in high] == ["Bash(python:*)"]

    def test_uppercase_docs_in_agents_dir_are_not_agents(self, tmp_path: Path) -> None:
        d = tmp_path / ".claude" / "agents"
        d.mkdir(parents=True)
        (d / "CUSTOMIZATION_NOTES.md").write_text("# notes\n")
        (d / "reviewer.md").write_text("---\ndescription: r\n---\n")
        names = {c.name for c in discover_setup("t", str(tmp_path)).by_type(ComponentType.AGENT)}
        assert names == {"reviewer"}

    def test_codex_mcp_servers_key(self, tmp_path: Path) -> None:
        p = tmp_path / ".mcp.json"
        p.write_text(json.dumps({"mcp_servers": {"s": {"command": "x"}}}))
        result = lint_mcp_config(str(p), {"mcp/valid-config": "warning"})
        assert _diags(result, "mcp/valid-config") == []

    def test_conditional_import_is_not_broken(self, tmp_path: Path) -> None:
        from harness_eval.inspection.engine import lint_claude_md

        (tmp_path / "CLAUDE.md").write_text(
            "First, check @AGENTS.override.md if exists.\nThen @missing.md\n"
        )
        result = lint_claude_md(str(tmp_path / "CLAUDE.md"), {"claude-md/include-exists": "error"})
        diags = _diags(result, "claude-md/include-exists")
        assert len(diags) == 1 and "missing.md" in diags[0].message


class TestFourthRound:
    """Crashes seen in the 8,966-repository from-scratch scan."""

    def test_agent_tools_map_is_parsed(self, tmp_path):
        from harness_eval.inspection.parsers import parse_agent

        p = tmp_path / "analyst.md"
        p.write_text(
            "---\nname: analyst\ndescription: x\ntools:\n  write: true\n  bash: false\n---\nbody\n"
        )
        agent = parse_agent(p)
        assert agent.allowed_tools == ["write"]
        assert "bash" in agent.disallowed_tools

    def test_agent_tools_scalar_does_not_crash(self, tmp_path):
        from harness_eval.inspection.parsers import parse_agent

        p = tmp_path / "a.md"
        p.write_text("---\nname: a\ndescription: x\ntools: 3\ndisallowedTools: false\n---\nbody\n")
        agent = parse_agent(p)
        assert agent.allowed_tools == ["3"]
        assert agent.disallowed_tools == []

    def test_token_count_accepts_special_token_text(self):
        from harness_eval.utils.tokens import count_tokens

        assert count_tokens("prefix <|endoftext|> suffix") > 0

    def test_divergence_ignores_implied_transport_type(self):
        from harness_eval.inspection.rules.mcp.cross_assistant_divergence import _normalise

        a = {"command": "npx", "args": ["-y", "x"]}
        b = {"type": "stdio", "command": "npx", "args": ["-y", "x"]}
        assert _normalise(a) == _normalise(b)
        c = {"url": "https://h/mcp"}
        d = {"type": "http", "url": "https://h/mcp"}
        assert _normalise(c) == _normalise(d)
        assert _normalise({"type": "sse", "url": "https://h/mcp"}) == _normalise(d)

    def test_hook_script_path_strips_shell_separator(self):
        from harness_eval.inspection.rules.hooks.command_script_exists import script_paths

        assert script_paths("if [ -f x ]; then $CLAUDE_PROJECT_DIR/scripts/preflight.sh; fi") == [
            "$CLAUDE_PROJECT_DIR/scripts/preflight.sh"
        ]

    def test_bom_before_frontmatter_is_ignored(self):
        from harness_eval.utils.parsing import parse_frontmatter, parse_frontmatter_rich

        text = "\ufeff---\nname: x\ndescription: y\n---\nbody\n"
        fm, body = parse_frontmatter(text)
        assert fm == {"name": "x", "description": "y"}
        assert body.strip() == "body"
        assert parse_frontmatter_rich(text).frontmatter == {"name": "x", "description": "y"}


class TestFifthRound:
    """Classes surfaced by reading every counted finding of the 5,928-repository corpus."""

    def test_nested_skill_md_is_not_a_skill(self, tmp_path):
        from harness_eval.core.discoverers.claude import ClaudeCodeDiscoverer

        (tmp_path / ".claude" / "skills" / "deploy").mkdir(parents=True)
        (tmp_path / ".claude" / "skills" / "deploy" / "SKILL.md").write_text(
            "---\nname: deploy\ndescription: d\n---\nx\n"
        )
        (tmp_path / ".claude" / "skills" / "deploy" / "steps").mkdir()
        (tmp_path / ".claude" / "skills" / "deploy" / "steps" / "SKILL.md").write_text(
            "# reference\n"
        )
        found = [str(p) for p in ClaudeCodeDiscoverer().collect_paths(tmp_path)]
        assert any(p.endswith("deploy/SKILL.md") for p in found)
        assert not any(p.endswith("steps/SKILL.md") for p in found)

    def test_hook_script_ignores_globs_substitutions_and_build_outputs(self):
        from harness_eval.inspection.rules.hooks.command_script_exists import script_paths

        cmd = "grep -q '*.py' && RESULT=$(scripts/check.sh) && ./dist/hook.js && ./node_modules/x"
        assert script_paths(cmd) == []
        assert script_paths("./scripts/real.sh") == ["./scripts/real.sh"]

    def test_npx_local_runner_and_no_install_are_not_unpinned(self):
        from harness_eval.inspection.rules.mcp.unpinned_package import _LOCAL_RUNNERS

        assert {"tsx", "node"} <= _LOCAL_RUNNERS

    def test_new_claude_code_tools_are_known(self):
        import json
        from pathlib import Path

        names = json.loads(
            (
                Path(__file__).resolve().parents[1] / "src/harness_eval/data/tool_names.json"
            ).read_text()
        )
        assert {"TaskCreate", "TaskUpdate", "EnterWorktree", "SendMessage"} <= set(names)


class TestGlobSkillReferences:
    def test_glob_reference_matches_skill_paths(self):
        from harness_eval.inspection.rules._component_index import resolve_skill_reference

        idx = {
            "skills": {"churn-prevention", "growth-marketer"},
            "plugins": set(),
            "skill_paths": {"business-growth/churn-prevention", "marketing/growth-marketer"},
        }
        assert resolve_skill_reference("business-growth/*", idx) is None
        assert resolve_skill_reference("growth-*", idx) is None
        assert resolve_skill_reference("sales/*", idx) == "missing"
        assert resolve_skill_reference("nothing-here", idx) == "missing"


class TestSixthRound:
    """Patch 0022: precision fixes from the second reading of the corpus."""

    def test_agents_md_alone_does_not_detect_opencode(self, tmp_path):
        from harness_eval.core.discoverers.opencode import OpenCodeDiscoverer

        (tmp_path / "AGENTS.md").write_text("# rules\n")
        assert not OpenCodeDiscoverer().detect(tmp_path)
        (tmp_path / ".opencode").mkdir()
        assert OpenCodeDiscoverer().detect(tmp_path)

    def test_hook_script_skips_variable_in_relative_path(self):
        from harness_eval.inspection.rules.hooks.command_script_exists import script_paths

        assert script_paths("./$PKG/hook.sh") == []
        assert script_paths("$CLAUDE_PROJECT_DIR/scripts/x.sh") == [
            "$CLAUDE_PROJECT_DIR/scripts/x.sh"
        ]

    def test_registry_manifest_and_empty_config_are_not_invalid(self):
        from harness_eval.inspection.rules.mcp.valid_config import _is_registry_manifest

        assert _is_registry_manifest({"name": "x", "version": "1.0", "tools": []})
        assert not _is_registry_manifest({"mcpServers": {}})

    def test_private_host_is_informational(self):
        from harness_eval.inspection.rules.mcp.endpoint_integrity import _is_private_host

        assert _is_private_host("odoo-rpc-mcp")
        assert _is_private_host("10.0.0.5")
        assert _is_private_host("box.internal")
        assert not _is_private_host("api.example.org")

    def test_slash_reference_only_in_invocation_context(self):
        from harness_eval.inspection.rules.commands.references_nonexistent_skill import (
            _SKILL_REF_PATTERNS,
        )

        pat = _SKILL_REF_PATTERNS[1]
        assert pat.search("Run /deploy to ship it") is not None
        assert pat.search("- /review") is not None
        assert pat.search("see docs/guide.md and src/lib for details") is None
        assert pat.search("the price is 3 USD/month") is None


class TestSeventhRound:
    """Patch 0023: consequences re-checked against current platform behaviour."""

    def test_missing_skill_description_is_a_warning_with_fallback_wording(self, tmp_path):
        d = tmp_path / "skills" / "demo"
        d.mkdir(parents=True)
        p = d / "SKILL.md"
        p.write_text("---\nname: demo\n---\nDoes a thing.\n")
        result = lint(str(p), {"frontmatter/description-required": "warning"})
        diags = _diags(result, "frontmatter/description-required")
        assert len(diags) == 1
        assert "first paragraph" in diags[0].message
        assert "specification requires" in diags[0].message

    def test_no_frontmatter_says_claude_code_still_loads(self, tmp_path):
        d = tmp_path / "skills" / "demo"
        d.mkdir(parents=True)
        p = d / "SKILL.md"
        p.write_text("# Demo\n\nDoes a thing.\n")
        result = lint(str(p), {"frontmatter/format-valid": "warning"})
        diags = _diags(result, "frontmatter/format-valid")
        assert len(diags) == 1
        assert "still loads" in diags[0].message

    def test_all_project_mcp_servers_is_a_warning_about_servers_only(self, tmp_path):
        path = _settings(tmp_path, {"enableAllProjectMcpServers": True})
        result = lint_hooks(path, {"hooks/permission-prompt-disabled": "error"})
        diags = _diags(result, "hooks/permission-prompt-disabled")
        assert len(diags) == 1
        assert diags[0].severity.value == "info"
        assert "Tool permission prompts are not affected" in diags[0].message

    def test_bypass_permissions_message_is_version_dated(self, tmp_path):
        path = _settings(tmp_path, {"permissions": {"defaultMode": "bypassPermissions"}})
        result = lint_hooks(path, {"hooks/permission-prompt-disabled": "error"})
        diags = _diags(result, "hooks/permission-prompt-disabled")
        assert len(diags) == 1
        assert diags[0].severity.value == "error"
        assert "v2.1.257" in diags[0].message

    def test_skill_reference_resolves_by_frontmatter_name(self, tmp_path):
        s = tmp_path / "skills" / "environments"
        s.mkdir(parents=True)
        (s / "SKILL.md").write_text(
            "---\nname: domino-environments\ndescription: envs\n---\nbody\n"
        )
        a = tmp_path / ".claude" / "agents"
        a.mkdir(parents=True)
        p = a / "setup.md"
        p.write_text(
            "---\nname: setup\ndescription: sets up\nskills:\n  - domino-environments\n"
            "  - environments\n  - nowhere\n---\nbody\n"
        )
        from harness_eval.inspection.engine import inspect_setup

        setup = discover_setup("t", str(tmp_path))
        msgs = [
            d.message
            for r in inspect_setup(setup, {"agent/referenced-skills-exist": "error"})
            for d in _diags(r, "agent/referenced-skills-exist")
        ]
        assert len(msgs) == 1 and "nowhere" in msgs[0]

    def test_bin_dir_is_a_build_output(self, tmp_path):
        p = tmp_path / ".mcp.json"
        p.write_text(json.dumps({"mcpServers": {"gws": {"command": "./bin/gws-mcp"}}}))
        result = lint_mcp_config(str(p), {"mcp/endpoint-integrity": "error"})
        assert _diags(result, "mcp/endpoint-integrity") == []


class TestEighthRound:
    """Patch 0024: cases from the independent reading of the corpus table."""

    def _mcp(self, tmp_path, servers):
        p = tmp_path / ".mcp.json"
        p.write_text(json.dumps({"mcpServers": servers}))
        return str(p)

    def test_uvx_flag_values_are_not_the_package(self, tmp_path):
        path = self._mcp(
            tmp_path,
            {
                "t": {
                    "command": "uvx",
                    "args": ["--python", ">=3.11,<3.14", "talkthrough-mcp[diarization,url]==0.4.1"],
                }
            },
        )
        assert (
            _diags(lint_mcp_config(path, {"mcp/unpinned-package": "error"}), "mcp/unpinned-package")
            == []
        )
        path = self._mcp(
            tmp_path, {"t": {"command": "uvx", "args": ["--python", "3.12", "some-server"]}}
        )
        assert (
            len(
                _diags(
                    lint_mcp_config(path, {"mcp/unpinned-package": "error"}), "mcp/unpinned-package"
                )
            )
            == 1
        )

    def test_disabled_server_is_skipped(self, tmp_path):
        path = self._mcp(
            tmp_path,
            {
                "slack": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-slack"],
                    "disabled": True,
                }
            },
        )
        assert (
            _diags(lint_mcp_config(path, {"mcp/unpinned-package": "error"}), "mcp/unpinned-package")
            == []
        )

    def test_npx_of_a_declared_dependency_is_local(self, tmp_path):
        (tmp_path / "package.json").write_text(json.dumps({"devDependencies": {"nx": "22.7.5"}}))
        self._mcp(
            tmp_path,
            {
                "nx-mcp": {"command": "npx", "args": ["nx", "mcp"]},
                "other": {"command": "npx", "args": ["-y", "shadcn@latest", "mcp"]},
            },
        )
        from harness_eval.inspection.engine import inspect_setup

        setup = discover_setup("t", str(tmp_path))
        msgs = [
            d.message
            for r in inspect_setup(setup, {"mcp/unpinned-package": "error"})
            for d in _diags(r, "mcp/unpinned-package")
        ]
        assert len(msgs) == 1 and "shadcn" in msgs[0]

    def test_copilot_path_instructions_are_not_agents(self, tmp_path):
        d = tmp_path / "agents"
        d.mkdir()
        (d / "copilot-path-instructions.md").write_text(
            '---\napplyTo: "**/*.md"\n---\nStyle rules.\n'
        )
        (d / "planner.md").write_text("---\ndescription: plans\n---\nbody\n")
        names = {c.name for c in discover_setup("t", str(tmp_path)).by_type(ComponentType.AGENT)}
        assert names == {"planner"}

    def test_skills_in_a_submodule_are_not_missing(self, tmp_path):
        (tmp_path / ".gitmodules").write_text(
            '[submodule ".claude/skills"]\n\tpath = .claude/skills\n\turl = x\n'
        )
        a = tmp_path / ".claude" / "agents"
        a.mkdir(parents=True)
        (a / "gov.md").write_text("---\nname: gov\ndescription: g\nskills: governance\n---\nbody\n")
        from harness_eval.inspection.engine import inspect_setup

        setup = discover_setup("t", str(tmp_path))
        assert [
            d
            for r in inspect_setup(setup, {"agent/referenced-skills-exist": "error"})
            for d in _diags(r, "agent/referenced-skills-exist")
        ] == []
