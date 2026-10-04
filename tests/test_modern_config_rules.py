from __future__ import annotations

import json
from pathlib import Path

from harness_eval.inspection.engine import lint, lint_claude_md, lint_config
from harness_eval.inspection.parsers import parse_skill


def _config(tmp_path: Path, content: str, name: str = "settings.json") -> str:
    path = tmp_path / name
    path.write_text(content)
    return str(path)


def _skill(tmp_path: Path, root: str, skill_id: str, body: str = "Do the task.") -> str:
    path = tmp_path / root / skill_id / "SKILL.md"
    path.parent.mkdir(parents=True)
    path.write_text(
        f"---\nname: {skill_id}\ndescription: Use when testing {skill_id}.\n---\n{body}\n"
    )
    return str(path)


def _ids(result) -> list[str]:
    return [finding.rule_id for finding in result.diagnostics]


def test_codex_uncontained_autonomy_is_flagged(tmp_path: Path) -> None:
    path = _config(
        tmp_path,
        'approval_policy = "never"\nsandbox_mode = "danger-full-access"\n',
        "config.toml",
    )
    result = lint_config(path, {"config/dangerous-autonomy": "error"}, source_tool="codex")
    assert _ids(result) == ["config/dangerous-autonomy"]


def test_codex_keeps_boundary_when_only_one_setting_is_broad(tmp_path: Path) -> None:
    path = _config(
        tmp_path,
        'approval_policy = "on-request"\nsandbox_mode = "danger-full-access"\n',
        "config.toml",
    )
    result = lint_config(path, {"config/dangerous-autonomy": "error"}, source_tool="codex")
    assert _ids(result) == []


def test_opencode_v2_permission_shape_and_effect(tmp_path: Path) -> None:
    path = _config(
        tmp_path,
        json.dumps({"permissions": [{"action": "shell", "resource": "*", "effect": "sometimes"}]}),
        "opencode.json",
    )
    result = lint_config(path, {"config/valid-structure": "error"}, source_tool="opencode")
    assert _ids(result) == ["config/valid-structure"]


def test_valid_opencode_v2_permission_is_clean(tmp_path: Path) -> None:
    path = _config(
        tmp_path,
        json.dumps(
            {"permissions": [{"action": "shell", "resource": "git status *", "effect": "allow"}]}
        ),
        "opencode.jsonc",
    )
    result = lint_config(path, {"config/valid-structure": "error"}, source_tool="opencode")
    assert _ids(result) == []


def test_gemini_disabled_skill_conflicts_with_discovered_skill(tmp_path: Path) -> None:
    skill = parse_skill(_skill(tmp_path, ".gemini/skills", "deploy"))
    path = _config(
        tmp_path,
        json.dumps({"skills": {"disabled": ["deploy"]}}),
    )
    result = lint_config(
        path,
        {"cross/config-component-conflict": "error"},
        all_skills=[skill],
        source_tool="gemini",
    )
    assert _ids(result) == ["cross/config-component-conflict"]


def test_gemini_enabled_skill_is_reachable(tmp_path: Path) -> None:
    skill = parse_skill(_skill(tmp_path, ".gemini/skills", "deploy"))
    path = _config(tmp_path, json.dumps({"skills": {"disabled": []}}))
    result = lint_config(
        path,
        {"cross/config-component-conflict": "error"},
        all_skills=[skill],
        source_tool="gemini",
    )
    assert _ids(result) == []


def test_gemini_does_not_claim_codex_only_skill_is_disabled(tmp_path: Path) -> None:
    skill = parse_skill(_skill(tmp_path, ".codex/skills", "deploy"))
    path = _config(tmp_path, json.dumps({"skills": {"disabled": ["deploy"]}}))
    result = lint_config(
        path,
        {"cross/config-component-conflict": "error"},
        all_skills=[skill],
        source_tool="gemini",
    )
    assert _ids(result) == []


def test_gemini_configured_hook_disabled_by_name_is_flagged(tmp_path: Path) -> None:
    path = _config(
        tmp_path,
        json.dumps(
            {
                "hooksConfig": {"disabled": ["security-check"]},
                "hooks": {
                    "BeforeTool": [
                        {
                            "hooks": [
                                {
                                    "name": "security-check",
                                    "type": "command",
                                    "command": "./check.sh",
                                }
                            ]
                        }
                    ]
                },
            }
        ),
    )
    result = lint_config(
        path,
        {"cross/config-component-conflict": "error"},
        source_tool="gemini",
    )
    assert _ids(result) == ["cross/config-component-conflict"]


def test_opencode_last_matching_rule_can_make_skill_unreachable(tmp_path: Path) -> None:
    skill = parse_skill(_skill(tmp_path, ".opencode/skills", "release"))
    data = {
        "permissions": [
            {"action": "skill", "resource": "*", "effect": "allow"},
            {"action": "skill", "resource": "release", "effect": "deny"},
        ]
    }
    path = _config(tmp_path, json.dumps(data), "opencode.json")
    result = lint_config(
        path,
        {"cross/config-component-conflict": "error"},
        all_skills=[skill],
        source_tool="opencode",
    )
    assert _ids(result) == ["cross/config-component-conflict"]


def test_opencode_later_allow_restores_skill(tmp_path: Path) -> None:
    skill = parse_skill(_skill(tmp_path, ".opencode/skills", "release"))
    data = {
        "permissions": [
            {"action": "skill", "resource": "*", "effect": "deny"},
            {"action": "skill", "resource": "release", "effect": "allow"},
        ]
    }
    path = _config(tmp_path, json.dumps(data), "opencode.json")
    result = lint_config(
        path,
        {"cross/config-component-conflict": "error"},
        all_skills=[skill],
        source_tool="opencode",
    )
    assert _ids(result) == []


def test_opencode_does_not_claim_codex_only_skill_is_denied(tmp_path: Path) -> None:
    skill = parse_skill(_skill(tmp_path, ".codex/skills", "release"))
    data = {"permissions": [{"action": "skill", "resource": "*", "effect": "deny"}]}
    path = _config(tmp_path, json.dumps(data), "opencode.json")
    result = lint_config(
        path,
        {"cross/config-component-conflict": "error"},
        all_skills=[skill],
        source_tool="opencode",
    )
    assert _ids(result) == []


def test_divergent_duplicate_skill_id_is_flagged(tmp_path: Path) -> None:
    first = parse_skill(_skill(tmp_path, ".agents/skills", "review", "Review Python."))
    second = parse_skill(_skill(tmp_path, ".codex/skills", "review", "Deploy services."))
    result = lint(
        first.skill_md_path,
        {"cross/duplicate-skill-id": "error"},
        all_skills=[first, second],
        parsed=first,
    )
    assert _ids(result) == ["cross/duplicate-skill-id"]


def test_unique_skill_id_is_clean(tmp_path: Path) -> None:
    first = parse_skill(_skill(tmp_path, ".agents/skills", "review"))
    second = parse_skill(_skill(tmp_path, ".codex/skills", "deploy"))
    result = lint(
        first.skill_md_path,
        {"cross/duplicate-skill-id": "error"},
        all_skills=[first, second],
        parsed=first,
    )
    assert _ids(result) == []


def test_copilot_path_instruction_requires_apply_to(tmp_path: Path) -> None:
    path = tmp_path / "python.instructions.md"
    path.write_text("---\ndescription: Python rules\n---\nUse Ruff.\n")
    result = lint_claude_md(str(path), {"content/activation-valid": "error"}, source_tool="copilot")
    assert _ids(result) == ["content/activation-valid"]


def test_copilot_apply_to_is_clean(tmp_path: Path) -> None:
    path = tmp_path / "python.instructions.md"
    path.write_text('---\napplyTo: "**/*.py"\n---\nUse Ruff.\n')
    result = lint_claude_md(str(path), {"content/activation-valid": "error"}, source_tool="copilot")
    assert _ids(result) == []
