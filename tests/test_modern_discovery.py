from __future__ import annotations

import json
from pathlib import Path

from harness_eval.core.setup import discover_setup
from harness_eval.core.types import ComponentType


def _types(setup) -> set[tuple[ComponentType, str]]:
    return {
        (component.component_type, component.source_tool or "") for component in setup.components
    }


def test_codex_toml_is_config_and_mcp_and_portable_skill_is_found(tmp_path: Path) -> None:
    config = tmp_path / ".codex" / "config.toml"
    config.parent.mkdir()
    config.write_text('[mcp_servers.docs]\nurl = "https://example.com/mcp"\n')
    skill = tmp_path / ".agents" / "skills" / "docs" / "SKILL.md"
    skill.parent.mkdir(parents=True)
    skill.write_text("---\nname: docs\ndescription: Use for docs.\n---\nRead docs.\n")

    setup = discover_setup("codex", str(tmp_path))
    assert (ComponentType.CONFIG, "codex") in _types(setup)
    assert (ComponentType.MCP_CONFIG, "codex") in _types(setup)
    assert any(component.component_type is ComponentType.SKILL for component in setup.components)


def test_opencode_jsonc_and_portable_skill_roots_are_found(tmp_path: Path) -> None:
    (tmp_path / ".opencode").mkdir()
    (tmp_path / "opencode.jsonc").write_text(
        "{\n"
        ' "permissions": [], // current V2 permission format\n'
        ' "mcp": {"docs": {"url": "https://e/mcp/*literal*/"}},\n'
        "}\n"
    )
    skill = tmp_path / ".claude" / "skills" / "shared" / "SKILL.md"
    skill.parent.mkdir(parents=True)
    skill.write_text("---\nname: shared\ndescription: Use for shared tasks.\n---\nRun.\n")

    setup = discover_setup("opencode", str(tmp_path))
    assert (ComponentType.CONFIG, "opencode") in _types(setup)
    assert (ComponentType.MCP_CONFIG, "opencode") in _types(setup)
    assert any(component.component_type is ComponentType.SKILL for component in setup.components)


def test_copilot_path_instructions_hooks_settings_and_skills_are_found(tmp_path: Path) -> None:
    instruction = tmp_path / ".github" / "instructions" / "python.instructions.md"
    instruction.parent.mkdir(parents=True)
    instruction.write_text('---\napplyTo: "**/*.py"\n---\nUse Ruff.\n')
    hook = tmp_path / ".github" / "hooks" / "checks.json"
    hook.parent.mkdir(parents=True)
    hook.write_text(json.dumps({"version": 1, "hooks": {}}))
    settings = tmp_path / ".github" / "copilot" / "settings.json"
    settings.parent.mkdir(parents=True)
    settings.write_text("{}")
    skill = tmp_path / ".github" / "skills" / "review" / "SKILL.md"
    skill.parent.mkdir(parents=True)
    skill.write_text("---\nname: review\ndescription: Use for reviews.\n---\nReview.\n")

    setup = discover_setup("copilot", str(tmp_path))
    types = _types(setup)
    assert (ComponentType.CLAUDE_MD, "copilot") in types
    assert (ComponentType.HOOKS, "copilot") in types
    assert (ComponentType.CONFIG, "copilot") in types
    assert (ComponentType.SKILL, "copilot") in types


def test_preferred_devin_and_current_cline_roots_are_found(tmp_path: Path) -> None:
    rule = tmp_path / ".devin" / "rules" / "python.md"
    rule.parent.mkdir(parents=True)
    rule.write_text("Use Ruff.\n")
    windsurf_skill = tmp_path / ".devin" / "skills" / "review" / "SKILL.md"
    windsurf_skill.parent.mkdir(parents=True)
    windsurf_skill.write_text("---\nname: review\ndescription: Use for reviews.\n---\nReview.\n")
    cline_rule = tmp_path / ".cline" / "rules" / "security.md"
    cline_rule.parent.mkdir(parents=True)
    cline_rule.write_text("Do not commit secrets.\n")
    cline_skill = tmp_path / ".cline" / "skills" / "secure" / "SKILL.md"
    cline_skill.parent.mkdir(parents=True)
    cline_skill.write_text("---\nname: secure\ndescription: Use for security.\n---\nScan.\n")

    setup = discover_setup("mixed", str(tmp_path))
    types = _types(setup)
    assert (ComponentType.CLAUDE_MD, "windsurf") in types
    assert (ComponentType.SKILL, "windsurf") in types
    assert (ComponentType.CLAUDE_MD, "cline") in types
    assert (ComponentType.SKILL, "cline") in types
