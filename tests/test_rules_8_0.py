"""The decidable rules added in 8.0 and the effect axis they ride on."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import harness_eval.inspection  # noqa: F401 — registers all rules
from harness_eval.inspection.engine import (
    lint,
    lint_agent,
    lint_command,
    lint_harness,
    lint_hooks,
    lint_mcp_config,
)
from harness_eval.inspection.registry import get_all_rules

FIXTURES = Path(__file__).parent / "fixtures"


def _ids(result) -> set[str]:
    return {d.rule_id for d in result.diagnostics}


def _diags(result, rule_id: str):
    return [d for d in result.diagnostics if d.rule_id == rule_id]


# --- effect axis ----------------------------------------------------------------


def test_every_rule_declares_a_valid_effect() -> None:
    for r in get_all_rules():
        assert r.meta.effect in {"block", "policy", "signal", "advice"}, r.meta.id


def test_signal_and_advice_rules_are_never_gating_or_provisional() -> None:
    for r in get_all_rules():
        if r.meta.effect in {"signal", "advice"}:
            assert r.meta.tier == "advisory", f"{r.meta.id} is heuristic but tier={r.meta.tier}"


def test_block_and_policy_rules_have_passed_the_corpus() -> None:
    for r in get_all_rules():
        if r.meta.effect in {"block", "policy"}:
            assert r.meta.tier in {"gating", "provisional"}, (
                f"{r.meta.id} is decidable but tier={r.meta.tier}"
            )


def test_multi_target_rules_register_for_each_target() -> None:
    from harness_eval.core.types import ComponentType
    from harness_eval.inspection.registry import get_default_catalog

    catalog = get_default_catalog()
    for ct in (ComponentType.SKILL, ComponentType.COMMAND, ComponentType.AGENT):
        ids = {r.meta.id for r in catalog.for_target(ct)}
        assert "security/no-prompt-injection" in ids, ct


# --- frontmatter/near-miss-key --------------------------------------------------

NEAR_MISS = "frontmatter/near-miss-key"


def _skill(tmp_path: Path, frontmatter: str, name: str = "demo") -> str:
    d = tmp_path / name
    d.mkdir()
    (d / "SKILL.md").write_text(f"---\n{frontmatter}---\n\nBody text.\n")
    return str(d)


def test_near_miss_key_fires_on_underscore_variant(tmp_path: Path) -> None:
    path = _skill(tmp_path, "name: demo\ndescription: Does a thing.\nallowed_tools: Read\n")
    found = _diags(lint(path, {NEAR_MISS: "error"}), NEAR_MISS)
    assert len(found) == 1
    assert found[0].data == {"key": "allowed_tools", "expected": "allowed-tools"}


def test_near_miss_key_is_silent_on_known_and_foreign_keys(tmp_path: Path) -> None:
    path = _skill(
        tmp_path,
        "name: demo\ndescription: Does a thing.\nallowed-tools: Read\nmetadata:\n  team: x\n"
        "some-vendor-key: true\n",
    )
    assert _diags(lint(path, {NEAR_MISS: "error"}), NEAR_MISS) == []


def test_near_miss_key_on_agent_camel_case(tmp_path: Path) -> None:
    agent = tmp_path / "reviewer.md"
    agent.write_text("---\ndescription: reviews\ndisallowed-tools: Bash\n---\nbody\n")
    found = _diags(lint_agent(str(agent), {NEAR_MISS: "error"}), NEAR_MISS)
    assert [d.data["expected"] for d in found] == ["disallowedTools"]


def test_near_miss_key_skips_other_clients(tmp_path: Path) -> None:
    d = tmp_path / "cmd"
    d.mkdir()
    (d / "command.md").write_text("---\nDescription: x\n---\nbody\n")
    result = lint_command(str(d), {NEAR_MISS: "error"}, source_tool="cursor")
    assert _diags(result, NEAR_MISS) == []


# --- frontmatter/allowed-tools-case ---------------------------------------------

TOOLS_CASE = "frontmatter/allowed-tools-case"


def test_allowed_tools_case_fires_on_lowercase_builtin(tmp_path: Path) -> None:
    path = _skill(tmp_path, "name: demo\ndescription: Does a thing.\nallowed-tools: read bash\n")
    found = _diags(lint(path, {TOOLS_CASE: "error"}), TOOLS_CASE)
    assert sorted(d.data["expected"] for d in found) == ["Bash", "Read"]


def test_allowed_tools_case_is_silent_on_exact_mcp_and_unknown(tmp_path: Path) -> None:
    path = _skill(
        tmp_path,
        "name: demo\ndescription: Does a thing.\n"
        "allowed-tools: Read Bash(git:*) mcp__github__list_issues MyCustomTool\n",
    )
    assert _diags(lint(path, {TOOLS_CASE: "error"}), TOOLS_CASE) == []


def test_allowed_tools_case_on_agent_tools(tmp_path: Path) -> None:
    agent = tmp_path / "reviewer.md"
    agent.write_text("---\ndescription: reviews\ntools: edit, Read\n---\nbody\n")
    found = _diags(lint_agent(str(agent), {TOOLS_CASE: "error"}), TOOLS_CASE)
    assert [(d.data["field"], d.data["expected"]) for d in found] == [("tools", "Edit")]


# --- hooks/event-name-near-miss --------------------------------------------------

EVENT = "hooks/event-name-near-miss"


def _settings(tmp_path: Path, data: dict) -> str:
    d = tmp_path / ".claude"
    d.mkdir(parents=True, exist_ok=True)
    p = d / "settings.json"
    p.write_text(json.dumps(data))
    return str(p)


def _hook(event: str) -> dict:
    return {"hooks": {event: [{"matcher": "Bash", "hooks": [{"type": "command", "command": "x"}]}]}}


def test_event_name_near_miss_fires_on_case_variant(tmp_path: Path) -> None:
    result = lint_hooks(_settings(tmp_path, _hook("preToolUse")), {EVENT: "error"})
    found = _diags(result, EVENT)
    assert len(found) == 1
    assert found[0].data == {"event": "preToolUse", "expected": "PreToolUse"}


def test_event_name_near_miss_is_silent_on_exact_and_unknown(tmp_path: Path) -> None:
    data = {"hooks": {**_hook("PreToolUse")["hooks"], **_hook("SomeFutureEvent")["hooks"]}}
    assert _diags(lint_hooks(_settings(tmp_path, data), {EVENT: "error"}), EVENT) == []


def test_event_name_near_miss_skips_cursor_and_copilot(tmp_path: Path) -> None:
    result = lint_hooks(
        _settings(tmp_path, _hook("preToolUse")), {EVENT: "error"}, source_tool="copilot"
    )
    assert _diags(result, EVENT) == []


# --- agent/tools-disallowed-overlap ----------------------------------------------

OVERLAP = "agent/tools-disallowed-overlap"


def test_overlap_fires_on_same_bare_tool(tmp_path: Path) -> None:
    agent = tmp_path / "a.md"
    agent.write_text("---\ndescription: d\ntools: Read, Bash\ndisallowedTools: Bash\n---\nbody\n")
    found = _diags(lint_agent(str(agent), {OVERLAP: "error"}), OVERLAP)
    assert [d.data["entry"] for d in found] == ["Bash"]


def test_overlap_is_silent_when_deny_narrows_allow(tmp_path: Path) -> None:
    agent = tmp_path / "a.md"
    agent.write_text("---\ndescription: d\ntools: Bash\ndisallowedTools: Bash(rm *)\n---\nbody\n")
    assert _diags(lint_agent(str(agent), {OVERLAP: "error"}), OVERLAP) == []


# --- mcp/args-reference-missing-file ---------------------------------------------

ARGS = "mcp/args-reference-missing-file"


def _mcp(tmp_path: Path, servers: dict) -> str:
    p = tmp_path / ".mcp.json"
    p.write_text(json.dumps({"mcpServers": servers}))
    return str(p)


def test_args_missing_file_fires(tmp_path: Path) -> None:
    path = _mcp(tmp_path, {"local": {"command": "node", "args": ["./servers/missing.js"]}})
    found = _diags(lint_mcp_config(path, {ARGS: "error"}), ARGS)
    assert [d.data["path"] for d in found] == ["./servers/missing.js"]


def test_args_missing_file_is_silent_when_present_or_undecidable(tmp_path: Path) -> None:
    (tmp_path / "servers").mkdir()
    (tmp_path / "servers" / "ok.js").write_text("")
    path = _mcp(
        tmp_path,
        {
            "a": {"command": "node", "args": ["./servers/ok.js"]},
            "b": {"command": "node", "args": ["./dist/server.js", "./${DIR}/x.js", "-y", "pkg"]},
            "fs": {"command": "npx", "args": ["-y", "@mcp/server-filesystem", "./data"]},
            "c": {"url": "https://example.com/mcp", "args": ["./not-a-stdio-server.js"]},
        },
    )
    assert _diags(lint_mcp_config(path, {ARGS: "error"}), ARGS) == []


# --- harness/image-unpinned -------------------------------------------------------

IMAGE = "harness/image-unpinned"
FULLSEND = FIXTURES / "sample-fullsend-setup"


def _scaffold_with_image(tmp_path: Path, image: str | None) -> Path:
    root = tmp_path / "scaffold"
    shutil.copytree(FULLSEND, root)
    h = root / "harness" / "triage.yaml"
    lines = [ln for ln in h.read_text().splitlines() if not ln.startswith("image:")]
    if image is not None:
        lines.insert(3, f"image: {image}")
    h.write_text("\n".join(lines) + "\n")
    return h


def test_image_unpinned_fires_on_latest_and_untagged(tmp_path: Path) -> None:
    for image in ("ghcr.io/example/sandbox:latest", "ghcr.io/example/sandbox", "registry:5000/x"):
        h = _scaffold_with_image(tmp_path / image.replace("/", "_").replace(":", "_"), image)
        found = _diags(lint_harness(str(h), {IMAGE: "warning"}, source_tool="fullsend"), IMAGE)
        assert [d.data["image"] for d in found] == [image], image


def test_image_unpinned_is_silent_on_tag_digest_variable_and_absent(tmp_path: Path) -> None:
    for image in (
        "ghcr.io/example/sandbox:v1.4.2",
        "ghcr.io/example/sandbox@sha256:" + "a" * 64,
        "${SANDBOX_IMAGE}",
        None,
    ):
        h = _scaffold_with_image(tmp_path / str(image).replace("/", "_").replace(":", "_"), image)
        assert _diags(lint_harness(str(h), {IMAGE: "warning"}, source_tool="fullsend"), IMAGE) == []


def test_image_unpinned_is_policy_not_block() -> None:
    rule = next(r for r in get_all_rules() if r.meta.id == IMAGE)
    assert rule.meta.effect == "policy"
