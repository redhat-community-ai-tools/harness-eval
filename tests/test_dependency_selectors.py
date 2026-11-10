"""Literal selector regressions. No package, image or target code is executed."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from harness_eval.inspection.engine import lint_mcp_config

RULE = "mcp/unpinned-package"


@pytest.mark.parametrize(
    ("command", "args", "reported"),
    [
        ("npx", ["pkg@^1.2.3"], ["pkg@^1.2.3"]),
        ("npx", ["@scope/pkg@~1.2.3"], ["@scope/pkg@~1.2.3"]),
        ("npx", ["pkg@next"], ["pkg@next"]),
        ("npx", ["pkg@1"], ["pkg@1"]),
        ("npx", ["pkg@1.2.3"], []),
        ("npx", ["pkg@1.2.3-rc.1+build.2"], []),
        ("npx", ["--package=pkg@1.2.3", "different-command"], []),
        ("npx", ["-p", "pkg@1.2.3", "different-command"], []),
        ("npx", ["--package=pkg@next", "different-command"], ["pkg@next"]),
        ("npx", ["--package", "one@1.2.3", "--package", "two@latest", "cmd"], ["two@latest"]),
        ("npx", ["--offline", "pkg@latest"], []),
        ("npx", ["pkg@latest", "--offline"], ["pkg@latest"]),
        ("npx", ["--registry", "https://registry.example", "pkg@1.2.3"], []),
        ("npx", ["--", "pkg@next"], ["pkg@next"]),
        ("npx", ["-ppkg@1.2.3", "cmd"], []),
        ("uvx", ["pkg@latest"], ["pkg@latest"]),
        ("uvx", ["pkg==1.*"], ["pkg==1.*"]),
        ("uvx", ["pkg@1.2.3"], []),
        ("uvx", ["pkg==1.2.3"], []),
        ("uvx", ["pkg[extra]==1.2rc1.post2.dev3+local.1"], []),
        ("uvx", ["--from=pkg==1.2.3", "different-command"], []),
        ("uvx", ["--from", "pkg>=1.2", "different-command"], ["pkg>=1.2"]),
        ("uvx", ["--from=pkg>=1.2", "different-command"], ["pkg>=1.2"]),
        ("uvx", ["pkg==1.2.3", "--from", "argument-for-tool"], []),
        ("uvx", ["--python", "3.12", "--from=pkg==1.2.3", "cmd"], []),
        (
            "uvx",
            ["--from", "git+https://example.org/repo@main", "cmd"],
            ["git+https://example.org/repo@main"],
        ),
        ("uvx", ["--from", "git+https://example.org/repo@" + "a" * 40, "cmd"], []),
        ("pipx", ["run", "--spec", "pkg==1.2.3", "different-command"], []),
        ("pipx", ["run", "--spec=pkg>=1.2", "different-command"], ["pkg>=1.2"]),
        (
            "docker",
            ["run", "registry.example:5000/team/image"],
            ["registry.example:5000/team/image"],
        ),
        ("docker", ["run", "registry.example:5000/team/image:1.2"], []),
        ("docker", ["run", "image:stable"], []),  # Explicit tag, not immutability evidence.
        ("docker", ["run", "image:latest"], ["image:latest"]),
        ("docker", ["run", "image:"], ["image:"]),
        ("docker", ["run", "image@sha256:" + "a" * 64], []),
        (r"C:\tools\npx.cmd", ["pkg@next"], ["pkg@next"]),
    ],
)
def test_literal_dependency_selector(
    tmp_path: Path, command: str, args: list[str], reported: list[str]
) -> None:
    path = tmp_path / ".mcp.json"
    path.write_text(json.dumps({"mcpServers": {"test": {"command": command, "args": args}}}))
    result = lint_mcp_config(str(path), {RULE: "warning"})
    findings = [d for d in result.diagnostics if d.rule_id == RULE]
    assert [d.data["spec"] for d in findings] == reported


def test_explicit_floating_selector_is_not_hidden_by_package_json(tmp_path: Path) -> None:
    from harness_eval.core.setup import discover_setup
    from harness_eval.inspection.engine import inspect_setup

    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"pkg": "1.2.3"}}))
    (tmp_path / ".mcp.json").write_text(
        json.dumps({"mcpServers": {"test": {"command": "npx", "args": ["pkg@latest"]}}})
    )
    results = inspect_setup(discover_setup("t", str(tmp_path)), {RULE: "warning"})
    assert any(d.rule_id == RULE for r in results for d in r.diagnostics)
