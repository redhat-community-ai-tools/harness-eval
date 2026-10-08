"""What harness-autonomy talks about: the change, the runtime boundary, one
finding per decision."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from click.testing import CliRunner

from harness_eval.cli import cli
from harness_eval.cli.autonomy import EXIT_FAIL, EXIT_PASS, EXIT_REVIEW_REQUIRED
from harness_eval.core.setup import discover_setup
from harness_eval.inspection.engine import inspect_setup, lint, lint_harness
from harness_eval.inspection.parsers import parse_harness

FIXTURES = Path(__file__).parent / "fixtures"
FULLSEND = FIXTURES / "sample-fullsend-setup"


def _scaffold(tmp_path: Path, name: str = "scaffold") -> Path:
    dst = tmp_path / name
    shutil.copytree(FULLSEND, dst)
    return dst


def _ids(results, rule_id):
    return [d for r in results for d in r.diagnostics if d.rule_id == rule_id]


# --- the runtime boundary: harness-managed components ------------------------------


def test_harness_managed_agent_is_not_flagged_for_missing_tools(tmp_path: Path) -> None:
    root = _scaffold(tmp_path)
    agent = root / "agents" / "triage.md"
    agent.write_text(agent.read_text().replace("disallowedTools: Bash(git push *)\n", ""))
    loose = root / "agents" / "helper.md"
    loose.write_text("---\ndescription: not run by any harness\n---\nbody\n")
    results = inspect_setup(
        discover_setup("s", str(root)), {"agent/excessive-permissions": "warning"}
    )
    flagged = {Path(d.location.file).name for d in _ids(results, "agent/excessive-permissions")}
    assert flagged == {"helper.md"}


def test_harness_shipped_skill_allowed_tools_is_not_flagged(tmp_path: Path) -> None:
    root = _scaffold(tmp_path)
    shipped = root / "skills" / "issue-labels" / "SKILL.md"
    shipped.write_text(
        shipped.read_text().replace(
            "---\n\n# Issue labels", "allowed-tools: Bash\n---\n\n# Issue labels", 1
        )
    )
    loose = root / "skills" / "local-helper"
    loose.mkdir()
    (loose / "SKILL.md").write_text(
        "---\nname: local-helper\ndescription: d\nallowed-tools: Bash\n---\nbody\n"
    )
    results = inspect_setup(
        discover_setup("s", str(root)), {"content/allowed-tools-auto-approve": "warning"}
    )
    flagged = {
        Path(d.location.file).parent.name
        for d in _ids(results, "content/allowed-tools-auto-approve")
    }
    assert flagged == {"local-helper"}


def test_forge_skill_counts_as_managed_and_is_existence_checked(tmp_path: Path) -> None:
    root = _scaffold(tmp_path)
    h = root / "harness" / "triage.yaml"
    h.write_text(
        h.read_text().replace(
            "forge:\n  github:\n",
            "forge:\n  github:\n    skills:\n      - skills/issue-labels/github\n"
            "      - skills/missing-forge-skill\n"
            "    providers:\n      - github-ro\n      - providers/github-ro.yaml\n"
            "    openshell:\n      profiles:\n        - profiles/missing.yaml\n",
        )
    )
    (root / "skills" / "issue-labels" / "github").mkdir()
    parsed = parse_harness(str(h), source_tool="fullsend")
    assert "skills/issue-labels/github" in parsed.fields.skills
    result = lint_harness(
        str(h), {"harness/referenced-file-exists": "error"}, source_tool="fullsend"
    )
    fields = sorted(
        d.data["field"] for d in result.diagnostics if d.rule_id == "harness/referenced-file-exists"
    )
    assert fields == [
        "forge.github.openshell.profiles[0]",
        "forge.github.providers[1]",
        "forge.github.skills[1]",
    ]


def test_doc_and_skill_entry_mappings_are_referenced(tmp_path: Path) -> None:
    root = _scaffold(tmp_path)
    h = root / "harness" / "triage.yaml"
    text = h.read_text().replace(
        "skills:\n  - skills/issue-labels\n",
        "doc: docs/triage.md\nskills:\n  - source: skills/issue-labels\n"
        "    overrides:\n      x: y\n",
    )
    h.write_text(text)
    result = lint_harness(
        str(h), {"harness/referenced-file-exists": "error"}, source_tool="fullsend"
    )
    fields = sorted(
        d.data["field"] for d in result.diagnostics if d.rule_id == "harness/referenced-file-exists"
    )
    assert fields == ["doc"]


# --- one finding per decision -------------------------------------------------------


def test_allowed_tools_auto_approve_reports_once_per_class(tmp_path: Path) -> None:
    d = tmp_path / "s"
    d.mkdir()
    (d / "SKILL.md").write_text(
        "---\nname: s\ndescription: d\n"
        "allowed-tools: Bash(git push:*) Bash(gh release:*) Write Bash\n---\nbody\n"
    )
    result = lint(str(d), {"content/allowed-tools-auto-approve": "warning"})
    found = [x for x in result.diagnostics if x.rule_id == "content/allowed-tools-auto-approve"]
    assert len(found) == 2
    by_msg = {x.message.split(":")[0][:30]: x.data["tools"] for x in found}
    assert "Bash" in list(by_msg.values())[0] + list(by_msg.values())[1]
    assert any(t == "Bash(git push:*), Bash(gh release:*), Write" for t in by_msg.values())


def test_skill_name_mismatch_is_informational(tmp_path: Path) -> None:
    d = tmp_path / "github-forge"
    d.mkdir()
    (d / "SKILL.md").write_text("---\nname: github\ndescription: d\n---\nbody\n")
    result = lint(str(d), {"frontmatter/format-valid": "warning"})
    mismatch = [x for x in result.diagnostics if "does not match directory" in x.message]
    assert len(mismatch) == 1 and mismatch[0].severity.value == "info"
    runner = CliRunner().invoke(cli, ["harness-autonomy", str(tmp_path), "--format", "json"])
    assert runner.exit_code == EXIT_PASS, runner.output


# --- the change, not the repository ----------------------------------------------


def test_compare_counts_only_findings_the_change_introduced(tmp_path: Path) -> None:
    base = _scaffold(tmp_path, "base")  # image: ...:latest is a pre-existing policy fact
    head = _scaffold(tmp_path, "head")
    (head / "agents" / "triage.md").unlink()  # the change breaks a reference
    runner = CliRunner()

    full = runner.invoke(cli, ["harness-autonomy", str(head), "--format", "json"])
    assert full.exit_code == EXIT_FAIL
    data = json.loads(full.output)
    assert [f["rule"] for f in data["policy"]] == ["harness/image-unpinned"]

    compared = runner.invoke(
        cli, ["harness-autonomy", str(head), "--compare", str(base), "--format", "json"]
    )
    assert compared.exit_code == EXIT_FAIL
    data = json.loads(compared.output)
    assert [f["rule"] for f in data["pre_existing"]] == ["harness/image-unpinned"]
    assert data["policy"] == []
    assert {f["rule"] for f in data["blocking"]} >= {"harness/referenced-file-exists"}
    assert data["evidence"]["compare"]["setup_fingerprint"]

    unchanged = runner.invoke(
        cli, ["harness-autonomy", str(base), "--compare", str(base), "--format", "json"]
    )
    assert unchanged.exit_code == EXIT_PASS
    assert json.loads(unchanged.output)["verdict"] == "PASS"


def test_compare_still_requires_review_for_a_new_policy_fact(tmp_path: Path) -> None:
    base = _scaffold(tmp_path, "base")
    head = _scaffold(tmp_path, "head")
    h = head / "harness" / "triage.yaml"
    h.write_text(
        h.read_text().replace(
            "image: ghcr.io/example/sandbox:latest", "image: ghcr.io/example/other:latest"
        )
    )
    result = CliRunner().invoke(
        cli, ["harness-autonomy", str(head), "--compare", str(base), "--format", "json"]
    )
    assert result.exit_code == EXIT_REVIEW_REQUIRED
    data = json.loads(result.output)
    assert [f["data"]["image"] for f in data["policy"]] == ["ghcr.io/example/other:latest"]
    assert data["pre_existing"] == []
