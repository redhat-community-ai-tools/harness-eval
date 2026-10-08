"""harness-autonomy: decidable rules only, three exit codes, policy waivers, coverage."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from click.testing import CliRunner

from harness_eval.cli import cli
from harness_eval.cli.autonomy import EXIT_FAIL, EXIT_PASS, EXIT_REVIEW_REQUIRED, load_policy
from harness_eval.config.presets import autonomy_rules, gate_rules, lint_rules, security_rules
from harness_eval.inspection.registry import get_all_rules

FIXTURES = Path(__file__).parent / "fixtures"
FULLSEND = FIXTURES / "sample-fullsend-setup"
CLEAN = FIXTURES / "corpus" / "false-positives"


def _run(*args: str):
    return CliRunner().invoke(cli, ["harness-autonomy", *args])


# --- rule selection is derived from effect and tier -------------------------------


def test_autonomy_set_is_exactly_decidable_corpus_passed_rules() -> None:
    expected = {
        r.meta.id
        for r in get_all_rules()
        if r.meta.effect in {"block", "policy"} and r.meta.tier in {"gating", "provisional"}
    }
    assert set(autonomy_rules()) == expected
    for r in get_all_rules():
        if r.meta.effect in {"signal", "advice"}:
            assert r.meta.id not in autonomy_rules()


def test_gate_is_block_rules_at_gating_tier() -> None:
    by_id = {r.meta.id: r for r in get_all_rules()}
    for rid in gate_rules():
        assert by_id[rid].meta.effect == "block" and by_id[rid].meta.tier == "gating"
    for rid in gate_rules(include_provisional=True):
        assert by_id[rid].meta.effect == "block"
    assert set(gate_rules()) < set(gate_rules(include_provisional=True))


def test_security_set_has_no_advice_and_every_signal_rule() -> None:
    by_id = {r.meta.id: r for r in get_all_rules()}
    selected = security_rules()
    for rid in selected:
        assert by_id[rid].meta.effect != "advice", rid
    for r in get_all_rules():
        if r.meta.effect in {"signal", "policy"}:
            assert r.meta.id in selected, r.meta.id
    assert selected["security/yara-signatures"] == "error"
    assert selected["security/cve-lookup"] == "off"


def test_lint_defaults_to_advice_and_all_runs_everything() -> None:
    by_id = {r.meta.id: r for r in get_all_rules()}
    for rid in lint_rules():
        assert by_id[rid].meta.effect == "advice", rid
    assert set(lint_rules(everything=True)) == set(by_id)
    assert lint_rules("strict", everything=True)["frontmatter/description-quality"] == "error"


# --- verdicts and exit codes -----------------------------------------------------


def test_clean_setup_passes_with_evidence_and_coverage() -> None:
    result = _run(str(CLEAN), "--format", "json")
    assert result.exit_code == EXIT_PASS, result.output
    data = json.loads(result.output)
    assert data["verdict"] == "PASS"
    assert data["blocking"] == [] and data["policy"] == []
    assert data["evidence"]["setup_fingerprint"]
    assert data["evidence"]["rules"]["digest"]
    assert data["coverage"]["rules_selected"] == len(autonomy_rules())
    assert data["coverage"]["components"]


def test_policy_finding_alone_is_review_required(tmp_path: Path) -> None:
    root = tmp_path / "scaffold"
    shutil.copytree(FULLSEND, root)  # image: ...:latest is a policy fact
    result = _run(str(root), "--format", "json")
    assert result.exit_code == EXIT_REVIEW_REQUIRED, result.output
    data = json.loads(result.output)
    assert data["verdict"] == "REVIEW_REQUIRED"
    assert [f["rule"] for f in data["policy"]] == ["harness/image-unpinned"]
    assert data["blocking"] == []


def test_block_finding_is_fail(tmp_path: Path) -> None:
    root = tmp_path / "scaffold"
    shutil.copytree(FULLSEND, root)
    (root / "agents" / "triage.md").unlink()
    result = _run(str(root), "--format", "json")
    assert result.exit_code == EXIT_FAIL
    data = json.loads(result.output)
    assert data["verdict"] == "FAIL"
    assert "harness/referenced-file-exists" in {f["rule"] for f in data["blocking"]}


def test_trusted_policy_file_waives_policy_findings(tmp_path: Path) -> None:
    root = tmp_path / "scaffold"
    shutil.copytree(FULLSEND, root)
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        "accept:\n"
        "  - rule: harness/image-unpinned\n"
        "    file: harness/*.yaml\n"
        "    reason: platform images float by design, tracked in SEC-42\n"
    )
    result = _run(str(root), "--policy", str(policy), "--format", "json")
    assert result.exit_code == EXIT_PASS, result.output
    data = json.loads(result.output)
    assert data["verdict"] == "PASS"
    assert len(data["waived"]) == 1
    assert data["waived"][0]["accepted_by"]["reason"].startswith("platform images")
    assert data["evidence"]["policy"]["digest"]


def test_policy_file_cannot_waive_block_rules(tmp_path: Path) -> None:
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        "accept:\n"
        "  - rule: harness/referenced-file-exists\n    reason: nope\n"
        "  - rule: harness/image-unpinned\n"
        "  - rule: no/such-rule\n    reason: x\n"
    )
    grants, problems = load_policy(policy)
    assert grants == []
    assert len(problems) == 3
    assert any("effect=block" in p for p in problems)


def test_terminal_output_lists_sections(tmp_path: Path) -> None:
    root = tmp_path / "scaffold"
    shutil.copytree(FULLSEND, root)
    result = _run(str(root))
    assert result.exit_code == EXIT_REVIEW_REQUIRED
    assert "Verdict: REVIEW_REQUIRED" in result.output
    assert "Policy (needs a decision)" in result.output
    assert "Coverage:" in result.output
    assert "Evidence:" in result.output


def test_sarif_carries_verdict() -> None:
    result = _run(str(CLEAN), "--format", "sarif")
    assert result.exit_code == EXIT_PASS
    doc = json.loads(result.output)
    props = doc["runs"][0]["properties"]["harnessEval.autonomy"]
    assert props["verdict"] == "PASS"


def test_baseline_suppressions_are_counted_not_hidden(tmp_path: Path) -> None:
    root = tmp_path / "scaffold"
    shutil.copytree(FULLSEND, root)
    (root / "agents" / "triage.md").unlink()
    first = json.loads(_run(str(root), "--format", "json").output)
    bl = tmp_path / "bl.json"
    import hashlib

    bl.write_text(
        json.dumps(
            {
                "version": "1.0",
                "findings": [
                    {
                        "rule_id": f["rule"],
                        "file": f["file"],
                        "message_hash": hashlib.sha256(f["message"].encode()).hexdigest()[:16],
                    }
                    for f in first["blocking"] + first["policy"]
                ],
            }
        )
    )
    result = _run(str(root), "--baseline", str(bl), "--format", "json")
    data = json.loads(result.output)
    assert data["coverage"]["baseline_suppressed"] == len(first["blocking"]) + len(first["policy"])
    assert data["evidence"]["baseline"]["suppressed"] == data["coverage"]["baseline_suppressed"]
