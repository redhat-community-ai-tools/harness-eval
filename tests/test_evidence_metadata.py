"""Scan evidence: fingerprint, revision, rule and config digests in lint output."""

from __future__ import annotations

import hashlib
import json
import re
import shutil
from pathlib import Path

from click.testing import CliRunner

import harness_eval.inspection  # noqa: F401 — registers all rules
from harness_eval.baseline import create_baseline
from harness_eval.cli import cli
from harness_eval.core.setup import discover_setup
from harness_eval.inspection.engine import build_scan_catalog, inspect_setup
from harness_eval.inspection.registry import RuleCatalog, get_all_rules
from harness_eval.output.metadata import EvalMetadata
from harness_eval.output.provenance import (
    ScanEvidence,
    collect_scan_evidence,
    config_digest,
    git_revision,
    rules_digest,
)
from harness_eval.output.sarif import format_sarif

FIXTURES = Path(__file__).parent / "fixtures"
CLEAN = FIXTURES / "sample-setup-a"
DIRTY = FIXTURES / "security-issues"
SHA = "a" * 40
SHA2 = "b" * 40
HEX40 = re.compile(r"^[0-9a-f]{40}$")


def _fake_git(
    root: Path, *, head: str, loose: dict[str, str] | None = None, packed: str = ""
) -> Path:
    git = root / ".git"
    git.mkdir(parents=True)
    (git / "HEAD").write_text(head + "\n")
    for ref, sha in (loose or {}).items():
        p = git / ref
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(sha + "\n")
    if packed:
        (git / "packed-refs").write_text(packed)
    return git


# --- git_revision ------------------------------------------------------------------


def test_revision_from_loose_ref(tmp_path: Path) -> None:
    _fake_git(tmp_path, head="ref: refs/heads/main", loose={"refs/heads/main": SHA})
    assert git_revision(tmp_path) == SHA


def test_revision_from_packed_refs(tmp_path: Path) -> None:
    _fake_git(
        tmp_path,
        head="ref: refs/heads/feature/x",
        packed=(
            f"# pack-refs with: peeled fully-peeled sorted\n{SHA2} refs/heads/feature/x\n^{SHA}\n"
        ),
    )
    assert git_revision(tmp_path) == SHA2


def test_detached_head(tmp_path: Path) -> None:
    _fake_git(tmp_path, head=SHA)
    assert git_revision(tmp_path) == SHA


def test_revision_found_from_a_subdirectory_and_a_file(tmp_path: Path) -> None:
    _fake_git(tmp_path, head="ref: refs/heads/main", loose={"refs/heads/main": SHA})
    sub = tmp_path / "a" / "b"
    sub.mkdir(parents=True)
    (sub / "CLAUDE.md").write_text("# x\n")
    assert git_revision(sub) == SHA
    assert git_revision(sub / "CLAUDE.md") == SHA


def test_worktree_pointer_and_commondir(tmp_path: Path) -> None:
    main = tmp_path / "main"
    _fake_git(main, head="ref: refs/heads/main", loose={"refs/heads/main": SHA})
    wt_git = main / ".git" / "worktrees" / "wt"
    wt_git.mkdir(parents=True)
    (wt_git / "HEAD").write_text("ref: refs/heads/topic\n")
    (wt_git / "commondir").write_text("../..\n")
    (main / ".git" / "refs" / "heads" / "topic").write_text(SHA2 + "\n")
    wt = tmp_path / "wt"
    wt.mkdir()
    (wt / ".git").write_text(f"gitdir: {wt_git}\n")
    assert git_revision(wt) == SHA2


def test_no_git_or_garbage_yields_none(tmp_path: Path) -> None:
    assert git_revision(tmp_path) is None
    _fake_git(tmp_path, head="not a sha")
    assert git_revision(tmp_path) is None
    (tmp_path / ".git" / "HEAD").write_text("ref: refs/heads/missing\n")
    assert git_revision(tmp_path) is None


# --- digests -----------------------------------------------------------------------


def test_rules_digest_is_order_independent_and_sensitive_to_the_set() -> None:
    rules = get_all_rules()
    assert rules_digest(rules) == rules_digest(list(reversed(rules)))
    assert rules_digest(rules) != rules_digest(rules[:-1])
    assert HEX40.match(rules_digest(rules)) is None and len(rules_digest(rules)) == 64


def test_config_digest_is_order_independent() -> None:
    assert config_digest({"a": "error", "b": "off"}) == config_digest({"b": "off", "a": "error"})
    assert config_digest({"a": "error"}) != config_digest({"a": "warning"})
    assert config_digest(None) == config_digest({})


def test_build_scan_catalog_reflects_target_rules(tmp_path: Path) -> None:
    (tmp_path / "CLAUDE.md").write_text("# p\n")
    rules_dir = tmp_path / ".harness-eval" / "rules"
    rules_dir.mkdir(parents=True)
    (rules_dir / "no-sudo.yaml").write_text(
        "id: custom/no-sudo\nseverity: error\ndescription: d\nsuggestion: s\n"
        "target: skill\ncategory: security\npatterns:\n  - label: sudo\n    regex: 'sudo'\n"
        "message: found\n"
    )
    without = build_scan_catalog(str(tmp_path))
    with_target = build_scan_catalog(str(tmp_path), load_target_yaml=True)
    assert len(with_target.all()) == len(without.all()) + 1
    assert rules_digest(with_target.all()) != rules_digest(without.all())
    assert isinstance(with_target, RuleCatalog)


# --- collect_scan_evidence ---------------------------------------------------------


def test_evidence_binds_fingerprint_revision_and_catalog(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    shutil.copytree(CLEAN, root)
    _fake_git(root, head="ref: refs/heads/main", loose={"refs/heads/main": SHA})
    setup = discover_setup("s", str(root), exclude=("vendor/**",))
    catalog = build_scan_catalog(str(root))
    ev = collect_scan_evidence(
        setup, catalog, {"x": "error"}, preset="recommended", excludes=("vendor/**",)
    )
    assert ev.setup_fingerprint == setup.fingerprint
    assert ev.vcs_revision == SHA
    assert ev.rules_digest == rules_digest(catalog.all())
    assert ev.rules_count == len(catalog.all())
    assert ev.config_digest == config_digest({"x": "error"})
    assert ev.preset == "recommended"
    assert ev.inventory_files == len(setup.inventory_paths or ())
    assert ev.excludes == ("vendor/**",)
    assert ev.limits["max_files"] == 100_000
    assert ev.baseline_digest is None and ev.baseline_suppressed == 0
    d = ev.to_dict()
    assert d["vcs"]["revision"] == SHA and d["rules"]["target_rules_loaded"] is False


# --- CLI output --------------------------------------------------------------------


def test_lint_json_carries_evidence() -> None:
    result = CliRunner().invoke(cli, ["harness-lint", str(CLEAN), "--format", "json"])
    assert result.exit_code == 0, result.output
    ev = json.loads(result.output)["metadata"]["evidence"]
    assert ev["setup_fingerprint"] == discover_setup("s", str(CLEAN)).fingerprint
    assert ev["rules"]["count"] == len(get_all_rules())
    assert ev["config"]["preset"] == "recommended"
    assert ev["vcs"]["revision"] is None or HEX40.match(ev["vcs"]["revision"])
    assert ev["inventory"]["files"] > 0


def test_lint_json_counts_baseline_suppressions(tmp_path: Path) -> None:
    from harness_eval.config.presets import PRESETS

    setup = discover_setup("d", str(DIRTY))
    results = inspect_setup(setup, PRESETS["recommended"])
    total = sum(len(r.diagnostics) for r in results)
    assert total > 0
    bl = tmp_path / "baseline.json"
    bl.write_text(json.dumps(create_baseline(results)))
    result = CliRunner().invoke(
        cli, ["harness-lint", str(DIRTY), "--format", "json", "--baseline", str(bl)]
    )
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert data["metadata"]["evidence"]["baseline"]["suppressed"] == total
    assert (
        data["metadata"]["evidence"]["baseline"]["digest"]
        == hashlib.sha256(bl.read_bytes()).hexdigest()
    )
    assert data["inspection"]["summary"]["errors"] == 0


def test_lint_terminal_prints_evidence_line() -> None:
    result = CliRunner().invoke(cli, ["harness-lint", str(CLEAN)])
    assert result.exit_code == 0
    assert re.search(
        r"Fingerprint: [0-9a-f]{12} \| Revision: (n/a|[0-9a-f]{12}) \| Rules digest: [0-9a-f]{12}",
        result.output,
    )


def test_single_file_lint_has_no_evidence_block() -> None:
    result = CliRunner().invoke(cli, ["harness-lint", str(CLEAN / "CLAUDE.md"), "--format", "json"])
    assert result.exit_code == 0, result.output
    assert "evidence" not in json.loads(result.output)["metadata"]


def test_sarif_carries_provenance(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    shutil.copytree(CLEAN, root)
    _fake_git(root, head="ref: refs/heads/main", loose={"refs/heads/main": SHA})
    for cmd in (
        ["harness-lint", str(root), "--format", "sarif"],
        ["harness-gate", str(root), "--format", "sarif"],
    ):
        result = CliRunner().invoke(cli, cmd)
        assert result.exit_code == 0, result.output
        run = json.loads(result.output)["runs"][0]
        assert run["versionControlProvenance"] == [{"revisionId": SHA}]
        assert run["properties"]["setupFingerprint"] == discover_setup("s", str(root)).fingerprint
        assert len(run["properties"]["rulesDigest"]) == 64
    assert json.loads(result.output)["runs"][0]["properties"]["preset"] == "gate"


def test_sarif_without_evidence_is_unchanged() -> None:
    doc = format_sarif([], EvalMetadata(version="x"))
    assert "versionControlProvenance" not in doc["runs"][0]
    assert "properties" not in doc["runs"][0]


def test_evidence_to_dict_shape() -> None:
    ev = ScanEvidence(
        setup_fingerprint="f" * 64,
        scan_root="/r",
        vcs_revision=None,
        rules_digest="d" * 64,
        rules_count=3,
        target_rules_loaded=True,
        config_digest="c" * 64,
    )
    assert set(ev.to_dict()) == {
        "setup_fingerprint",
        "scan_root",
        "vcs",
        "rules",
        "config",
        "baseline",
        "inventory",
    }
    assert (
        EvalMetadata(version="1", evidence=ev).to_dict()["evidence"]["rules"]["target_rules_loaded"]
        is True
    )
