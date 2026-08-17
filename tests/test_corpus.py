"""Integration test corpus: snapshot-based regression tests.

Each directory under tests/fixtures/corpus/ is a self-contained agent setup.
An expected-findings.json file records the exact findings harness-eval should
produce. Any drift fails the build with a readable diff.

To update snapshots after intentional rule changes:

    uv run scripts/update_corpus_snapshots.py
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from harness_eval.core.setup import discover_setup
from harness_eval.inspection.engine import inspect_setup

CORPUS_DIR = Path(__file__).parent / "fixtures" / "corpus"


def _corpus_fixtures() -> list[Path]:
    if not CORPUS_DIR.is_dir():
        return []
    return sorted(d for d in CORPUS_DIR.iterdir() if d.is_dir() and not d.name.startswith("."))


def _get_findings(fixture_path: Path) -> list[dict]:
    setup = discover_setup(fixture_path.name, str(fixture_path))
    results = inspect_setup(setup)
    findings = []
    for result in results:
        for diag in result.diagnostics:
            findings.append(
                {
                    "rule_id": diag.rule_id,
                    "severity": (
                        diag.severity.value
                        if hasattr(diag.severity, "value")
                        else str(diag.severity)
                    ),
                    "target_name": result.target_name,
                    "target_type": result.target_type,
                    "message": diag.message,
                }
            )
    # Exclude environment-dependent findings (YARA availability varies by install extras)
    findings = [f for f in findings if f["rule_id"] != "security/yara-signatures"]
    findings.sort(key=lambda f: (f["rule_id"], f["target_name"], f["message"]))
    return findings


@pytest.fixture(params=_corpus_fixtures(), ids=lambda p: p.name)
def corpus_fixture(request) -> Path:
    return request.param


class TestCorpusSnapshots:
    def test_findings_match_snapshot(self, corpus_fixture: Path) -> None:
        snapshot_path = corpus_fixture / "expected-findings.json"
        if not snapshot_path.exists():
            pytest.skip(
                f"No snapshot for {corpus_fixture.name}. "
                f"Run: uv run scripts/update_corpus_snapshots.py"
            )

        expected = json.loads(snapshot_path.read_text())
        actual = _get_findings(corpus_fixture)

        if actual != expected:
            expected_ids = {f["rule_id"] for f in expected}
            actual_ids = {f["rule_id"] for f in actual}
            added = actual_ids - expected_ids
            removed = expected_ids - actual_ids

            msg_parts = [
                f"Snapshot mismatch for {corpus_fixture.name}.",
                f"Expected {len(expected)} findings, got {len(actual)}.",
            ]
            if added:
                msg_parts.append(f"New rules firing: {sorted(added)}")
            if removed:
                msg_parts.append(f"Rules no longer firing: {sorted(removed)}")
            msg_parts.append("Run `uv run scripts/update_corpus_snapshots.py` to update.")
            pytest.fail("\n".join(msg_parts))
