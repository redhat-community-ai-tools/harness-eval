# /// script
# requires-python = ">=3.11"
# dependencies = ["harness-eval"]
# ///
"""Regenerate expected-findings snapshots for the integration test corpus.

Run this after intentional rule changes to update the golden files:

    uv run scripts/update_corpus_snapshots.py

Each fixture directory under tests/fixtures/corpus/ gets an
expected-findings.json containing the sorted, deterministic output
of harness-eval's lint + security scans.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from harness_eval.core.setup import discover_setup
from harness_eval.inspection.engine import inspect_setup

CORPUS_DIR = Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "corpus"


def snapshot_findings(fixture_path: Path) -> list[dict]:
    """Run lint on a fixture and return sorted findings as dicts."""
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


def main() -> None:
    if not CORPUS_DIR.is_dir():
        print(f"Corpus directory not found: {CORPUS_DIR}", file=sys.stderr)
        sys.exit(1)

    fixtures = sorted(d for d in CORPUS_DIR.iterdir() if d.is_dir() and not d.name.startswith("."))
    if not fixtures:
        print("No fixtures found in corpus directory.", file=sys.stderr)
        sys.exit(1)

    updated = 0
    for fixture in fixtures:
        findings = snapshot_findings(fixture)
        snapshot_path = fixture / "expected-findings.json"
        snapshot_path.write_text(json.dumps(findings, indent=2, sort_keys=True) + "\n")
        print(f"  {fixture.name}: {len(findings)} findings")
        updated += 1

    print(f"\nUpdated {updated} snapshots in {CORPUS_DIR}")


if __name__ == "__main__":
    main()
