"""Baseline support for incremental adoption.

Create a snapshot of current findings so teams can adopt harness-eval
without fixing every pre-existing issue first. New findings are surfaced
while baselined ones are suppressed.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from harness_eval.inspection.types import Finding, InspectionResult


def finding_key(finding: Finding, scan_root: Path | str) -> tuple[str, str, str]:
    """Identity of a finding that survives moving the tree: the rule, the
    file relative to the scan root, and a hash of the message with every
    occurrence of the root path blanked. Two checkouts of the same revision
    yield the same keys, which is what comparing a head against its base needs.
    """
    root = Path(scan_root).resolve()
    file = finding.location.file
    try:
        rel = str(Path(file).resolve().relative_to(root))
    except (ValueError, OSError):
        rel = file
    message = finding.message.replace(str(root), "<root>").replace(str(scan_root), "<root>")
    return (finding.rule_id, rel, hashlib.sha256(message.encode()).hexdigest()[:16])


def create_baseline(results: list[InspectionResult]) -> dict:
    """Build a baseline dict from current inspection results."""
    findings = []
    for r in results:
        for d in r.diagnostics:
            findings.append(
                {
                    "rule_id": d.rule_id,
                    "file": d.location.file,
                    "message_hash": hashlib.sha256(d.message.encode()).hexdigest()[:16],
                }
            )
    return {"version": "1.0", "findings": findings}


def filter_baselined(
    results: list[InspectionResult],
    baseline: dict,
) -> list[InspectionResult]:
    """Remove findings that match the baseline, returning only new ones."""
    baseline_set = {
        (f["rule_id"], f["file"], f["message_hash"]) for f in baseline.get("findings", [])
    }
    filtered = []
    for r in results:
        new_diags = [
            d
            for d in r.diagnostics
            if (
                d.rule_id,
                d.location.file,
                hashlib.sha256(d.message.encode()).hexdigest()[:16],
            )
            not in baseline_set
        ]
        filtered.append(
            InspectionResult(
                target_path=r.target_path,
                target_name=r.target_name,
                tokens=r.tokens,
                target_type=r.target_type,
                diagnostics=new_diags,
                rules_run=r.rules_run,
                error_count=sum(1 for d in new_diags if d.severity.value == "error"),
                warning_count=sum(1 for d in new_diags if d.severity.value == "warning"),
                info_count=sum(1 for d in new_diags if d.severity.value == "info"),
            )
        )
    return filtered
