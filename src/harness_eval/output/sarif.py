"""SARIF v2.1.0 output for CI integration (GitHub code scanning, etc.)."""

from __future__ import annotations

from harness_eval.inspection.types import Finding, InspectionResult, Severity
from harness_eval.output.metadata import EvalMetadata

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"

_SEVERITY_MAP = {
    Severity.ERROR: "error",
    Severity.WARNING: "warning",
    Severity.INFO: "note",
}


def _build_rule_descriptors(findings: list[Finding]) -> list[dict]:
    from harness_eval.inspection.registry import get_rule

    seen: dict[str, dict] = {}
    for f in findings:
        if f.rule_id in seen:
            continue
        props: dict = {"tags": [f.category.value]}
        rule = get_rule(f.rule_id)
        if rule and rule.meta.frameworks:
            props["frameworks"] = rule.meta.frameworks
        descriptor: dict = {
            "id": f.rule_id,
            "shortDescription": {"text": f.rule_id},
            "properties": props,
        }
        seen[f.rule_id] = descriptor
    return list(seen.values())


def _relativize_path(path: str) -> str:
    import os

    try:
        return os.path.relpath(path)
    except ValueError:
        return path


def _build_result(finding: Finding, rule_index: dict[str, int]) -> dict:
    result: dict = {
        "ruleId": finding.rule_id,
        "ruleIndex": rule_index.get(finding.rule_id, 0),
        "level": _SEVERITY_MAP.get(finding.severity, "note"),
        "message": {"text": finding.message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": _relativize_path(finding.location.file),
                        "uriBaseId": "%SRCROOT%",
                    },
                    "region": {"startLine": finding.location.start_line or 1},
                },
            }
        ],
    }
    if finding.fix:
        result["fixes"] = [
            {
                "description": {"text": finding.fix.description},
            }
        ]
    if finding.reachability:
        result.setdefault("properties", {})["reachability"] = finding.reachability
    return result


def format_sarif(
    inspection_results: list[InspectionResult],
    metadata: EvalMetadata | None = None,
) -> dict:
    all_findings = [d for r in inspection_results for d in r.diagnostics]

    rules = _build_rule_descriptors(all_findings)
    rule_index = {r["id"]: i for i, r in enumerate(rules)}

    version = metadata.version if metadata else "dev"

    run: dict = {
        "tool": {
            "driver": {
                "name": "harness-eval",
                "version": version,
                "informationUri": "https://github.com/redhat-community-ai-tools/harness-eval",
                "rules": rules,
            },
        },
        "results": [_build_result(f, rule_index) for f in all_findings],
        "originalUriBaseIds": {
            "%SRCROOT%": {"uri": "file:///" + _relativize_path(".") + "/"},
        },
    }

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [run],
    }
