# /// script
# requires-python = ">=3.11"
# dependencies = ["harness-eval"]
# ///
"""Run security-focused setup assessment and output security-only JSON."""

import json
import sys
from pathlib import Path


def main() -> None:
    setup_path = sys.argv[1] if len(sys.argv) > 1 else "."
    user_config = sys.argv[2] if len(sys.argv) > 2 and sys.argv[2] != "-" else None

    from harness_eval.config.presets import SECURITY
    from harness_eval.core.setup import discover_setup
    from harness_eval.inspection.engine import inspect_setup
    from harness_eval.inspection.registry import get_all_rules

    setup = discover_setup(name=Path(setup_path).name, path=setup_path, user_config_dir=user_config)
    results = inspect_setup(setup, SECURITY)

    skip_rules = {"security/yara-signatures", "security/cve-lookup"}
    skip_notices: list[str] = []
    seen_skip: set[str] = set()

    for r in results:
        for d in r.diagnostics:
            if (
                d.rule_id in skip_rules
                and d.severity.value == "info"
                and d.message not in seen_skip
            ):
                seen_skip.add(d.message)
                skip_notices.append(d.message)

    findings = []
    for r in results:
        filtered = [
            d for d in r.diagnostics if not (d.rule_id in skip_rules and d.severity.value == "info")
        ]
        if filtered:
            findings.append(
                {
                    "component": f"{r.target_type}/{r.target_name}",
                    "errors": sum(1 for d in filtered if d.severity.value == "error"),
                    "warnings": sum(1 for d in filtered if d.severity.value == "warning"),
                    "details": [
                        {"rule": d.rule_id, "severity": d.severity.value, "message": d.message}
                        for d in filtered
                    ],
                }
            )

    raw_errors = sum(f["errors"] for f in findings)
    raw_warnings = sum(f["warnings"] for f in findings)

    if raw_errors == 0 and raw_warnings == 0:
        risk = "SAFE"
    elif raw_errors == 0:
        risk = "CAUTION"
    else:
        risk = "UNSAFE"

    rules_checked = [
        {"id": r.meta.id, "description": r.meta.description}
        for r in get_all_rules()
        if r.meta.id in SECURITY and SECURITY[r.meta.id] != "off"
    ]

    output: dict[str, object] = {
        "security_scan": True,
        "setup": setup.name,
        "risk_assessment": risk,
        "adjudicated": False,
        "components_scanned": len(results),
        "rules_checked": rules_checked,
        "raw_errors": raw_errors,
        "raw_warnings": raw_warnings,
        "findings": findings,
    }
    if skip_notices:
        output["skipped_checks"] = skip_notices

    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
