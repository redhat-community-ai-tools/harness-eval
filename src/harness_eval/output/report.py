"""Report generation: structured output for assess results."""

from __future__ import annotations

import json
from collections import defaultdict

from harness_eval.analysis.system import SystemReport
from harness_eval.inspection.types import InspectionResult


def _get_type_display(detected_tools: tuple[str, ...] = ()) -> dict[str, str]:
    base = {
        "skill": "Skills",
        "command": "Commands",
        "hooks": "Hooks",
        "agent": "Agents",
        "rule": "Rules",
        "output_style": "Output Styles",
    }
    multi_tool = len(detected_tools) > 1
    has_cursor_only = detected_tools == ("Cursor",)
    if has_cursor_only:
        base["claude_md"] = "Cursor Rules"
    elif multi_tool:
        base["claude_md"] = "System Instructions"
    elif "Claude Code" in detected_tools:
        base["claude_md"] = "CLAUDE.md"
    elif "Gemini CLI" in detected_tools:
        base["claude_md"] = "GEMINI.md"
    elif "OpenCode" in detected_tools:
        base["claude_md"] = "AGENTS.md"
    else:
        base["claude_md"] = "System Instructions"
    base["mcp_config"] = "MCP Configs"
    return base


_TYPE_ORDER = [
    "skill",
    "command",
    "hooks",
    "claude_md",
    "agent",
    "mcp_config",
    "rule",
    "output_style",
]


def format_header(title: str, **stats: str | int) -> str:
    lines = [f"\n{'=' * 60}", title, f"{'=' * 60}"]
    for label, value in stats.items():
        lines.append(f"{label}: {value}")
    return "\n".join(lines)


def format_section(title: str) -> str:
    return f"\n{title}:\n{'─' * 60}"


def format_finding_line(
    rule_id: str, severity: str, message: str, suggestion: str | None = None
) -> str:
    label = "FAIL" if severity == "error" else ("INFO" if severity == "info" else "WARNING")
    short_id = rule_id.split("/")[-1]
    line = f"    {label:<8} {short_id}: {message}"
    if suggestion:
        line += f"\n             Fix: {suggestion}"
    return line


def _shorten_rule_id(rule_id: str) -> str:
    parts = rule_id.split("/", 1)
    return parts[1] if len(parts) > 1 else rule_id


def _compress_findings(diagnostics: list) -> list[str]:
    """Group identical rule findings into compressed lines."""
    by_rule: dict[str, list] = defaultdict(list)
    for d in diagnostics:
        by_rule[d.rule_id].append(d)

    compressed: list[str] = []
    for rule_id, findings in by_rule.items():
        severity = findings[0].severity.value
        label = "FAIL" if severity == "error" else ("INFO" if severity == "info" else "WARNING")
        short_id = _shorten_rule_id(rule_id)
        if len(findings) <= 2:
            for d in findings:
                compressed.append(f"  {label:<8} {short_id}: {d.message}")
                if d.suggestion:
                    compressed.append(f"           Fix: {d.suggestion}")
        else:
            compressed.append(f"  {label:<8} {short_id}: {len(findings)} findings")
            for d in findings:
                compressed.append(f"           {d.message}")
            if findings[0].suggestion:
                compressed.append(f"           Fix: {findings[0].suggestion}")
    return compressed


def format_terminal(
    system: SystemReport,
    inspection_results: list[InspectionResult],
) -> str:
    """Format a full assessment report for terminal output."""
    lines: list[str] = []

    lines.append(f"{'=' * 60}")
    lines.append(f"Setup Assessment: {system.setup_name}")
    lines.append(f"{'=' * 60}")
    if system.detected_tools:
        lines.append(f"Detected tools: {', '.join(system.detected_tools)}")
    lines.append(f"Components: {system.component_count}")
    lines.append(f"Total tokens: {system.budget.total_tokens}")
    lines.append("")

    total_errors = sum(r.error_count for r in inspection_results)
    total_warnings = sum(r.warning_count for r in inspection_results)
    total_fixable = sum(r.fixable_count for r in inspection_results)
    all_diags = [d for r in inspection_results for d in r.diagnostics]

    summary_parts = []
    if total_errors:
        summary_parts.append(f"{total_errors} error{'s' if total_errors != 1 else ''}")
    if total_warnings:
        summary_parts.append(f"{total_warnings} warning{'s' if total_warnings != 1 else ''}")
    if not summary_parts:
        summary_parts.append("no issues found")

    fixable_note = f" ({total_fixable} auto-fixable)" if total_fixable else ""
    lines.append(f"Summary: {', '.join(summary_parts)}{fixable_note}")

    top_issues = sorted(
        all_diags,
        key=lambda d: (0 if d.severity.value == "error" else 1, d.location.start_line or 0),
    )[:3]
    if top_issues:
        lines.append("Top issues:")
        for i, d in enumerate(top_issues, 1):
            sev = (
                "ERROR"
                if d.severity.value == "error"
                else ("INFO" if d.severity.value == "info" else "WARNING")
            )
            loc = (
                f"{d.location.file}:{d.location.start_line}"
                if d.location.start_line
                else d.location.file
            )
            lines.append(f"  {i}. [{sev}] {d.rule_id} in {loc}")
    lines.append("")

    lines.append("Legend:")
    lines.append(f"{'─' * 60}")
    lines.append("  PASS     Rule checked, no issues found")
    lines.append("  FAIL     Rule checked, error found (must fix)")
    lines.append("  WARNING  Rule checked, potential issue (should review)")
    lines.append("  SKIP     Check was skipped (missing dependency or N/A)")
    lines.append("")

    tool_set = set(system.detected_tools)
    tool_set.discard("Third-party modules")
    if not tool_set:
        always_label = "system instructions, hooks"
    elif tool_set == {"Cursor"}:
        always_label = "cursor rules, hooks"
    elif len(tool_set) > 1:
        always_label = "system instructions, hooks"
    elif "Gemini CLI" in tool_set:
        always_label = "GEMINI.md"
    elif "OpenCode" in tool_set:
        always_label = "AGENTS.md"
    elif "Copilot" in tool_set:
        always_label = "system instructions, hooks"
    else:
        always_label = "CLAUDE.md, hooks"

    lines.append("Token Budget:")
    lines.append(f"{'─' * 60}")
    lines.append(
        f"  Always-loaded ({always_label}): "
        f"{system.budget.always_loaded_tokens} tokens "
        f"({system.budget.always_loaded_ratio:.0%})"
    )
    lines.append(
        f"  On-demand (skills, commands, agents): "
        f"{system.budget.on_demand_tokens} tokens "
        f"({1 - system.budget.always_loaded_ratio:.0%})"
    )
    if system.budget.by_type:
        lines.append("  By type:")
        for type_name, tokens in sorted(
            system.budget.by_type.items(), key=lambda x: x[1], reverse=True
        ):
            pct = tokens / system.budget.total_tokens * 100 if system.budget.total_tokens else 0
            lines.append(f"    {type_name:<12} {tokens:>6} tokens ({pct:.0f}%)")

    if system.triggers.skill_count > 0:
        lines.append("")
        lines.append("Trigger Analysis:")
        lines.append(f"{'─' * 60}")
        lines.append(
            f"  {system.triggers.skills_with_description}/{system.triggers.skill_count} "
            f"skills have descriptions"
        )
        if system.triggers.missing_use_when:
            lines.append(
                f"  {len(system.triggers.missing_use_when)} skills lack "
                f"activation context ('use when' phrasing):"
            )
            for name in system.triggers.missing_use_when:
                lines.append(f"    - {name}")
        if system.triggers.overlap_pairs:
            lines.append(f"  {len(system.triggers.overlap_pairs)} trigger overlap(s) detected:")
            for name_a, name_b, sim in system.triggers.overlap_pairs:
                lines.append(f"    - {name_a} <-> {name_b} ({sim:.0%} similar)")

    if system.dependencies.broken_refs:
        lines.append("")
        lines.append("Dependencies:")
        lines.append(f"{'─' * 60}")
        lines.append(f"  {len(system.dependencies.broken_refs)} broken reference(s):")
        for edge in system.dependencies.broken_refs:
            lines.append(
                f"    - {edge.source_type}/{edge.source_name} "
                f"references missing {edge.target_type}/{edge.target_name}"
            )

    if system.findings:
        lines.append("")
        lines.append("Findings:")
        lines.append(f"{'─' * 60}")
        for finding in system.findings:
            lines.append(f"  WARNING  {finding}")

    total_errors = sum(r.error_count for r in inspection_results)
    total_warnings = sum(r.warning_count for r in inspection_results)
    if inspection_results:
        lines.append("")
        lines.append("Inspection Results:")
        lines.append(f"{'─' * 60}")
        lines.append(
            f"  {len(inspection_results)} components inspected, "
            f"{total_errors} errors, {total_warnings} warnings"
        )

        grouped: dict[str, list[InspectionResult]] = defaultdict(list)
        for r in inspection_results:
            grouped[r.target_type].append(r)

        all_type_keys = [k for k in _TYPE_ORDER if k in grouped]
        all_type_keys += [k for k in grouped if k not in _TYPE_ORDER]

        for type_key in all_type_keys:
            results = grouped[type_key]
            label = _get_type_display(system.detected_tools).get(type_key, type_key)
            lines.append("")
            lines.append(f"  {label} ({len(results)})")
            lines.append(f"  {'─' * 56}")
            for r in results:
                if not r.diagnostics:
                    if r.rules_run:
                        rule_names = ", ".join(_shorten_rule_id(rr.rule_id) for rr in r.rules_run)
                        lines.append(f"    {r.target_name:<40} PASS ({len(r.rules_run)} rules)")
                        lines.append(f"      checked: {rule_names}")
                    else:
                        lines.append(f"    {r.target_name:<40} PASS")
                else:
                    parts = []
                    if r.error_count:
                        parts.append(f"{r.error_count} error{'s' if r.error_count != 1 else ''}")
                    if r.warning_count:
                        parts.append(
                            f"{r.warning_count} warning{'s' if r.warning_count != 1 else ''}"
                        )
                    status = ", ".join(parts)
                    lines.append(f"    {r.target_name:<40} {status}")
                    for cline in _compress_findings(r.diagnostics):
                        lines.append(f"      {cline}")

    if system.uncategorized_files:
        lines.append("")
        lines.append("Uncategorized Files (security-only rules applied):")
        lines.append(f"{'─' * 60}")
        for f in system.uncategorized_files:
            lines.append(f"  {f}")

    lines.append("")
    return "\n".join(lines)


def _build_json_inspection(inspection_results: list[InspectionResult]) -> dict:
    total_errors = sum(r.error_count for r in inspection_results)
    total_warnings = sum(r.warning_count for r in inspection_results)

    grouped: dict[str, list[InspectionResult]] = defaultdict(list)
    for r in inspection_results:
        grouped[r.target_type].append(r)

    result: dict = {
        "summary": {
            "total": len(inspection_results),
            "errors": total_errors,
            "warnings": total_warnings,
        },
    }

    all_type_keys = [k for k in _TYPE_ORDER if k in grouped]
    all_type_keys += [k for k in grouped if k not in _TYPE_ORDER]

    for type_key in all_type_keys:
        result[type_key] = [
            {
                "name": r.target_name,
                "status": "pass" if not r.diagnostics else "fail",
                "errors": r.error_count,
                "warnings": r.warning_count,
                "rules": [
                    {
                        "rule": rr.rule_id,
                        "result": "pass" if rr.passed else "fail",
                    }
                    for rr in r.rules_run
                ],
                "findings": [
                    {
                        "rule": d.rule_id,
                        "severity": d.severity.value,
                        "message": d.message,
                        **({"suggestion": d.suggestion} if d.suggestion else {}),
                    }
                    for d in r.diagnostics
                ],
            }
            for r in grouped[type_key]
        ]

    return result


def format_json(
    system: SystemReport,
    inspection_results: list[InspectionResult],
) -> str:
    """Format a full assessment report as JSON."""
    output = {
        "setup": system.setup_name,
        "detected_tools": list(system.detected_tools),
        "component_count": system.component_count,
        "budget": {
            "total_tokens": system.budget.total_tokens,
            "always_loaded": system.budget.always_loaded_tokens,
            "on_demand": system.budget.on_demand_tokens,
            "always_loaded_ratio": round(system.budget.always_loaded_ratio, 2),
            "by_type": system.budget.by_type,
            "heaviest": system.budget.heaviest_component_name,
        },
        "triggers": {
            "skill_count": system.triggers.skill_count,
            "with_description": system.triggers.skills_with_description,
            "missing_use_when": system.triggers.missing_use_when,
            "overlaps": [
                {"a": a, "b": b, "similarity": round(s, 2)}
                for a, b, s in system.triggers.overlap_pairs
            ],
        },
        "dependencies": {
            "total_edges": len(system.dependencies.edges),
            "broken": [
                {
                    "source": f"{e.source_type}/{e.source_name}",
                    "target": f"{e.target_type}/{e.target_name}",
                }
                for e in system.dependencies.broken_refs
            ],
        },
        "findings": system.findings,
        "inspection": _build_json_inspection(inspection_results),
    }
    if system.uncategorized_files:
        output["uncategorized_files"] = system.uncategorized_files
    return json.dumps(output, indent=2)


def format_report_card(
    results: list[InspectionResult],
) -> dict:
    """Generate a unified report card aggregating all inspection results.

    Returns a dict (not JSON string) so the caller can add metadata.
    """
    total_errors = sum(r.error_count for r in results)
    total_warnings = sum(r.warning_count for r in results)
    total_findings = total_errors + total_warnings

    if total_errors > 0:
        verdict = "BLOCKED"
    elif total_warnings > 0:
        verdict = "NEEDS_WORK"
    else:
        verdict = "CLEAN"

    by_category: dict[str, int] = defaultdict(int)
    for r in results:
        for d in r.diagnostics:
            category = d.rule_id.split("/")[0] if "/" in d.rule_id else "other"
            by_category[category] += 1

    components = []
    for r in results:
        components.append(
            {
                "name": r.target_name,
                "type": r.target_type,
                "verdict": "pass" if r.error_count == 0 else "fail",
                "errors": r.error_count,
                "warnings": r.warning_count,
                "tokens": r.tokens,
            }
        )

    certification = _compute_certification(results)
    grade = _compute_grade(total_errors, total_warnings)

    return {
        "verdict": verdict,
        "grade": grade,
        "certification": certification,
        "summary": {
            "components_scanned": len(results),
            "total_errors": total_errors,
            "total_warnings": total_warnings,
            "total_findings": total_findings,
        },
        "by_category": dict(by_category),
        "components": components,
    }


def _compute_grade(total_errors: int, total_warnings: int) -> str:
    """Compute a letter grade from error/warning counts.

    - A: 0 errors, 0 warnings
    - B: 0 errors, warnings < 3
    - C: 0 errors
    - D: errors < 5
    - F: errors >= 5
    """
    if total_errors == 0 and total_warnings == 0:
        return "A"
    if total_errors == 0 and total_warnings < 3:
        return "B"
    if total_errors == 0:
        return "C"
    if total_errors < 5:
        return "D"
    return "F"


def _compute_certification(
    results: list[InspectionResult],
) -> dict:
    """Compute setup certification tiers.

    Tiers are hierarchical: Hardened requires Verified, Verified requires Basic.

    Basic: lint passes with 0 errors.
    Verified: Basic + no quality warnings (imprecise, unfinished, generic advice).
    Hardened: Verified + no security findings.
    """
    total_errors = sum(r.error_count for r in results)

    quality_rule_prefixes = (
        "quality/",
        "content/orphan",
        "content/total-context",
        "content/permission-escalation",
    )
    quality_warnings = sum(
        1
        for r in results
        for d in r.diagnostics
        if d.severity.value == "warning"
        and any(d.rule_id.startswith(p) for p in quality_rule_prefixes)
    )

    security_errors = sum(
        1
        for r in results
        for d in r.diagnostics
        if d.rule_id.startswith("security/") and d.severity.value == "error"
    )

    basic_passed = total_errors == 0
    verified_passed = basic_passed and quality_warnings == 0
    hardened_passed = verified_passed and security_errors == 0

    if hardened_passed:
        tier = "HARDENED"
    elif verified_passed:
        tier = "VERIFIED"
    elif basic_passed:
        tier = "BASIC"
    else:
        tier = "NONE"

    return {
        "tier": tier,
        "basic": {
            "passed": basic_passed,
            "reason": "0 lint errors" if basic_passed else f"{total_errors} lint errors",
        },
        "verified": {
            "passed": verified_passed,
            "reason": (
                "no quality warnings"
                if verified_passed
                else (
                    f"{total_errors} lint errors"
                    if not basic_passed
                    else f"{quality_warnings} quality warnings"
                )
            ),
        },
        "hardened": {
            "passed": hardened_passed,
            "reason": (
                "no security findings"
                if hardened_passed
                else (
                    f"{total_errors} lint errors"
                    if not basic_passed
                    else (
                        f"{quality_warnings} quality warnings"
                        if not verified_passed
                        else f"{security_errors} security findings"
                    )
                )
            ),
        },
    }
