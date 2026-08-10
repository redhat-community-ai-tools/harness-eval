"""harness-eval-security command."""

from __future__ import annotations

import json as json_mod
import time
from dataclasses import dataclass
from pathlib import Path

import click

from harness_eval.cli import cli
from harness_eval.cli._helpers import emit_output
from harness_eval.core.setup import discover_setup
from harness_eval.core.types import ParsedComponent
from harness_eval.inspection.types import AdjudicatedFinding, Finding, InspectionResult, Severity
from harness_eval.output.metadata import EvalMetadata
from harness_eval.utils.redact import redact_secrets


@dataclass(frozen=True)
class _SecurityReport:
    setup_name: str
    risk: str
    adjudicated: bool
    results: list[InspectionResult]
    adjudication_map: dict[str, list[AdjudicatedFinding]]
    rubric_results: list
    skip_notices: list[str]
    metadata: EvalMetadata
    effective_errors: int
    effective_warnings: int
    false_positive_count: int
    downgraded_count: int


def _parse_adjudication_response(
    response: str, findings: list[Finding]
) -> list[AdjudicatedFinding]:
    import json
    import re

    json_match = re.search(r"```(?:json)?\s*([\s\S]*?)```", response)
    raw = json_match.group(1).strip() if json_match else response.strip()
    if not raw.startswith("["):
        bracket = raw.find("[")
        if bracket >= 0:
            raw = raw[bracket:]

    try:
        verdicts = json.loads(raw)
    except json.JSONDecodeError:
        return [
            AdjudicatedFinding(finding=f, verdict="CONFIRMED", reasoning="parse error")
            for f in findings
        ]

    result: list[AdjudicatedFinding] = []
    verdict_by_idx: dict[int, dict[str, str]] = {}
    for v in verdicts:
        idx = v.get("finding_index", -1)
        if isinstance(idx, int) and 0 <= idx < len(findings):
            verdict_by_idx[idx] = v

    for i, f in enumerate(findings):
        if i in verdict_by_idx:
            v = verdict_by_idx[i]
            verdict = v.get("verdict", "CONFIRMED").upper()
            if verdict not in ("CONFIRMED", "FALSE_POSITIVE", "DOWNGRADED"):
                verdict = "CONFIRMED"
            result.append(
                AdjudicatedFinding(
                    finding=f,
                    verdict=verdict,
                    reasoning=v.get("reasoning", ""),
                )
            )
        else:
            result.append(
                AdjudicatedFinding(finding=f, verdict="CONFIRMED", reasoning="not adjudicated")
            )

    return result


def _clean_results(
    results: list[InspectionResult],
) -> tuple[list[InspectionResult], list[str]]:
    """Filter out non-security and skip-notice findings. Returns (cleaned, skip_notices)."""
    skip_rules = {"security/yara-signatures", "security/cve-lookup"}
    non_security_rules = {"parser", "frontmatter/format-valid"}
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

    cleaned: list[InspectionResult] = []
    for r in results:
        filtered = [
            d
            for d in r.diagnostics
            if not (d.rule_id in skip_rules and d.severity.value == "info")
            and d.rule_id not in non_security_rules
        ]
        cleaned.append(
            InspectionResult(
                target_path=r.target_path,
                target_name=r.target_name,
                tokens=r.tokens,
                target_type=r.target_type,
                diagnostics=filtered,
                rules_run=r.rules_run,
                error_count=sum(1 for d in filtered if d.severity.value == "error"),
                warning_count=sum(1 for d in filtered if d.severity.value == "warning"),
                info_count=sum(1 for d in filtered if d.severity.value == "info"),
                fixable_count=sum(1 for d in filtered if d.fix is not None),
                suppression_count=r.suppression_count,
            )
        )
    return cleaned, skip_notices


def _assess_risk(
    results: list[InspectionResult],
    adjudicated: bool,
    adjudication_map: dict[str, list[AdjudicatedFinding]],
    total_semantic: int,
) -> tuple[str, int, int, int, int]:
    """Compute risk assessment. Returns (risk, effective_errors, effective_warnings, false_positives, downgraded)."""
    raw_errors = sum(r.error_count for r in results)
    raw_warnings = sum(r.warning_count for r in results)

    if adjudicated:
        all_adjudicated = [af for afs in adjudication_map.values() for af in afs]
        confirmed_errors = sum(
            1 for af in all_adjudicated if af.is_confirmed and af.finding.severity == Severity.ERROR
        )
        confirmed_warnings = sum(
            1
            for af in all_adjudicated
            if af.is_confirmed and af.finding.severity == Severity.WARNING
        )
        downgraded_count = sum(1 for af in all_adjudicated if af.verdict == "DOWNGRADED")
        false_positive_count = sum(1 for af in all_adjudicated if af.is_false_positive)

        effective_errors = confirmed_errors
        effective_warnings = confirmed_warnings + downgraded_count
    else:
        effective_errors = raw_errors
        effective_warnings = raw_warnings
        false_positive_count = 0
        downgraded_count = 0

    if effective_errors == 0 and effective_warnings == 0 and total_semantic == 0:
        risk = "SAFE"
    elif effective_errors == 0:
        risk = "CAUTION"
    else:
        risk = "UNSAFE"

    return risk, effective_errors, effective_warnings, false_positive_count, downgraded_count


def _format_json_security(report: _SecurityReport) -> str:
    raw_errors = sum(r.error_count for r in report.results)
    raw_warnings = sum(r.warning_count for r in report.results)
    total_semantic = sum(len(rr.issues) for rr in report.rubric_results)
    components_with_findings = [r for r in report.results if r.diagnostics]

    output: dict[str, object] = {
        "security_scan": True,
        "setup": report.setup_name,
        "risk_assessment": report.risk,
        "adjudicated": report.adjudicated,
        "components_scanned": len(report.results),
        "raw_errors": raw_errors,
        "raw_warnings": raw_warnings,
        "semantic_issues": total_semantic,
    }
    if report.adjudicated:
        output["confirmed_errors"] = report.effective_errors
        output["confirmed_warnings"] = report.effective_warnings
        output["false_positives"] = report.false_positive_count
        output["downgraded"] = report.downgraded_count

    findings_list = []
    for r in components_with_findings:
        comp_findings: dict[str, object] = {
            "component": f"{r.target_type}/{r.target_name}",
            "errors": r.error_count,
            "warnings": r.warning_count,
            "details": [],
        }
        adj_for_comp = report.adjudication_map.get(r.target_name, [])
        adj_by_msg = {af.finding.message: af for af in adj_for_comp}
        details = []
        for d in r.diagnostics:
            detail: dict[str, str] = {
                "rule": d.rule_id,
                "severity": d.severity.value,
                "message": d.message,
            }
            af = adj_by_msg.get(d.message)
            if af:
                detail["verdict"] = af.verdict
                detail["reasoning"] = af.reasoning
            details.append(detail)
        comp_findings["details"] = details
        findings_list.append(comp_findings)

    output["findings"] = findings_list
    output["metadata"] = report.metadata.to_dict()
    if report.skip_notices:
        output["skipped_checks"] = report.skip_notices
    if report.rubric_results:
        output["semantic_review"] = [
            {
                "component": rr.component_name,
                "type": rr.component_type,
                "issues": [
                    {
                        "category": i.category,
                        "description": i.description,
                        "evidence": i.evidence,
                        "suggestion": i.suggestion,
                        "impact": i.impact,
                    }
                    for i in rr.issues
                ],
            }
            for rr in report.rubric_results
        ]
    return json_mod.dumps(output, indent=2)


def _format_terminal_security(report: _SecurityReport) -> None:
    raw_errors = sum(r.error_count for r in report.results)
    raw_warnings = sum(r.warning_count for r in report.results)
    components_with_findings = [r for r in report.results if r.diagnostics]
    clean_count = len(report.results) - len(components_with_findings)

    click.echo(f"\n{'=' * 60}")
    click.echo(f"Security Audit: {report.setup_name}")
    click.echo(f"{'=' * 60}")
    click.echo(f"Components scanned: {len(report.results)}")
    if report.adjudicated:
        click.echo(f"Scanner:         {raw_errors} errors, {raw_warnings} warnings")
        click.echo(
            f"After review:    {report.effective_errors} confirmed errors, "
            f"{report.false_positive_count} false positives, "
            f"{report.downgraded_count} downgraded"
        )
    else:
        click.echo(f"Errors: {raw_errors} | Warnings: {raw_warnings}")
    click.echo(f"Risk Assessment: {report.risk}")
    click.echo("")

    if components_with_findings:
        click.echo("Security Findings:")
        click.echo(f"{'─' * 60}")
        for r in components_with_findings:
            parts = []
            if r.error_count:
                parts.append(f"{r.error_count} error{'s' if r.error_count != 1 else ''}")
            if r.warning_count:
                parts.append(f"{r.warning_count} warning{'s' if r.warning_count != 1 else ''}")
            status = ", ".join(parts)
            click.echo(f"  {r.target_type}/{r.target_name:<36} {status}")
            adj_for_comp = report.adjudication_map.get(r.target_name, [])
            adj_by_msg = {af.finding.message: af for af in adj_for_comp}
            for d in r.diagnostics:
                sev = "FAIL" if d.severity.value == "error" else "WARNING"
                short_rule = d.rule_id.split("/", 1)[-1]
                af = adj_by_msg.get(d.message)
                if af and af.is_false_positive:
                    click.echo(
                        f"    {sev:<8} {short_rule}: {d.message}"
                        f"\n             -> FALSE POSITIVE: {af.reasoning}"
                    )
                elif af and af.verdict == "DOWNGRADED":
                    click.echo(
                        f"    {sev:<8} {short_rule}: {d.message}"
                        f"\n             -> DOWNGRADED: {af.reasoning}"
                    )
                else:
                    click.echo(f"    {sev:<8} {short_rule}: {d.message}")
        click.echo("")

    if clean_count > 0:
        click.echo(f"{clean_count}/{len(report.results)} components passed all security checks.")
        click.echo("")

    if report.rubric_results:
        click.echo("Semantic Security Review:")
        click.echo(f"{'─' * 60}")
        for rr in report.rubric_results:
            click.echo(f"  {rr.component_type}/{rr.component_name}:")
            for issue in rr.issues:
                click.echo(f"    [{issue.category}] {issue.description}")
                click.echo(f"      Evidence: {issue.evidence}")
                click.echo(f"      Fix: {issue.suggestion}")
                if issue.impact:
                    click.echo(f"      Impact: {issue.impact}")
        click.echo("")

    if report.skip_notices:
        click.echo("Skipped Checks:")
        click.echo(f"{'─' * 60}")
        for notice in report.skip_notices:
            click.echo(f"  {notice}")
        click.echo("")

    click.echo(report.metadata.format_terminal())
    click.echo("")


@cli.command("security")
@click.argument("path", type=click.Path(exists=True))
@click.option(
    "--format", "fmt", type=click.Choice(["terminal", "json", "sarif"]), default="terminal"
)
@click.option(
    "--output",
    "output_path",
    type=click.Path(),
    default=None,
    help="Write output to file instead of stdout.",
)
@click.option(
    "--review",
    is_flag=True,
    help="Also run LLM-based semantic security review (requires API key).",
)
@click.option("--provider", type=click.Choice(["gemini", "anthropic"]), default="gemini")
@click.option("--model", default=None, help="LLM model for semantic security review.")
@click.option(
    "--fail-on-error",
    is_flag=True,
    help="Exit with code 1 if any errors found.",
)
@click.option(
    "--fail-on-warning",
    is_flag=True,
    help="Exit with code 1 if any warnings or errors found.",
)
@click.option(
    "--user-config",
    type=click.Path(),
    default=None,
    help="Path to ~/.claude directory for user-level CLAUDE.md discovery.",
)
@click.option(
    "--recursive",
    is_flag=True,
    help="Recursively search for agent configs in all subdirectories.",
)
@click.option(
    "--enforce",
    type=click.Choice(["strict", "advisory", "off"]),
    default=None,
    help="Enforcement mode: strict (exit 1 on any finding), advisory (exit 0 always), off (skip).",
)
@click.option(
    "--baseline",
    "baseline_path",
    type=click.Path(exists=True),
    default=None,
    help="Path to baseline JSON file. Suppress baselined findings.",
)
@click.option(
    "--exclude",
    multiple=True,
    help="Glob patterns for files/dirs to exclude from scanning (repeatable).",
)
def eval_setup_security(
    path: str,
    fmt: str,
    output_path: str | None,
    review: bool,
    provider: str,
    model: str | None,
    fail_on_error: bool,
    fail_on_warning: bool,
    user_config: str | None,
    recursive: bool,
    enforce: str | None,
    baseline_path: str | None,
    exclude: tuple[str, ...],
) -> None:
    """Deep security audit: all deterministic security rules + optional LLM review."""
    if enforce and (fail_on_error or fail_on_warning):
        raise click.UsageError(
            "--enforce is mutually exclusive with --fail-on-error and --fail-on-warning"
        )

    t0 = time.monotonic()
    from harness_eval.config.presets import SECURITY
    from harness_eval.inspection.engine import inspect_setup

    target = Path(path)
    setup = discover_setup(
        name=target.name,
        path=path,
        user_config_dir=user_config,
        recursive=recursive,
        exclude=exclude,
    )
    results = inspect_setup(setup, SECURITY)

    if baseline_path:
        import json as _json_bl

        from harness_eval.baseline import filter_baselined

        bl_data = _json_bl.loads(Path(baseline_path).read_text())
        results = filter_baselined(results, bl_data)

    results, skip_notices = _clean_results(results)

    rubric_results = []
    adjudication_map: dict[str, list[AdjudicatedFinding]] = {}
    adjudicated = False

    if review:
        from concurrent.futures import ThreadPoolExecutor, as_completed

        from harness_eval.rubric.dimensions import SECURITY_REVIEW_CATEGORIES
        from harness_eval.rubric.prompts.adjudication import (
            ADJUDICATION_SYSTEM,
            build_adjudication_prompt,
        )
        from harness_eval.rubric.scorer import RubricChecker
        from harness_eval.utils.llm import create_client

        client = create_client(provider, model)
        checker = RubricChecker(client)
        try:
            checker._ensure_client_safe()
        except (ImportError, ValueError) as e:
            key_hint = "ANTHROPIC_API_KEY" if provider == "anthropic" else "GEMINI_API_KEY"
            raise click.ClickException(
                f"{e}\n\nSet {key_hint} in your environment, or run `harness-eval doctor` to check setup."
            ) from None

        components_needing_adjudication = [r for r in results if r.diagnostics]
        if components_needing_adjudication:
            n = len(components_needing_adjudication)
            click.echo(
                f"  Adjudicating {n} components with findings...",
                err=True,
            )
            comp_map: dict[str, ParsedComponent] = {}
            for c in setup.components:
                key = f"{c.component_type.value}/{c.name}"
                if key not in comp_map:
                    comp_map[key] = c
            for r in components_needing_adjudication:
                comp = comp_map.get(f"{r.target_type}/{r.target_name}")
                if not comp:
                    continue
                findings_data = [
                    {
                        "rule_id": d.rule_id,
                        "severity": d.severity.value,
                        "message": redact_secrets(d.message),
                    }
                    for d in r.diagnostics
                ]
                prompt = build_adjudication_prompt(
                    r.target_type,
                    r.target_name,
                    redact_secrets(comp.content),
                    findings_data,
                )
                try:
                    response = client.generate(ADJUDICATION_SYSTEM, prompt)
                    verdicts = _parse_adjudication_response(response, r.diagnostics)
                    adjudication_map[r.target_name] = verdicts
                except Exception:
                    adjudication_map[r.target_name] = [
                        AdjudicatedFinding(
                            finding=d, verdict="CONFIRMED", reasoning="adjudication failed"
                        )
                        for d in r.diagnostics
                    ]
            adjudicated = True

        context_parts = [
            f"[{c.component_type.value}] {c.name}: {redact_secrets(c.content)[:200]}"
            for c in setup.components
        ]
        context_text = "\n".join(context_parts)

        click.echo(f"  Semantic review: {len(setup.components)} components...", err=True)

        from harness_eval.rubric.types import RubricResult

        all_sec_results: list[RubricResult] = []
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = {
                executor.submit(
                    checker.check,
                    comp.component_type.value,
                    comp.name,
                    comp.content,
                    context_text,
                    SECURITY_REVIEW_CATEGORIES,
                ): comp
                for comp in setup.components
            }
            for future in as_completed(futures):
                all_sec_results.append(future.result())

        for rr in all_sec_results:
            if rr.issues:
                rubric_results.append(rr)

    total_semantic = sum(len(rr.issues) for rr in rubric_results)
    risk, effective_errors, effective_warnings, false_positive_count, downgraded_count = (
        _assess_risk(results, adjudicated, adjudication_map, total_semantic)
    )

    sec_metadata = EvalMetadata(
        version=EvalMetadata.get_version(),
        duration_seconds=time.monotonic() - t0,
        components_scanned=len(results),
        invocation_source="cli",
    )
    if review:
        sec_metadata.provider = provider
        sec_metadata.model = client.model  # type: ignore[attr-defined]
        sec_metadata.llm_calls_total = client.calls_total  # type: ignore[attr-defined]
        sec_metadata.llm_calls_succeeded = client.calls_succeeded  # type: ignore[attr-defined]

    report = _SecurityReport(
        setup_name=setup.name,
        risk=risk,
        adjudicated=adjudicated,
        results=results,
        adjudication_map=adjudication_map,
        rubric_results=rubric_results,
        skip_notices=skip_notices,
        metadata=sec_metadata,
        effective_errors=effective_errors,
        effective_warnings=effective_warnings,
        false_positive_count=false_positive_count,
        downgraded_count=downgraded_count,
    )

    if fmt == "sarif":
        from harness_eval.output.sarif import format_sarif

        sarif_doc = format_sarif(results, sec_metadata)
        emit_output(json_mod.dumps(sarif_doc, indent=2), output_path)
    elif fmt == "json":
        emit_output(_format_json_security(report), output_path)
    else:
        _format_terminal_security(report)

    if enforce == "off":
        return
    if enforce == "strict":
        if effective_errors + effective_warnings > 0:
            raise SystemExit(1)
        return
    if enforce == "advisory":
        return

    if fail_on_error and effective_errors > 0:
        raise SystemExit(1)
    if fail_on_warning and (effective_errors + effective_warnings) > 0:
        raise SystemExit(1)
