"""harness-eval scan: vet a skill or setup before installing."""

from __future__ import annotations

import json as json_mod
import time
from pathlib import Path

import click

from harness_eval.cli import cli
from harness_eval.config.presets import SECURITY
from harness_eval.output.metadata import EvalMetadata


@cli.command("scan")
@click.argument("path", type=click.Path(exists=True))
@click.option("--format", "fmt", type=click.Choice(["terminal", "json"]), default="terminal")
@click.option("--fail-on-error", is_flag=True, help="Exit code 1 if any errors are found.")
@click.option("--fail-on-warning", is_flag=True, help="Exit code 1 if any findings are found.")
def scan_skill(path: str, fmt: str, fail_on_error: bool, fail_on_warning: bool) -> None:
    """Scan a skill or setup for security and quality issues before installing.

    Run this on a downloaded or cloned skill directory before adding it to
    your project. Combines lint + security checks in one pass.
    """
    t0 = time.monotonic()
    from harness_eval.config.presets import RECOMMENDED
    from harness_eval.core.setup import discover_setup
    from harness_eval.inspection.engine import inspect_setup

    target = Path(path).resolve()

    setup = discover_setup(name=target.name, path=str(target))

    if not setup.components:
        click.echo(f"No agent components found in {path}.", err=True)
        raise SystemExit(1)

    lint_results = inspect_setup(setup, RECOMMENDED)
    security_results = inspect_setup(setup, SECURITY)

    seen_keys: set[str] = set()
    merged = []
    for r in [*lint_results, *security_results]:
        key = (r.target_type, r.target_name)
        if key in seen_keys:
            existing = next(m for m in merged if (m.target_type, m.target_name) == key)
            existing_ids = {d.rule_id for d in existing.diagnostics}
            for d in r.diagnostics:
                if d.rule_id not in existing_ids:
                    existing.diagnostics.append(d)
                    existing_ids.add(d.rule_id)
            for rr in r.rules_run:
                if rr.rule_id not in {x.rule_id for x in existing.rules_run}:
                    existing.rules_run.append(rr)
        else:
            seen_keys.add(key)
            merged.append(r)

    total_errors = sum(r.error_count for r in merged)
    total_warnings = sum(r.warning_count for r in merged)

    if total_errors > 0:
        verdict = "UNSAFE"
    elif total_warnings > 0:
        verdict = "CAUTION"
    else:
        verdict = "SAFE"

    metadata = EvalMetadata(
        version=EvalMetadata.get_version(),
        duration_seconds=time.monotonic() - t0,
        components_scanned=len(merged),
        invocation_source="cli",
    )

    if fmt == "json":
        output = {
            "scan": True,
            "path": str(target),
            "verdict": verdict,
            "components": len(merged),
            "errors": total_errors,
            "warnings": total_warnings,
            "findings": [
                {
                    "component": r.target_name,
                    "type": r.target_type,
                    "errors": r.error_count,
                    "warnings": r.warning_count,
                    "details": [
                        {
                            "rule": d.rule_id,
                            "severity": d.severity.value,
                            "message": d.message,
                            **({"suggestion": d.suggestion} if d.suggestion else {}),
                        }
                        for d in r.diagnostics
                    ],
                }
                for r in merged
                if r.diagnostics
            ],
            "metadata": metadata.to_dict(),
        }
        click.echo(json_mod.dumps(output, indent=2))
    else:
        click.echo(f"\n{'=' * 60}")
        click.echo(f"Scan: {target.name}")
        click.echo(f"{'=' * 60}")
        click.echo(f"Components: {len(merged)}")
        click.echo(f"Errors: {total_errors} | Warnings: {total_warnings}")
        click.echo(f"Verdict: {verdict}")
        click.echo("")

        for r in merged:
            if r.diagnostics:
                click.echo(f"  {r.target_type}/{r.target_name}:")
                for d in r.diagnostics:
                    label = "FAIL" if d.severity.value == "error" else "WARNING"
                    short_rule = d.rule_id.split("/")[-1]
                    click.echo(f"    {label:<8} {short_rule}: {d.message}")
                    if d.suggestion:
                        click.echo(f"             Fix: {d.suggestion}")
                click.echo("")

        if verdict == "SAFE":
            click.echo("No issues found. Safe to install.")
        elif verdict == "CAUTION":
            click.echo("Warnings found. Review before installing.")
        else:
            click.echo("Security issues found. Do not install without review.")

        click.echo(metadata.format_terminal())
        click.echo("")

    if fail_on_warning and (total_errors + total_warnings) > 0:
        raise SystemExit(1)
    if fail_on_error and total_errors > 0:
        raise SystemExit(1)
