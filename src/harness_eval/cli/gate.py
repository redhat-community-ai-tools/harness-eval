"""harness-gate command: fast, LLM-free gate on corpus-validated rules."""

from __future__ import annotations

import json as json_mod
from pathlib import Path

import click

from harness_eval.cli import cli
from harness_eval.cli._helpers import emit_output


@cli.command("harness-gate")
@click.argument("path", type=click.Path(exists=True))
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["json", "sarif"]),
    default=None,
    help="Output format. Default: one line per finding (rule id, file, message).",
)
@click.option(
    "--baseline",
    "baseline_path",
    type=click.Path(exists=True),
    default=None,
    help="Baseline JSON file. Suppress baselined findings.",
)
@click.option(
    "--include-provisional",
    is_flag=True,
    help="Also run tier=provisional rules (0 corpus false positives, but fewer than 50 findings).",
)
@click.option(
    "--output",
    "output_path",
    type=click.Path(),
    default=None,
    help="Write output to a file instead of stdout.",
)
@click.option(
    "--recursive",
    is_flag=True,
    help="Recursively search subdirectories for agent configs.",
)
def harness_gate(
    path: str,
    fmt: str | None,
    baseline_path: str | None,
    include_provisional: bool,
    output_path: str | None,
    recursive: bool,
) -> None:
    """Gate on validated rules only. Runs tier=gating rules (add --include-provisional
    for the provisional tier), exits 1 on any finding, and never loads LLM extras."""
    from harness_eval.config.presets import gate_rules
    from harness_eval.core.setup import discover_setup
    from harness_eval.inspection.engine import inspect_setup

    config_rules = gate_rules(include_provisional=include_provisional)
    target = Path(path)

    if target.is_dir():
        setup = discover_setup(name=target.name, path=path, recursive=recursive)
        results = inspect_setup(setup, config_rules)
    else:
        from harness_eval.cli.lint import _inspect_single_file

        results = _inspect_single_file(target, config_rules)

    if baseline_path:
        from harness_eval.baseline import filter_baselined

        bl_data = json_mod.loads(Path(baseline_path).read_text())
        results = filter_baselined(results, bl_data)

    findings = [d for r in results for d in r.diagnostics]

    if fmt == "sarif":
        from harness_eval.output.metadata import EvalMetadata
        from harness_eval.output.sarif import format_sarif

        metadata = EvalMetadata(
            version=EvalMetadata.get_version(),
            duration_seconds=0.0,
            components_scanned=len(results),
            rules_checked=sum(len(r.rules_run) for r in results),
            invocation_source="cli",
        )
        sarif_doc = format_sarif(results, metadata, scan_root=path)
        emit_output(json_mod.dumps(sarif_doc, indent=2), output_path)
    elif fmt == "json":
        out = [
            {
                "rule": d.rule_id,
                "file": d.location.file,
                "severity": d.severity.value,
                "message": d.message,
            }
            for d in findings
        ]
        emit_output(json_mod.dumps(out, indent=2), output_path)
    else:
        lines = [f"{d.rule_id}\t{d.location.file}\t{d.message}" for d in findings]
        emit_output("\n".join(lines) if lines else "No gating findings.", output_path)

    if findings:
        raise SystemExit(1)
