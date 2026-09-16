"""harness-eval baseline command: snapshot current findings for incremental adoption."""

from __future__ import annotations

import json
from pathlib import Path

import click

from harness_eval.cli import cli
from harness_eval.cli._helpers import scan_limit_options, scan_limits_from


@cli.command("baseline")
@click.argument("path", type=click.Path(exists=True))
@click.option(
    "--output",
    "-o",
    default=".harness-eval-baseline.json",
    help="Output path for the baseline file.",
)
@click.option(
    "--preset",
    type=click.Choice(["recommended", "strict", "security", "pre-workflow"]),
    default="recommended",
    help="Rule preset to use when generating the baseline.",
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
@scan_limit_options
def create_baseline_cmd(
    path: str,
    output: str,
    preset: str,
    user_config: str | None,
    recursive: bool,
    max_file_bytes: int,
    max_total_bytes: int,
    max_files: int,
    max_depth: int,
) -> None:
    """Create a baseline snapshot of current findings for incremental adoption."""
    from harness_eval.baseline import create_baseline
    from harness_eval.config.presets import PRESETS
    from harness_eval.core.setup import discover_setup
    from harness_eval.inspection.engine import inspect_setup

    target = Path(path)
    config_rules = PRESETS.get(preset, {})
    setup = discover_setup(
        name=target.name,
        path=path,
        user_config_dir=user_config,
        recursive=recursive,
        limits=scan_limits_from(max_file_bytes, max_total_bytes, max_files, max_depth),
    )
    results = inspect_setup(setup, config_rules)
    baseline = create_baseline(results)

    Path(output).write_text(json.dumps(baseline, indent=2))

    total = len(baseline["findings"])
    click.echo(f"Baseline created with {total} finding(s): {output}")
