"""harness-eval-lint command."""

from __future__ import annotations

import json as json_mod
import time
from pathlib import Path

import click

from harness_eval.cli import cli
from harness_eval.cli._helpers import emit_output
from harness_eval.core.setup import discover_setup
from harness_eval.output.metadata import EvalMetadata


@cli.command("harness-lint")
@click.argument("path", type=click.Path(exists=True))
@click.option(
    "--preset",
    type=click.Choice(["recommended", "strict", "security", "pre-workflow"]),
    default="recommended",
)
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
@click.option("--fix", is_flag=True, help="Apply auto-fixes.")
@click.option(
    "--fail-on-error",
    is_flag=True,
    help="Exit with code 1 if any errors found. Useful for CI and hooks.",
)
@click.option(
    "--watch",
    is_flag=True,
    help="Watch files for changes and re-run lint automatically.",
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
    "--report-card",
    "report_card_path",
    type=click.Path(),
    default=None,
    help="Write a unified report card JSON to this path.",
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
def eval_setup_lint(
    path: str,
    preset: str,
    fmt: str,
    output_path: str | None,
    fix: bool,
    fail_on_error: bool,
    watch: bool,
    fail_on_warning: bool,
    user_config: str | None,
    recursive: bool,
    enforce: str | None,
    report_card_path: str | None,
    baseline_path: str | None,
    exclude: tuple[str, ...],
) -> None:
    """Lint: deterministic rules + system analysis. No LLM, fast."""
    if enforce and (fail_on_error or fail_on_warning):
        raise click.UsageError(
            "--enforce is mutually exclusive with --fail-on-error and --fail-on-warning"
        )

    if watch:
        from harness_eval.watch import run_watch

        if fix:
            click.echo("Warning: --fix is ignored in watch mode.", err=True)
        if fail_on_error:
            click.echo("Warning: --fail-on-error is ignored in watch mode.", err=True)
        if fail_on_warning:
            click.echo("Warning: --fail-on-warning is ignored in watch mode.", err=True)
        run_watch(path=path, preset=preset, fmt=fmt, user_config=user_config, recursive=recursive)
        return

    t0 = time.monotonic()
    from harness_eval.analysis.system import analyze_system
    from harness_eval.config.presets import PRESETS
    from harness_eval.inspection.engine import inspect_setup
    from harness_eval.inspection.fixer import apply_fixes
    from harness_eval.output.report import format_json, format_terminal

    config_rules = PRESETS.get(preset, {})
    target = Path(path)

    if target.is_dir():
        setup = discover_setup(
            name=target.name,
            path=path,
            user_config_dir=user_config,
            recursive=recursive,
            exclude=exclude,
        )
        results = inspect_setup(setup, config_rules)

        if baseline_path:
            import json as _json_bl

            from harness_eval.baseline import filter_baselined

            bl_data = _json_bl.loads(Path(baseline_path).read_text())
            results = filter_baselined(results, bl_data)

        system = analyze_system(setup)

        metadata = EvalMetadata(
            version=EvalMetadata.get_version(),
            duration_seconds=time.monotonic() - t0,
            components_scanned=len(results),
            rules_checked=sum(len(r.rules_run) for r in results),
            invocation_source="cli",
        )

        if fmt == "sarif":
            from harness_eval.output.sarif import format_sarif

            sarif_doc = format_sarif(results, metadata, scan_root=path)
            emit_output(json_mod.dumps(sarif_doc, indent=2), output_path)
        elif fmt == "json":
            json_out = format_json(system, results)
            data = json_mod.loads(json_out)
            data["metadata"] = metadata.to_dict()
            emit_output(json_mod.dumps(data, indent=2), output_path)
        else:
            text = format_terminal(system, results) + "\n" + metadata.format_terminal()
            emit_output(text, output_path)
    else:
        results = _inspect_single_file(target, config_rules)

        metadata = EvalMetadata(
            version=EvalMetadata.get_version(),
            duration_seconds=time.monotonic() - t0,
            components_scanned=len(results),
            rules_checked=sum(len(r.rules_run) for r in results),
            invocation_source="cli",
        )

        if fmt == "sarif":
            from harness_eval.output.sarif import format_sarif

            sarif_doc = format_sarif(results, metadata, scan_root=path)
            emit_output(json_mod.dumps(sarif_doc, indent=2), output_path)
        elif fmt == "json":
            output = {
                "results": [
                    {
                        "target": f"{r.target_type}/{r.target_name}",
                        "tokens": r.tokens,
                        "errors": r.error_count,
                        "warnings": r.warning_count,
                        "findings": [
                            {"rule": d.rule_id, "severity": d.severity.value, "message": d.message}
                            for d in r.diagnostics
                        ],
                    }
                    for r in results
                ],
                "metadata": metadata.to_dict(),
            }
            emit_output(json_mod.dumps(output, indent=2), output_path)
        else:
            total_errors = sum(r.error_count for r in results)
            total_warnings = sum(r.warning_count for r in results)
            lines_out = []
            for r in results:
                if r.diagnostics:
                    lines_out.append(f"\n{r.target_type}/{r.target_name} ({r.tokens} tokens):")
                    for d in r.diagnostics:
                        icon = "X" if d.severity.value == "error" else "!"
                        lines_out.append(f"  [{icon}] {d.rule_id}: {d.message}")
            lines_out.append(
                f"\n{len(results)} components scanned, "
                f"{total_errors} errors, {total_warnings} warnings"
            )
            lines_out.append(metadata.format_terminal())
            emit_output("\n".join(lines_out), output_path)

    all_findings = [d for r in results for d in r.diagnostics]
    fixable_count = sum(1 for d in all_findings if d.fix is not None)

    if fix:
        fix_results = apply_fixes(all_findings, project_root=Path(path).resolve())
        total_fixed = sum(fr.fixes_applied for fr in fix_results)
        files_fixed = sum(1 for fr in fix_results if fr.fixes_applied > 0)
        if total_fixed:
            click.echo(f"\nFixed {total_fixed} issues across {files_fixed} files.")
        else:
            click.echo("\nNo auto-fixable issues found.")
    elif fixable_count > 0:
        click.echo(
            f"\n{fixable_count} of {len(all_findings)} findings are auto-fixable. "
            f"Run with --fix to apply."
        )

    if report_card_path:
        from harness_eval.output.report import format_report_card

        card = format_report_card(results)
        Path(report_card_path).write_text(json_mod.dumps(card, indent=2))
        cert = card.get("certification", {})
        tier = cert.get("tier", "NONE")
        click.echo(f"\nCertification: {tier}")
        for level in ("basic", "verified", "hardened"):
            info = cert.get(level, {})
            icon = "PASS" if info.get("passed") else "FAIL"
            click.echo(f"  {level.capitalize()}: {icon} ({info.get('reason', '')})")
        click.echo(f"Report card written to {report_card_path}")

    if enforce == "off":
        return
    if enforce == "strict":
        total = sum(r.error_count + r.warning_count for r in results)
        if total > 0:
            raise SystemExit(1)
        return
    if enforce == "advisory":
        return

    if fail_on_error:
        total_errors = sum(r.error_count for r in results)
        if total_errors > 0:
            raise SystemExit(1)

    if fail_on_warning:
        total_errors = sum(r.error_count for r in results)
        total_warnings = sum(r.warning_count for r in results)
        if total_errors + total_warnings > 0:
            raise SystemExit(1)


def _inspect_single_file(target, config_rules):
    """Inspect a single file, auto-detecting its type."""
    from harness_eval.inspection.engine import (
        lint,
        lint_agent,
        lint_claude_md,
        lint_command,
        lint_hooks,
    )

    name = target.name.lower()
    if name == "skill.md":
        return [lint(str(target.parent), config_rules)]
    elif name == "command.md":
        return [lint_command(str(target.parent), config_rules)]
    elif name == "claude.md":
        return [lint_claude_md(str(target), config_rules)]
    elif name in ("settings.json", "hooks.json"):
        return [lint_hooks(str(target), config_rules)]
    elif target.suffix == ".mdc" or name == ".cursorrules":
        return [lint_claude_md(str(target), config_rules)]
    elif target.suffix == ".toml":
        return [lint_command(str(target), config_rules)]
    elif target.suffix == ".md":
        return [lint_agent(str(target), config_rules)]
    click.echo(
        f"Warning: could not detect component type for '{target.name}'. "
        f"Expected: SKILL.md, command.md, CLAUDE.md, .mdc, .cursorrules, "
        f"settings.json, hooks.json, or an agent .md file.",
        err=True,
    )
    return []


cli.add_command(eval_setup_lint, "lint")
