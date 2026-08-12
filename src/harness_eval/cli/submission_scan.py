"""harness-eval skill-submission-scan: scan skill submissions for security and quality."""

from __future__ import annotations

import json as json_mod
import time
from pathlib import Path

import click

from harness_eval.cli import cli
from harness_eval.output.metadata import EvalMetadata


@cli.command("skill-submission-scan")
@click.argument("path", type=click.Path(exists=True))
@click.option(
    "--output-security",
    type=click.Path(),
    default=None,
    help="Path to write security findings JSON.",
)
@click.option(
    "--output-quality",
    type=click.Path(),
    default=None,
    help="Path to write quality findings JSON.",
)
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["terminal", "json"]),
    default="terminal",
    help="Display format.",
)
@click.option("--fail-on-error", is_flag=True, help="Exit code 1 if any errors found.")
@click.option("--fail-on-warning", is_flag=True, help="Exit code 1 if any findings found.")
def submission_scan(
    path: str,
    output_security: str | None,
    output_quality: str | None,
    fmt: str,
    fail_on_error: bool,
    fail_on_warning: bool,
) -> None:
    """Scan a skill submission directory for security and quality issues.

    Produces pipeline-compatible JSON with security and quality findings.
    Runs harness-eval deterministic rules with false-positive
    reduction (code-fence tracking, negation awareness, example context).
    """
    t0 = time.monotonic()

    from harness_eval.config.presets import SKILL_SUBMISSION
    from harness_eval.submission.scanner import scan_submission

    target = Path(path).resolve()

    if not target.is_dir():
        click.echo(f"Error: {path} is not a directory.", err=True)
        raise SystemExit(1)

    result = scan_submission(
        target,
        SKILL_SUBMISSION,
    )

    metadata = EvalMetadata(
        version=EvalMetadata.get_version(),
        duration_seconds=time.monotonic() - t0,
        components_scanned=len(result.inspection_results),
        invocation_source="cli",
    )

    if output_security:
        Path(output_security).write_text(
            json_mod.dumps({"findings": result.security_findings}, indent=2),
            encoding="utf-8",
        )

    if output_quality:
        Path(output_quality).write_text(
            json_mod.dumps({"findings": result.quality_findings}, indent=2),
            encoding="utf-8",
        )

    if fmt == "json":
        output = {
            "scan": True,
            "path": str(target),
            "verdict": result.verdict,
            "security_findings": len(result.security_findings),
            "quality_findings": len(result.quality_findings),
            "errors": result.total_errors,
            "warnings": result.total_warnings,
            "security": {"findings": result.security_findings},
            "quality": {"findings": result.quality_findings},
            "metadata": metadata.to_dict(),
        }
        click.echo(json_mod.dumps(output, indent=2))
    else:
        from harness_eval.output.report import format_finding_line, format_header

        click.echo(
            format_header(
                f"Submission Scan: {target.name}",
                Security=f"{len(result.security_findings)} findings",
                Quality=f"{len(result.quality_findings)} findings",
                Errors=result.total_errors,
                Warnings=result.total_warnings,
                Verdict=result.verdict,
            )
        )
        click.echo("")

        if result.security_findings:
            click.echo("  Security:")
            for f in result.security_findings:
                click.echo(
                    format_finding_line(
                        f["rule_id"],
                        f["severity"],
                        f"{f['file_path']}:{f['line']} {f['message']}",
                        None,
                    )
                )
            click.echo("")

        if result.quality_findings:
            click.echo("  Quality:")
            for f in result.quality_findings:
                click.echo(
                    format_finding_line(
                        f["rule_id"],
                        f["severity"],
                        f"{f['file_path']}:{f['line']} {f['message']}",
                        None,
                    )
                )
            click.echo("")

        if result.verdict == "SAFE":
            click.echo("No issues found. Submission is clean.")
        elif result.verdict == "CAUTION":
            click.echo("Warnings found. Review before accepting.")
        else:
            click.echo("Security issues found. Do not accept without review.")

        click.echo(metadata.format_terminal())
        click.echo("")

    if output_security:
        click.echo(f"Security findings written to: {output_security}", err=True)
    if output_quality:
        click.echo(f"Quality findings written to: {output_quality}", err=True)

    if fail_on_warning and (result.total_errors + result.total_warnings) > 0:
        raise SystemExit(1)
    if fail_on_error and result.total_errors > 0:
        raise SystemExit(1)
