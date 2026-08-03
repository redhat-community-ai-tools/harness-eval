"""harness-eval scan: vet a skill or agent setup before installing."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import click

from harness_eval.cli import cli
from harness_eval.core.setup import discover_setup


def _is_url(target: str) -> bool:
    return target.startswith(("http://", "https://", "git@", "ssh://"))


def _is_bare_skill(path: Path) -> bool:
    return (path / "SKILL.md").is_file() and not (path / "skills").is_dir()


def _clone_repo(url: str, dest: Path) -> None:
    result = subprocess.run(
        ["git", "clone", "--depth", "1", "--quiet", url, str(dest)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    if result.returncode != 0:
        raise click.ClickException(f"git clone failed: {result.stderr.strip()}")


@cli.command("scan")
@click.argument("target")
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["terminal", "json"]),
    default="terminal",
    help="Output format.",
)
def scan_skill(target: str, fmt: str) -> None:
    """Vet a skill or setup from a URL or local path before installing."""
    from harness_eval.cli.security import _assess_risk, _clean_results
    from harness_eval.config.presets import SCAN
    from harness_eval.inspection.engine import inspect_setup

    if not shutil.which("git") and _is_url(target):
        raise click.ClickException("git is required to scan remote URLs")

    t0 = time.monotonic()
    tmp_dir = None
    wrapper_dir = None

    try:
        if _is_url(target):
            tmp_dir = tempfile.mkdtemp(prefix="harness-eval-scan-")
            scan_path = Path(tmp_dir)
            click.echo(f"Cloning {target}...")
            _clone_repo(target, scan_path)
            name = target.rstrip("/").split("/")[-1].removesuffix(".git")
        else:
            scan_path = Path(target)
            if not scan_path.is_dir():
                raise click.ClickException(f"Path does not exist: {target}")
            name = scan_path.name

        wrapper_dir = None
        if _is_bare_skill(scan_path):
            wrapper_dir = tempfile.mkdtemp(prefix="harness-eval-wrap-")
            skill_dest = Path(wrapper_dir) / "skills" / scan_path.name
            skill_dest.parent.mkdir(parents=True)
            shutil.copytree(scan_path, skill_dest)
            effective_path = wrapper_dir
        else:
            effective_path = str(scan_path)

        setup = discover_setup(name=name, path=str(effective_path))
        results = inspect_setup(setup, SCAN)
        results, skip_notices = _clean_results(results)

        risk, errors, warnings, _, _ = _assess_risk(
            results, adjudicated=False, adjudication_map={}, total_semantic=0
        )

        duration = time.monotonic() - t0

        if fmt == "json":
            findings = []
            for r in results:
                for d in r.diagnostics:
                    findings.append(
                        {
                            "rule": d.rule_id,
                            "severity": d.severity.value,
                            "message": d.message,
                            "file": r.target_path,
                        }
                    )
            click.echo(
                json.dumps(
                    {
                        "target": target,
                        "verdict": risk,
                        "errors": errors,
                        "warnings": warnings,
                        "findings": findings,
                        "duration_seconds": round(duration, 2),
                    },
                    indent=2,
                )
            )
        else:
            component_count = len(setup.components)
            rule_count = sum(len(r.rules_run) for r in results)
            click.echo(f"\nScanned {component_count} components, {rule_count} rules checked")

            if errors or warnings:
                for r in results:
                    for d in r.diagnostics:
                        icon = "x" if d.severity.value == "error" else "!"
                        click.echo(f"  [{icon}] {d.rule_id}: {d.message}")

            click.echo(f"\nVerdict: {risk} ({errors} errors, {warnings} warnings)")
            click.echo(f"Duration: {duration:.1f}s")

        if risk == "UNSAFE":
            sys.exit(1)

    finally:
        if tmp_dir and Path(tmp_dir).exists():
            shutil.rmtree(tmp_dir, ignore_errors=True)
        if wrapper_dir and Path(wrapper_dir).exists():
            shutil.rmtree(wrapper_dir, ignore_errors=True)
