"""harness-eval rules command."""

from __future__ import annotations

import click

from harness_eval.cli import cli


@cli.command("rules")
@click.option(
    "--category",
    default=None,
    help="Filter by category (security, quality, content, hooks, mcp, agents, commands, etc.)",
)
@click.option(
    "--target",
    default=None,
    help="Filter by target type (skill, command, claude_md, hooks, agent, mcp_config).",
)
@click.option(
    "--framework",
    default=None,
    help="Filter by security framework (owasp_llm, owasp_agentic, mitre_atlas).",
)
@click.option(
    "--tier",
    type=click.Choice(["gating", "provisional", "advisory"]),
    default=None,
    help="Filter by evidence tier (gating, provisional, advisory).",
)
@click.option(
    "--scope",
    type=click.Choice(["FILE", "FILE_FS", "PAIRWISE", "SETUP"]),
    default=None,
    help="Filter by analysis scope (FILE, FILE_FS, PAIRWISE, SETUP).",
)
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["terminal", "json"]),
    default="terminal",
)
def list_rules(
    category: str | None,
    target: str | None,
    framework: str | None,
    tier: str | None,
    scope: str | None,
    fmt: str,
) -> None:
    """List all available lint rules with ID, severity, target, and description."""
    from harness_eval.inspection.registry import get_all_rules

    rules = sorted(get_all_rules(), key=lambda r: r.meta.id)

    if category:
        rules = [r for r in rules if r.meta.id.startswith(f"{category}/")]

    if tier:
        rules = [r for r in rules if r.meta.tier == tier]

    if scope:
        rules = [r for r in rules if r.meta.scope == scope]

    if target:
        rules = [
            r
            for r in rules
            if (hasattr(r.meta.target_type, "value") and r.meta.target_type.value == target)
            or str(r.meta.target_type) == target
        ]

    if framework:
        rules = [r for r in rules if r.meta.frameworks and framework in r.meta.frameworks]

    if fmt == "json":
        import json as json_mod

        output = []
        for r in rules:
            entry: dict = {
                "id": r.meta.id,
                "severity": r.meta.default_severity.value,
                "target": r.meta.target_type.value
                if hasattr(r.meta.target_type, "value")
                else str(r.meta.target_type),
                "category": r.meta.category.value,
                "tier": r.meta.tier,
                "scope": r.meta.scope,
                "fixable": r.meta.fixable,
                "description": r.meta.description,
            }
            if r.meta.frameworks:
                entry["frameworks"] = r.meta.frameworks
            output.append(entry)
        click.echo(json_mod.dumps(output, indent=2))
    else:
        categories: dict[str, int] = {}
        click.echo(f"{'ID':<42} {'Severity':<10} {'Target':<12} Description")
        click.echo(f"{'─' * 42} {'─' * 10} {'─' * 12} {'─' * 40}")
        for r in rules:
            sev = r.meta.default_severity.value
            tgt = (
                r.meta.target_type.value
                if hasattr(r.meta.target_type, "value")
                else str(r.meta.target_type)
            )
            click.echo(f"{r.meta.id:<42} {sev:<10} {tgt:<12} {r.meta.description}")
            cat = r.meta.id.split("/")[0]
            categories[cat] = categories.get(cat, 0) + 1

        click.echo("")
        summary = ", ".join(f"{count} {cat}" for cat, count in sorted(categories.items()))
        click.echo(f"{len(rules)} rules total ({summary})")
