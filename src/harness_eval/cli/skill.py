"""eval-skill command."""

from __future__ import annotations

import json as json_mod
import time
from pathlib import Path

import click

from harness_eval.cli import cli
from harness_eval.core.setup import discover_setup
from harness_eval.core.types import ComponentType
from harness_eval.output.metadata import EvalMetadata


@cli.command("skill")
@click.argument("skill_path", type=click.Path(exists=True))
@click.option(
    "--context",
    "context_path",
    type=click.Path(exists=True),
    default=None,
    help="Setup directory for contextual evaluation.",
)
@click.option(
    "--preset",
    type=click.Choice(["recommended", "strict", "security", "pre-workflow"]),
    default="recommended",
)
@click.option("--format", "fmt", type=click.Choice(["terminal", "json"]), default="terminal")
@click.option(
    "--rubric", "run_rubric", is_flag=True, help="Also run LLM rubric scoring (requires API key)."
)
@click.option("--provider", type=click.Choice(["gemini", "anthropic"]), default="gemini")
@click.option("--model", default=None, help="LLM model for rubric scoring.")
@click.option(
    "--user-config",
    type=click.Path(),
    default=None,
    help="Path to ~/.claude directory for user-level CLAUDE.md discovery.",
)
def eval_skill(
    skill_path: str,
    context_path: str | None,
    preset: str,
    fmt: str,
    run_rubric: bool,
    provider: str,
    model: str | None,
    user_config: str | None,
) -> None:
    """Deep-evaluate a single skill, individually and in context of the setup."""
    t0 = time.monotonic()
    from harness_eval.config.presets import PRESETS
    from harness_eval.inspection.engine import lint
    from harness_eval.inspection.parsers import parse_skill

    config_rules = PRESETS.get(preset, {})
    target = Path(skill_path)
    if target.is_file() and target.name.lower() == "skill.md":
        target = target.parent

    skill = parse_skill(str(target))
    result = lint(str(target), config_rules)

    context_findings: list[str] = []
    if context_path:
        context_findings = _contextual_skill_analysis(str(target), context_path, config_rules)

    rubric_result = None
    if run_rubric:
        from harness_eval.rubric.scorer import RubricChecker
        from harness_eval.utils.llm import create_client

        client = create_client(provider, model)
        checker = RubricChecker(client)
        try:
            checker._ensure_client_safe()
        except ImportError as e:
            raise click.ClickException(str(e)) from None

        context_text = None
        if context_path:
            ctx_setup = discover_setup(
                name="context", path=context_path, user_config_dir=user_config
            )
            parts = [
                f"[{c.component_type.value}] {c.name}: {c.content[:200]}"
                for c in ctx_setup.components
            ]
            context_text = "\n".join(parts)

        rubric_result = checker.check(
            component_type="skill",
            component_name=skill.dir_name,
            content=skill.raw_content,
            context=context_text,
        )

    skill_metadata = EvalMetadata(
        version=EvalMetadata.get_version(),
        duration_seconds=time.monotonic() - t0,
        components_scanned=1,
        rules_checked=len(result.rules_run),
        invocation_source="cli",
    )
    if run_rubric and rubric_result:
        skill_metadata.provider = provider
        skill_metadata.model = client.model  # type: ignore[attr-defined]
        skill_metadata.llm_calls_total = client.calls_total  # type: ignore[attr-defined]
        skill_metadata.llm_calls_succeeded = client.calls_succeeded  # type: ignore[attr-defined]

    if fmt == "json":
        output: dict = {
            "skill": skill.dir_name,
            "tokens": skill.tokens,
            "errors": result.error_count,
            "warnings": result.warning_count,
            "findings": [
                {"rule": d.rule_id, "severity": d.severity.value, "message": d.message}
                for d in result.diagnostics
            ],
        }
        output["metadata"] = skill_metadata.to_dict()
        if context_findings:
            output["context_findings"] = context_findings
        if rubric_result:
            output["rubric"] = {
                "issues": [
                    {
                        "category": i.category,
                        "description": i.description,
                        "evidence": i.evidence,
                        "suggestion": i.suggestion,
                        "severity": i.severity,
                        "impact": i.impact,
                    }
                    for i in rubric_result.issues
                ],
                "summary": rubric_result.summary,
                "verdict": rubric_result.verdict,
            }
        click.echo(json_mod.dumps(output, indent=2))
    else:
        click.echo(f"\n{'=' * 60}")
        click.echo(f"Skill Evaluation: {skill.dir_name}")
        click.echo(f"{'=' * 60}")
        click.echo(f"Tokens: {skill.tokens}")
        click.echo(f"Files: {len(skill.files)}")

        if skill.frontmatter:
            desc = skill.frontmatter.get("description", "(none)")
            click.echo(f"Description: {desc}")

        click.echo(f"\nInspection: {result.error_count} errors, {result.warning_count} warnings")
        click.echo(f"{'─' * 60}")
        if result.diagnostics:
            for d in result.diagnostics:
                icon = "X" if d.severity.value == "error" else "!"
                click.echo(f"  [{icon}] {d.rule_id}: {d.message}")
        else:
            click.echo("  No issues found.")

        if context_findings:
            click.echo("\nContextual Analysis (in setup):")
            click.echo(f"{'─' * 60}")
            for finding in context_findings:
                click.echo(f"  [~] {finding}")

        if rubric_result:
            if rubric_result.issues:
                click.echo(f"\nRubric Issues ({len(rubric_result.issues)} found):")
                click.echo(f"{'─' * 60}")
                for issue in rubric_result.issues:
                    click.echo(f"  [{issue.category}] {issue.description}")
                    click.echo(f"    Evidence: {issue.evidence}")
                    click.echo(f"    Fix: {issue.suggestion}")
                    if issue.impact:
                        click.echo(f"    Impact: {issue.impact}")
            else:
                click.echo("\nRubric: No issues found.")
            if rubric_result.summary:
                click.echo(f"\n  Summary: {rubric_result.summary}")

        click.echo(skill_metadata.format_terminal())
        click.echo("")


def _contextual_skill_analysis(skill_path, context_path, config_rules):
    """Analyze a skill in context of its parent setup."""
    from harness_eval.analysis.triggers import analyze_triggers
    from harness_eval.inspection.parsers import parse_skill
    from harness_eval.utils.similarity import tfidf_similarity

    findings = []
    skill = parse_skill(skill_path)
    setup = discover_setup(name="context", path=context_path)

    for comp in setup.by_type(ComponentType.SKILL):
        if comp.name == skill.dir_name:
            continue
        sim = tfidf_similarity(skill.body, comp.content)
        if sim >= 0.60:
            findings.append(f"Content overlap: {sim:.0%} similar to skill '{comp.name}'")

    for comp in setup.by_type(ComponentType.CLAUDE_MD):
        for section_text in comp.content.split("\n#"):
            if len(section_text.split()) < 20:
                continue
            sim = tfidf_similarity(skill.body, section_text)
            if sim >= 0.50:
                findings.append(f"Overlaps with CLAUDE.md content ({sim:.0%} similar)")
                break

    triggers = analyze_triggers(setup)
    for name_a, name_b, sim in triggers.overlap_pairs:
        if skill.dir_name in (name_a, name_b):
            other = name_b if name_a == skill.dir_name else name_a
            findings.append(f"Trigger overlap with '{other}' ({sim:.0%} similar descriptions)")

    if skill.frontmatter:
        desc = skill.frontmatter.get("description", "")
        if isinstance(desc, str):
            desc_lower = desc.lower()
            if not any(
                p in desc_lower for p in ["use when", "use for", "applies to", "relevant for"]
            ):
                findings.append(
                    "Missing activation context in description (no 'use when' phrasing)"
                )

    return findings
