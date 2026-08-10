"""harness-eval-review command."""

from __future__ import annotations

import json as json_mod
import time
from pathlib import Path

import click

from harness_eval.cli import cli
from harness_eval.core.setup import discover_setup
from harness_eval.core.types import ComponentType
from harness_eval.output.metadata import EvalMetadata
from harness_eval.rubric.types import RubricResult
from harness_eval.utils.redact import redact_secrets


@cli.command("harness-review")
@click.argument("path", type=click.Path(exists=True))
@click.option("--format", "fmt", type=click.Choice(["terminal", "json"]), default="terminal")
@click.option("--provider", type=click.Choice(["gemini", "anthropic"]), default="gemini")
@click.option("--model", default=None, help="LLM model for rubric scoring.")
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
def eval_setup_review(
    path: str, fmt: str, provider: str, model: str | None, user_config: str | None, recursive: bool
) -> None:
    """Review: LLM rubric scoring per component. Requires API key in environment."""
    t0 = time.monotonic()
    from harness_eval.rubric.scorer import RubricChecker
    from harness_eval.utils.llm import create_client

    setup = discover_setup(
        name=Path(path).name, path=path, user_config_dir=user_config, recursive=recursive
    )

    client = create_client(provider, model)
    checker = RubricChecker(client)

    context_parts = [
        f"[{c.component_type.value}] {c.name}: {redact_secrets(c.content)[:200]}"
        for c in setup.components
    ]
    context_text = "\n".join(context_parts)

    component_type_map = {
        ComponentType.SKILL: "skill",
        ComponentType.COMMAND: "command",
        ComponentType.CLAUDE_MD: "claude_md",
        ComponentType.HOOKS: "hooks",
        ComponentType.AGENT: "agent",
    }

    from concurrent.futures import ThreadPoolExecutor, as_completed

    from harness_eval.utils.tokens import count_tokens

    reviewable = []
    for comp in setup.components:
        comp_type_str = component_type_map.get(comp.component_type)
        if comp_type_str:
            reviewable.append((comp_type_str, comp.name, comp.content))

    small: list[tuple[str, str, str]] = []
    large: list[tuple[str, str, str]] = []
    for item in reviewable:
        if count_tokens(item[2]) < 500:
            small.append(item)
        else:
            large.append(item)

    batches: list[list[tuple[str, str, str]]] = []
    for i in range(0, len(small), 3):
        batches.append(small[i : i + 3])
    for item in large:
        batches.append([item])

    try:
        checker._ensure_client_safe()
    except (ImportError, ValueError) as e:
        key_hint = "ANTHROPIC_API_KEY" if provider == "anthropic" else "GEMINI_API_KEY"
        raise click.ClickException(
            f"{e}\n\nSet {key_hint} in your environment, or run `harness-eval doctor` to check setup."
        ) from None
    click.echo(f"  Reviewing {len(reviewable)} components ({len(batches)} batches)...", err=True)

    rubric_results: list[RubricResult] = []
    with ThreadPoolExecutor(max_workers=4) as executor:
        future_map = {}
        for batch in batches:
            if len(batch) == 1:
                ct, cn, cc = batch[0]
                future = executor.submit(checker.check, ct, cn, cc, context_text)
            else:
                future = executor.submit(checker.check_batch, batch, context_text)  # type: ignore[arg-type]
            future_map[future] = batch

        for future in as_completed(future_map):
            result = future.result()
            if isinstance(result, list):
                rubric_results.extend(result)
            else:
                rubric_results.append(result)

    comp_order = {comp.name: i for i, comp in enumerate(setup.components)}
    rubric_results.sort(key=lambda r: comp_order.get(r.component_name, 999))

    metadata = EvalMetadata(
        version=EvalMetadata.get_version(),
        duration_seconds=time.monotonic() - t0,
        components_scanned=len(rubric_results),
        invocation_source="cli",
        provider=provider,
        model=client.model,  # type: ignore[attr-defined]
        llm_calls_total=client.calls_total,  # type: ignore[attr-defined]
        llm_calls_succeeded=client.calls_succeeded,  # type: ignore[attr-defined]
    )

    if fmt == "json":
        output = {
            "setup": setup.name,
            "component_count": len(setup.components),
            "rubric": [
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
                    "summary": rr.summary,
                    "verdict": rr.verdict,
                }
                for rr in rubric_results
            ],
            "metadata": metadata.to_dict(),
        }
        click.echo(json_mod.dumps(output, indent=2))
    else:
        from harness_eval.output.report import format_header

        click.echo(
            format_header(
                f"Setup Review: {setup.name}",
                Components=len(setup.components),
                Provider=f"{provider} | Model: {client.model}",
            )
        )
        click.echo("")

        for rr in rubric_results:
            if rr.issues:
                click.echo(f"  {rr.component_type}/{rr.component_name}:")
                for issue in rr.issues:
                    click.echo(f"    [{issue.category}] {issue.description}")
                    click.echo(f"      Evidence: {issue.evidence}")
                    click.echo(f"      Fix: {issue.suggestion}")
                    if issue.impact:
                        click.echo(f"      Impact: {issue.impact}")
            else:
                click.echo(f"  {rr.component_type}/{rr.component_name}: no issues")
            if rr.summary:
                click.echo(f"    Summary: {rr.summary}")
            click.echo("")

        total_issues = sum(len(rr.issues) for rr in rubric_results)
        click.echo(f"{len(rubric_results)} components reviewed, {total_issues} rubric issues found")
        click.echo(metadata.format_terminal())
        click.echo("")
