"""harness-eval doctor: show installed capabilities and environment."""

from __future__ import annotations

import os
import sys

import click

from harness_eval.cli import cli

_CAPABILITIES = [
    ("anthropic", "[llm]", "Anthropic LLM provider", 'pip install "harness-eval[llm]"'),
    ("google.genai", "[llm]", "Gemini LLM provider", 'pip install "harness-eval[llm]"'),
    ("yara", "[yara]", "YARA malware signatures", 'pip install "harness-eval[yara]"'),
    ("watchfiles", "[watch]", "File watching (--watch)", 'pip install "harness-eval[watch]"'),
    ("bashlex", "[bash-ast]", "Bash AST taint analysis", 'pip install "harness-eval[bash-ast]"'),
    ("tiktoken", "[tiktoken]", "Accurate token counting", 'pip install "harness-eval[tiktoken]"'),
]

_ENV_VARS = ["GEMINI_API_KEY", "GOOGLE_API_KEY", "ANTHROPIC_API_KEY"]


def _check_import(module: str) -> bool:
    try:
        __import__(module)
        return True
    except ImportError:
        return False


@cli.command("doctor")
def doctor() -> None:
    """Check installed capabilities and environment configuration."""
    import harness_eval

    click.echo(f"harness-eval {harness_eval.__version__}")
    click.echo(f"Python {sys.version.split()[0]}")
    click.echo("")

    click.echo("Capabilities:")
    for module, extra, description, install in _CAPABILITIES:
        available = _check_import(module)
        status = "available" if available else "missing"
        marker = "+" if available else "-"
        line = f"  {marker} {description:<30} {status:<12} {extra}"
        if not available:
            line += f"  ({install})"
        click.echo(line)

    click.echo("")
    click.echo("Environment:")
    for var in _ENV_VARS:
        status = "set" if os.environ.get(var) else "unset"
        click.echo(f"  {var:<25} {status}")
