"""CLI entry point for harness-eval."""

from __future__ import annotations

import click

cli = click.Group(name="harness-eval", help="Evaluate AI agent setups.")
click.version_option(package_name="harness-eval")(cli)

from harness_eval.cli import baseline as _baseline  # noqa: E402, F401
from harness_eval.cli import doctor as _doctor  # noqa: E402, F401
from harness_eval.cli import gate as _gate  # noqa: E402, F401
from harness_eval.cli import lint as _lint  # noqa: E402, F401
from harness_eval.cli import review as _review  # noqa: E402, F401
from harness_eval.cli import rules as _rules  # noqa: E402, F401
from harness_eval.cli import scan as _scan  # noqa: E402, F401
from harness_eval.cli import security as _security  # noqa: E402, F401
from harness_eval.cli import skill as _skill  # noqa: E402, F401
from harness_eval.cli import submission_scan as _submission_scan  # noqa: E402, F401
