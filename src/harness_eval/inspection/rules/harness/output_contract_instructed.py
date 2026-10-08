"""A harness that declares an output contract must tell the agent about it.

The harness side of an output contract (a schema the validator checks, a
file name the runtime expects) is enforced after the agent exits. The agent
side is a sentence in its instructions: write the result to this file. When
the harness declares the contract and nothing the agent reads mentions it,
the run fails deterministically: the validator looks for a file nobody was
told to write.

The instruction closure is what the runtime gives the agent from this tree:
the agent prompt, every markdown file of each listed skill and plugin, and
the scaffold's shared instruction files. A mention is any of the tokens the
format mapper derived from the declared contract (file name, schema name,
the environment variables and helper tool the runtime exposes for it).

The rule stays silent whenever instructions can come from outside the tree:
a ``base`` harness, an ``agent_input`` directory, runtime fetching, an
incomplete layer, or a listed instruction file that does not exist (that is
``harness/referenced-file-exists``' finding, not a missing mention).
"""

from __future__ import annotations

from pathlib import Path

from harness_eval.core.types import ComponentType
from harness_eval.inspection.types import (
    Location,
    ReportDescriptor,
    RuleCategory,
    RuleContext,
    RuleMeta,
    Severity,
)
from harness_eval.utils.paths import safe_join

_MAX_CLOSURE_FILES = 500


def instruction_closure(fields, root: Path) -> list[Path] | None:
    """Files the agent reads from *root*, or None when any listed one is missing."""
    files: list[Path] = []
    if fields.instructions is None:
        return None
    prompt = safe_join(root, fields.instructions)
    if prompt is None or not prompt.is_file():
        return None
    files.append(prompt)
    for rel in [*fields.skills, *fields.plugins]:
        d = safe_join(root, rel)
        if d is None or not d.is_dir():
            return None
        files.extend(sorted(p for p in d.rglob("*.md") if p.is_file()))
        if len(files) > _MAX_CLOSURE_FILES:
            return None
    for rel in fields.shared_instruction_files:
        f = safe_join(root, rel)
        if f is not None and f.is_file():
            files.append(f)
    return files


def _line_of_contract(raw: str) -> int | None:
    for i, line in enumerate(raw.splitlines(), 1):
        if "validation_loop" in line or "FULLSEND_OUTPUT" in line or "schema:" in line:
            return i
    return None


class HarnessOutputContractInstructed:
    meta = RuleMeta(
        id="harness/output-contract-instructed",
        tier="provisional",
        effect="block",
        scope="PAIRWISE",
        default_severity=Severity.ERROR,
        fixable=False,
        description=(
            "A harness that declares an output contract (schema or output file) must have "
            "instructions that mention it; otherwise the validator looks for a file the "
            "agent was never told to write"
        ),
        category=RuleCategory.CONTENT,
        messages={
            "uninstructed": (
                "Harness declares an output contract ({{contract}}) but none of the {{count}} "
                "instruction files the agent reads mention it (looked for: {{tokens}})"
            ),
        },
        target_type=ComponentType.HARNESS,
        default_suggestion=(
            "Tell the agent, in its prompt or a listed skill, which file to write the result to."
        ),
    )

    def create(self, context: RuleContext) -> None:
        harness = context.harness
        if harness is None or harness.fields is None:
            return
        f = harness.fields
        if not f.output_contract_tokens or not f.layer_complete:
            return
        if f.base is not None or f.agent_input is not None or f.runtime_fetch:
            return
        files = instruction_closure(f, f.root_dir)
        if files is None:
            return
        for path in files:
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                return  # unreadable: not decidable
            if any(tok in text for tok in f.output_contract_tokens):
                return
        contract = f.output_schema or f.output_file or ""
        context.report(
            ReportDescriptor(
                message_id="uninstructed",
                data={
                    "contract": contract,
                    "count": len(files),
                    "tokens": ", ".join(f.output_contract_tokens),
                },
                location=Location(
                    file=harness.file_path, start_line=_line_of_contract(harness.raw_content)
                ),
            )
        )
