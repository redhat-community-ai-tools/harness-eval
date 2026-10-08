"""Every path a harness references must exist in the tree.

A pipeline harness binds an agent prompt to scripts, skills, plugins, a
policy, an output schema and host files. The runtime resolves those paths
when the agent is dispatched; a missing one fails the run, after the
sandbox was provisioned, with no linter having looked at it.

This mirrors what the fullsend runtime checks in ``ValidateFilesExist`` and
skips exactly what the runtime skips: URLs, absolute paths, references that
still contain a host ``${VAR}``, optional host files, and every reference
when the harness inherits from a URL base (its resources may live at that
base). It also stays silent when the tree is one layer of a composed
configuration (an overlay or an org config layer), because a reference that
another layer satisfies is not missing. Everything reported is a file a
complete scaffold does not contain.
"""

from __future__ import annotations

from harness_eval.core.types import ComponentType
from harness_eval.inspection.harness_formats.fullsend import normalize_path
from harness_eval.inspection.types import (
    Location,
    ReportDescriptor,
    RuleCategory,
    RuleContext,
    RuleMeta,
    Severity,
)
from harness_eval.utils.paths import safe_join


def _line_of(raw: str, needle: str) -> int | None:
    for i, line in enumerate(raw.splitlines(), 1):
        if needle in line:
            return i
    return None


class HarnessReferencedFileExists:
    meta = RuleMeta(
        id="harness/referenced-file-exists",
        tier="provisional",
        effect="block",
        scope="FILE_FS",
        default_severity=Severity.ERROR,
        fixable=False,
        description=(
            "Every path a harness references (agent prompt, policy, scripts, skills, "
            "plugins, host files, output schema, base) must exist in the tree"
        ),
        category=RuleCategory.STRUCTURAL,
        messages={
            "missing": "'{{field}}' references '{{ref}}' but {{kind}} does not exist under {{root}}",
            "escapes": "'{{field}}' references '{{ref}}' which resolves outside the harness root",
        },
        target_type=ComponentType.HARNESS,
        default_suggestion="Fix the path, add the missing file, or remove the reference.",
    )

    def create(self, context: RuleContext) -> None:
        harness = context.harness
        if harness is None or harness.fields is None:
            return
        fields = harness.fields
        # Another layer, or a URL base, can supply any of these resources at
        # dispatch time; only a complete scaffold makes "missing" decidable.
        if not fields.layer_complete:
            return
        if fields.base is not None and normalize_path(fields.base) is None:
            return

        root = fields.root_dir
        for ref in fields.refs:
            if ref.optional:
                continue
            target = safe_join(root, ref.value)
            line = _line_of(harness.raw_content, ref.value)
            if target is None:
                context.report(
                    ReportDescriptor(
                        message_id="escapes",
                        data={"field": ref.field, "ref": ref.value},
                        location=Location(file=harness.file_path, start_line=line),
                    )
                )
                continue
            exists = target.is_dir() if ref.directory else target.is_file()
            if not exists:
                context.report(
                    ReportDescriptor(
                        message_id="missing",
                        data={
                            "field": ref.field,
                            "ref": ref.value,
                            "kind": "the directory" if ref.directory else "the file",
                            "root": str(root),
                        },
                        location=Location(file=harness.file_path, start_line=line),
                    )
                )
