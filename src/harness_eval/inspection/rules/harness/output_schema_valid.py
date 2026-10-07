"""A declared output schema must be a JSON object.

The validator loads the schema with a JSON parser and hands it to a JSON
Schema library. A schema that is not valid JSON, or whose top level is not
an object, fails every run of that agent at validation time, after the
agent has done its work.

Only a schema that resolves to an existing file in the tree is parsed. A
missing file is ``harness/referenced-file-exists``' finding; a path the
mapper could not resolve (host ``${VAR}``, URL) is not decidable here.
"""

from __future__ import annotations

import json

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


class HarnessOutputSchemaValid:
    meta = RuleMeta(
        id="harness/output-schema-valid",
        tier="provisional",
        scope="FILE_FS",
        default_severity=Severity.ERROR,
        fixable=False,
        description="A declared output schema must parse as a JSON object",
        category=RuleCategory.STRUCTURAL,
        messages={
            "invalid_json": "Output schema '{{ref}}' is not valid JSON: {{error}}",
            "not_object": "Output schema '{{ref}}' must be a JSON object, got {{kind}}",
        },
        target_type=ComponentType.HARNESS,
        default_suggestion="Fix the schema file so it parses as a JSON Schema object.",
    )

    def create(self, context: RuleContext) -> None:
        harness = context.harness
        if harness is None or harness.fields is None:
            return
        f = harness.fields
        schema_refs = [
            r
            for r in f.refs
            if r.field in ("validation_loop.schema",) or r.field.endswith("FULLSEND_OUTPUT_SCHEMA")
        ]
        for ref in schema_refs:
            target = safe_join(f.root_dir, ref.value)
            if target is None or not target.is_file():
                continue
            try:
                loaded = json.loads(target.read_text(encoding="utf-8", errors="replace"))
            except json.JSONDecodeError as exc:
                context.report(
                    ReportDescriptor(
                        message_id="invalid_json",
                        data={"ref": ref.value, "error": f"line {exc.lineno}: {exc.msg}"},
                        location=Location(file=harness.file_path),
                    )
                )
                continue
            except OSError:
                continue
            if not isinstance(loaded, dict):
                context.report(
                    ReportDescriptor(
                        message_id="not_object",
                        data={"ref": ref.value, "kind": type(loaded).__name__},
                        location=Location(file=harness.file_path),
                    )
                )
