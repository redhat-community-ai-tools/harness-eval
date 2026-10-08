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
        effect="block",
        scope="FILE_FS",
        default_severity=Severity.ERROR,
        fixable=False,
        description=(
            "A declared output schema must parse as a JSON object, and an object that "
            "forbids additional properties must not require a key it does not define"
        ),
        category=RuleCategory.STRUCTURAL,
        messages={
            "invalid_json": "Output schema '{{ref}}' is not valid JSON: {{error}}",
            "not_object": "Output schema '{{ref}}' must be a JSON object, got {{kind}}",
            "unsatisfiable_required": (
                "Output schema '{{ref}}': {{path}} requires '{{key}}' but defines no such "
                "property and sets additionalProperties: false; no output can ever validate."
            ),
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
                continue
            for path, key in unsatisfiable_required(loaded):
                context.report(
                    ReportDescriptor(
                        message_id="unsatisfiable_required",
                        data={"ref": ref.value, "path": path, "key": key},
                        location=Location(file=harness.file_path),
                    )
                )


def unsatisfiable_required(schema: object, path: str = "root") -> list[tuple[str, str]]:
    """Keys an object schema requires but can never carry: ``required`` names a
    key absent from ``properties`` while ``additionalProperties`` is ``false``
    and no ``patternProperties`` could admit it. Walks nested object schemas,
    arrays and combinators; anything it does not understand is left alone."""
    out: list[tuple[str, str]] = []
    if isinstance(schema, list):
        for i, item in enumerate(schema):
            out.extend(unsatisfiable_required(item, f"{path}[{i}]"))
        return out
    if not isinstance(schema, dict):
        return out
    required = schema.get("required")
    props = schema.get("properties")
    if (
        isinstance(required, list)
        and schema.get("additionalProperties") is False
        and not schema.get("patternProperties")
        and (props is None or isinstance(props, dict))
    ):
        defined = set(props or {})
        for key in required:
            if isinstance(key, str) and key not in defined:
                out.append((path, key))
    if isinstance(props, dict):
        for name, sub in props.items():
            out.extend(unsatisfiable_required(sub, f"{path}.{name}"))
    for key in ("items", "additionalProperties", "not", "if", "then", "else"):
        out.extend(unsatisfiable_required(schema.get(key), f"{path}.{key}"))
    for key in ("allOf", "anyOf", "oneOf", "prefixItems"):
        out.extend(unsatisfiable_required(schema.get(key), f"{path}.{key}"))
    defs = schema.get("$defs") or schema.get("definitions")
    if isinstance(defs, dict):
        for name, sub in defs.items():
            out.extend(unsatisfiable_required(sub, f"{path}.$defs.{name}"))
    return out
