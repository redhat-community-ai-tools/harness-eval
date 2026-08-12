from __future__ import annotations

import re
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

_FRONTMATTER_RE = re.compile(r"^---\s*\n.*?\n---\s*", re.DOTALL)
_HEADING_RE = re.compile(r"^#.*\n?")
_EXCLUDED_DIRS = {".git", "node_modules", "vendor", "__pycache__", ".venv"}


class FileCompleteness:
    meta: RuleMeta = RuleMeta(
        id="submission/file-completeness",
        default_severity=Severity.WARNING,
        fixable=False,
        description="Submission files must have meaningful content",
        category=RuleCategory.CONTENT,
        messages={
            "thin_instruction": "instruction.md has only {{chars}} characters of body text",
            "thin_instruction_error": "instruction.md has only {{chars}} characters of body text",
            "no_assertions": "{{file}} has no assert statements or pytest.raises",
        },
        target_type=ComponentType.SKILL,
    )

    def create(self, context: RuleContext) -> None:
        if context.scan_state.get("_file_completeness_done"):
            return
        context.scan_state["_file_completeness_done"] = True

        project_root = context.scan_state.get("project_root")
        if not project_root:
            return

        root = Path(project_root)

        self._check_instruction(root, context)
        self._check_test_assertions(root, context)

    def _check_instruction(self, root: Path, context: RuleContext) -> None:
        instruction = root / "instruction.md"
        if not instruction.exists():
            return

        try:
            content = instruction.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return

        body = _FRONTMATTER_RE.sub("", content).strip()
        body = _HEADING_RE.sub("", body).strip()

        if len(body) < 50:
            severity_override = Severity.ERROR if len(body) < 10 else None
            msg_id = "thin_instruction_error" if len(body) < 10 else "thin_instruction"
            context.report(
                ReportDescriptor(
                    message_id=msg_id,
                    data={"chars": str(len(body))},
                    location=Location(file=str(instruction), start_line=1),
                    severity_override=severity_override,
                )
            )

    def _check_test_assertions(self, root: Path, context: RuleContext) -> None:
        tests_dir = root / "tests"
        if not tests_dir.is_dir():
            return

        for py_file in sorted(tests_dir.rglob("*.py")):
            if any(part in _EXCLUDED_DIRS for part in py_file.parts):
                continue
            try:
                content = py_file.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            if "assert" not in content and "pytest.raises" not in content:
                rel = str(py_file.relative_to(root))
                context.report(
                    ReportDescriptor(
                        message_id="no_assertions",
                        data={"file": rel},
                        location=Location(file=str(py_file), start_line=1),
                    )
                )
