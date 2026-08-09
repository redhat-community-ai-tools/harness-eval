from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from harness_eval.inspection.types import Finding
from harness_eval.utils.paths import is_within


@dataclass
class FixResult:
    file_path: str
    fixes_applied: int
    rule_ids: list[str]


def apply_fixes(diagnostics: list[Finding], project_root: Path | None = None) -> list[FixResult]:
    """Apply auto-fixes for diagnostics that have fix information.

    Groups fixes by file, applies in reverse line order to preserve line numbers.
    """
    fixable = [d for d in diagnostics if d.fix is not None and d.fix.replacement is not None]
    if not fixable:
        return []

    by_file: dict[str, list[Finding]] = {}
    for diag in fixable:
        by_file.setdefault(diag.location.file, []).append(diag)

    results = []
    for file_path, diags in by_file.items():
        path = Path(file_path)
        if not path.exists():
            continue
        if project_root is not None and not is_within(path, project_root):
            continue

        raw_bytes = path.read_bytes()
        line_ending = "\r\n" if b"\r\n" in raw_bytes else "\n"
        content = raw_bytes.decode("utf-8", errors="replace")
        lines = content.split(line_ending)
        rule_ids = []

        sorted_diags = sorted(
            diags,
            key=lambda d: d.location.start_line or 0,
            reverse=True,
        )

        for diag in sorted_diags:
            if diag.fix is None or diag.fix.replacement is None:
                continue
            line_num = diag.location.start_line
            if line_num is None or line_num < 1 or line_num > len(lines):
                continue
            lines[line_num - 1] = diag.fix.replacement
            rule_ids.append(diag.rule_id)

        path.write_text(line_ending.join(lines), encoding="utf-8")
        results.append(
            FixResult(
                file_path=file_path,
                fixes_applied=len(rule_ids),
                rule_ids=rule_ids,
            )
        )

    return results
