"""Combine inspection passes that looked at the same components."""

from __future__ import annotations

from harness_eval.inspection.types import Finding, InspectionResult, RuleResult, Severity

_SEV_RANK = {Severity.INFO: 0, Severity.WARNING: 1, Severity.ERROR: 2}


def _finding_key(finding: Finding) -> tuple[str, str, int | None, str]:
    return (
        finding.rule_id,
        finding.location.file,
        finding.location.start_line,
        finding.message,
    )


def _copy_result(result: InspectionResult) -> InspectionResult:
    return InspectionResult(
        target_path=result.target_path,
        target_name=result.target_name,
        tokens=result.tokens,
        target_type=result.target_type,
        diagnostics=list(result.diagnostics),
        rules_run=list(result.rules_run),
        suppression_count=result.suppression_count,
    )


def _prefer(current: Finding, incoming: Finding) -> Finding:
    if _SEV_RANK[incoming.severity] > _SEV_RANK[current.severity]:
        return incoming
    return current


def _merge_rules(existing: list[RuleResult], incoming: list[RuleResult]) -> None:
    by_id = {rule.rule_id: index for index, rule in enumerate(existing)}
    for rule in incoming:
        index = by_id.get(rule.rule_id)
        if index is None:
            existing.append(rule)
            by_id[rule.rule_id] = len(existing) - 1
        elif existing[index].passed and not rule.passed:
            existing[index] = rule


def _recount(result: InspectionResult) -> None:
    result.error_count = sum(1 for d in result.diagnostics if d.severity == Severity.ERROR)
    result.warning_count = sum(1 for d in result.diagnostics if d.severity == Severity.WARNING)
    result.info_count = sum(1 for d in result.diagnostics if d.severity == Severity.INFO)
    result.fixable_count = sum(1 for d in result.diagnostics if d.fix is not None)


def merge_inspection_results(*groups: list[InspectionResult]) -> list[InspectionResult]:
    """Keep every distinct finding from each pass.

    The same finding reported twice (same rule, file, line, and message) keeps
    the higher severity. A second hit from the same rule, with a different
    message, is kept. The inputs are not modified.
    """
    merged: list[InspectionResult] = []
    by_component: dict[tuple[str, str], InspectionResult] = {}

    for group in groups:
        for result in group:
            key = (result.target_type, result.target_name)
            existing = by_component.get(key)
            if existing is None:
                copy = _copy_result(result)
                by_component[key] = copy
                merged.append(copy)
                continue

            by_finding = {_finding_key(d): index for index, d in enumerate(existing.diagnostics)}
            for finding in result.diagnostics:
                index = by_finding.get(_finding_key(finding))
                if index is None:
                    existing.diagnostics.append(finding)
                    by_finding[_finding_key(finding)] = len(existing.diagnostics) - 1
                else:
                    existing.diagnostics[index] = _prefer(existing.diagnostics[index], finding)
            _merge_rules(existing.rules_run, result.rules_run)

    for result in merged:
        _recount(result)
    return merged
