"""Skill submission scanner for ABEvalFlow pipeline integration.

Scans a skill submission directory using harness-eval's rule engine and
produces pipeline-compatible JSON output with security and quality findings.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

from harness_eval.core.types import ComponentType
from harness_eval.inspection.types import Finding, InspectionResult, Severity

logger = logging.getLogger(__name__)

_EXCLUDED_DIRS = {".git", "node_modules", "vendor", "__pycache__", ".venv"}

_CRITICAL_RULES = frozenset(
    {
        "security/stealth-persistence",
        "security/prompt-exfiltration",
    }
)

_SECURITY_PREFIXES = ("security/",)


@dataclass
class SubmissionScanResult:
    security_findings: list[dict] = field(default_factory=list)
    quality_findings: list[dict] = field(default_factory=list)
    inspection_results: list[InspectionResult] = field(default_factory=list)
    total_errors: int = 0
    total_warnings: int = 0
    verdict: str = "SAFE"


def _is_excluded(path: Path, base: Path) -> bool:
    try:
        parts = path.relative_to(base).parts
    except ValueError:
        return False
    return bool(_EXCLUDED_DIRS.intersection(parts))


def _pipeline_severity(finding: Finding) -> str:
    if finding.severity == Severity.ERROR:
        if finding.rule_id in _CRITICAL_RULES:
            return "critical"
        return "high"
    if finding.severity == Severity.WARNING:
        if finding.rule_id.startswith(("quality/", "submission/")):
            return "low"
        return "medium"
    return "info"


def _pipeline_category(rule_id: str) -> str:
    parts = rule_id.split("/", 1)
    if len(parts) == 2:
        return parts[1].replace("-", "_")
    return rule_id.replace("-", "_")


def _to_pipeline_finding(finding: Finding, submission_dir: Path) -> dict:
    file_path = ""
    line = 0
    if finding.location:
        try:
            file_path = str(Path(finding.location.file).relative_to(submission_dir))
        except ValueError:
            file_path = finding.location.file
        line = finding.location.start_line or 0

    return {
        "severity": _pipeline_severity(finding),
        "rule_id": finding.rule_id,
        "message": finding.message,
        "file_path": file_path,
        "category": _pipeline_category(finding.rule_id),
        "line": line,
    }


def _is_security_finding(finding: Finding) -> bool:
    return finding.rule_id.startswith(_SECURITY_PREFIXES)


def scan_submission(
    directory: Path,
    preset: dict[str, str],
    *,
    review: bool = False,
    provider: str | None = None,
    model: str | None = None,
) -> SubmissionScanResult:
    """Scan a skill submission directory for security and quality issues.

    Args:
        directory: Path to the submission directory.
        preset: Rule preset dict (rule_id -> severity).
        review: If True, run LLM semantic security review.
        provider: LLM provider for semantic review.
        model: LLM model for semantic review.

    Returns:
        SubmissionScanResult with pipeline-formatted findings.
    """
    from harness_eval.inspection.engine import lint, lint_text_file
    from harness_eval.inspection.parsers import parse_skill

    scan_state: dict = {"project_root": str(directory)}
    results: list[InspectionResult] = []

    skill_md_files = sorted(
        p for p in directory.rglob("SKILL.md") if not _is_excluded(p, directory)
    )
    skill_dirs = [p.parent for p in skill_md_files]

    all_skills = []
    for skill_dir in skill_dirs:
        try:
            all_skills.append(parse_skill(str(skill_dir)))
        except Exception:
            logger.warning("Failed to parse skill: %s", skill_dir)

    for skill_dir in skill_dirs:
        try:
            result = lint(
                str(skill_dir),
                preset,
                scan_state=scan_state,
                all_skills=all_skills,
            )
            results.append(result)
        except Exception:
            logger.warning("Failed to lint skill: %s", skill_dir)

    all_md = sorted(
        p
        for p in directory.rglob("*.md")
        if not _is_excluded(p, directory) and p.name != "SKILL.md"
    )
    for md_file in all_md:
        try:
            result = lint_text_file(
                str(md_file),
                ComponentType.UNCATEGORIZED,
                preset,
                scan_state=scan_state,
            )
            results.append(result)
        except Exception:
            logger.warning("Failed to scan: %s", md_file)

    if review:
        _run_llm_review(directory, results, provider=provider, model=model)

    security_findings: list[dict] = []
    quality_findings: list[dict] = []
    total_errors = 0
    total_warnings = 0

    for result in results:
        total_errors += result.error_count
        total_warnings += result.warning_count
        for finding in result.diagnostics:
            pipeline_finding = _to_pipeline_finding(finding, directory)
            if _is_security_finding(finding):
                security_findings.append(pipeline_finding)
            else:
                quality_findings.append(pipeline_finding)

    if total_errors > 0:
        verdict = "UNSAFE"
    elif total_warnings > 0:
        verdict = "CAUTION"
    else:
        verdict = "SAFE"

    return SubmissionScanResult(
        security_findings=security_findings,
        quality_findings=quality_findings,
        inspection_results=results,
        total_errors=total_errors,
        total_warnings=total_warnings,
        verdict=verdict,
    )


def _run_llm_review(
    directory: Path,
    results: list[InspectionResult],
    *,
    provider: str | None = None,
    model: str | None = None,
) -> None:
    """Run LLM semantic security review on submission files."""
    try:
        from harness_eval.rubric.checker import RubricChecker
        from harness_eval.rubric.dimensions import SECURITY_REVIEW_CATEGORIES
    except ImportError:
        logger.warning("LLM review requires rubric module; skipping")
        return

    md_files = sorted(p for p in directory.rglob("*.md") if not _is_excluded(p, directory))
    if not md_files:
        return

    contents: list[tuple[str, str]] = []
    for md_file in md_files:
        try:
            content = md_file.read_text(encoding="utf-8", errors="replace")
            rel_path = str(md_file.relative_to(directory))
            contents.append((rel_path, content))
        except OSError:
            continue

    if not contents:
        return

    try:
        checker = RubricChecker(provider=provider, model=model)
        combined = "\n\n---\n\n".join(f"### {path}\n\n{content}" for path, content in contents)
        llm_findings = checker.check(
            combined,
            categories=SECURITY_REVIEW_CATEGORIES,
            component_name="submission",
        )
        if llm_findings and results:
            for f in llm_findings:
                results[0].diagnostics.append(f)
    except Exception:
        logger.warning("LLM semantic review failed", exc_info=True)
