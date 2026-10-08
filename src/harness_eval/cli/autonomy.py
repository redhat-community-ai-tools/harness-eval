"""harness-autonomy: the deterministic check a merge policy can trust.

Runs only rules whose effect is ``block`` (a decidable configuration defect)
or ``policy`` (a decidable fact whose acceptability is a trust decision), and
only at tiers that have passed the corpus (``gating`` and ``provisional``).
Heuristic (``signal``) and quality (``advice``) rules never take part, so a
finding here is a fact about the configuration, not a pattern match.

Exit codes: 0 PASS (no findings), 1 FAIL (a block finding), 2 REVIEW_REQUIRED
(policy findings only; a person or a trusted policy file has to accept them).
No LLM, no network, no rules loaded from the scanned tree.
"""

from __future__ import annotations

import fnmatch
import json as json_mod
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import click

from harness_eval.cli import cli
from harness_eval.cli._helpers import (
    emit_output,
    exclude_option,
    scan_limit_options,
    scan_limits_from,
)
from harness_eval.core.types import ComponentType
from harness_eval.inspection.types import Finding, InspectionResult, Severity, finding_data_field

EXIT_PASS = 0
EXIT_FAIL = 1
EXIT_REVIEW_REQUIRED = 2

_HARNESS_FS_RULES = ("harness/referenced-file-exists", "harness/output-schema-valid")


@dataclass(frozen=True)
class PolicyGrant:
    """One accepted policy fact from a trusted policy file."""

    rule: str
    file: str | None
    reason: str

    def covers(self, finding: Finding, scan_root: Path) -> bool:
        if finding.rule_id != self.rule:
            return False
        if self.file is None:
            return True
        path = Path(finding.location.file)
        try:
            rel = str(path.resolve().relative_to(scan_root.resolve()))
        except ValueError:
            rel = str(path)
        return fnmatch.fnmatch(rel, self.file) or fnmatch.fnmatch(path.name, self.file)


def load_policy(path: str | Path) -> tuple[list[PolicyGrant], list[str]]:
    """Read a policy file. Returns (grants, problems).

    Format (YAML or JSON)::

        accept:
          - rule: hooks/permission-prompt-disabled
            file: .claude/settings.json      # optional glob, relative to the scan root
            reason: approved by security, ticket SEC-123

    Every entry needs ``rule`` and a non-empty ``reason``. Only rules with
    effect=policy can be accepted; anything else is reported and ignored.
    """
    import yaml

    from harness_eval.inspection.registry import get_rule

    try:
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as e:
        return [], [f"policy file {path}: {e}"]
    if not isinstance(data, dict) or not isinstance(data.get("accept"), list):
        return [], [f"policy file {path}: expected a mapping with an 'accept' list"]
    grants: list[PolicyGrant] = []
    problems: list[str] = []
    for i, entry in enumerate(data["accept"]):
        if not isinstance(entry, dict) or not isinstance(entry.get("rule"), str):
            problems.append(f"policy entry {i}: needs a 'rule' string")
            continue
        rule_id = entry["rule"]
        reason = entry.get("reason")
        if not isinstance(reason, str) or not reason.strip():
            problems.append(f"policy entry {i} ({rule_id}): needs a non-empty 'reason'")
            continue
        rule = get_rule(rule_id)
        if rule is None:
            problems.append(f"policy entry {i}: unknown rule '{rule_id}'")
            continue
        if rule.meta.effect != "policy":
            problems.append(
                f"policy entry {i}: '{rule_id}' has effect={rule.meta.effect}; "
                "only policy rules can be accepted"
            )
            continue
        file_glob = entry.get("file")
        if file_glob is not None and not isinstance(file_glob, str):
            problems.append(f"policy entry {i} ({rule_id}): 'file' must be a string")
            continue
        grants.append(PolicyGrant(rule=rule_id, file=file_glob, reason=reason.strip()))
    return grants, problems


@dataclass
class AutonomyReport:
    verdict: str
    blocking: list[Finding] = field(default_factory=list)
    policy: list[Finding] = field(default_factory=list)
    waived: list[tuple[Finding, PolicyGrant]] = field(default_factory=list)
    info: list[Finding] = field(default_factory=list)
    coverage: dict[str, Any] = field(default_factory=dict)
    policy_problems: list[str] = field(default_factory=list)
    evidence: dict[str, Any] | None = None
    duration_seconds: float = 0.0

    @property
    def exit_code(self) -> int:
        return {"PASS": EXIT_PASS, "FAIL": EXIT_FAIL}.get(self.verdict, EXIT_REVIEW_REQUIRED)


def _finding_dict(d: Finding) -> dict[str, Any]:
    out: dict[str, Any] = {
        "rule": d.rule_id,
        "severity": d.severity.value,
        "file": d.location.file,
        "message": d.message,
        **finding_data_field(d),
    }
    if d.location.start_line is not None:
        out["line"] = d.location.start_line
    return out


def classify(
    results: list[InspectionResult],
    grants: list[PolicyGrant],
    scan_root: Path,
) -> AutonomyReport:
    from harness_eval.inspection.registry import get_rule

    report = AutonomyReport(verdict="PASS")
    for r in results:
        for d in r.diagnostics:
            if d.severity == Severity.INFO:
                report.info.append(d)
                continue
            rule = get_rule(d.rule_id)
            effect = rule.meta.effect if rule is not None else "block"
            if effect == "policy":
                grant = next((g for g in grants if g.covers(d, scan_root)), None)
                if grant is not None:
                    report.waived.append((d, grant))
                else:
                    report.policy.append(d)
            else:
                report.blocking.append(d)
    if report.blocking:
        report.verdict = "FAIL"
    elif report.policy:
        report.verdict = "REVIEW_REQUIRED"
    return report


def _coverage(
    setup: Any,
    results: list[InspectionResult],
    config_rules: dict[str, str],
    baseline_suppressed: int,
) -> dict[str, Any]:
    """What the verdict does and does not rest on."""
    from harness_eval.inspection.registry import get_rule
    from harness_eval.inspection.types import ParsedHarness

    components: dict[str, int] = {}
    for c in setup.components:
        components[c.component_type.value] = components.get(c.component_type.value, 0) + 1

    ran: set[str] = set()
    for r in results:
        ran.update(rr.rule_id for rr in r.rules_run)

    present = {c.component_type for c in setup.components}
    not_applicable: dict[str, list[str]] = {}
    for rid in sorted(config_rules):
        if rid in ran:
            continue
        rule = get_rule(rid)
        if rule is None:
            continue
        if not present.intersection(rule.meta.targets):
            targets = ", ".join(t.value for t in rule.meta.targets)
            reason = f"no {targets} component in the setup"
        elif rule.meta.tools:
            reason = f"only applies to {', '.join(rule.meta.tools)} components"
        else:
            reason = "no component of its type was linted"
        not_applicable.setdefault(reason, []).append(rid)

    skipped: list[dict[str, str]] = []
    for c in setup.by_type(ComponentType.HARNESS):
        parsed = c.parsed
        if isinstance(parsed, ParsedHarness) and parsed.fields is not None:
            f = parsed.fields
            if not f.layer_complete:
                skipped.append(
                    {
                        "component": f"harness/{c.name}",
                        "rules": ", ".join(_HARNESS_FS_RULES),
                        "reason": (
                            "tree is one layer of a composed configuration (overlay or org "
                            "config); references resolve against other layers at dispatch time"
                        ),
                    }
                )
            elif f.base and "://" in f.base:
                skipped.append(
                    {
                        "component": f"harness/{c.name}",
                        "rules": ", ".join(_HARNESS_FS_RULES),
                        "reason": f"inherits from remote base {f.base}; resources may be remote",
                    }
                )

    return {
        "rules_selected": len(config_rules),
        "rules_run": sorted(ran & set(config_rules)),
        "not_applicable": [
            {"reason": reason, "rules": rules} for reason, rules in sorted(not_applicable.items())
        ],
        "components": dict(sorted(components.items())),
        "skipped": skipped,
        "baseline_suppressed": baseline_suppressed,
    }


def format_json(report: AutonomyReport, setup_name: str) -> str:
    out: dict[str, Any] = {
        "command": "harness-autonomy",
        "setup": setup_name,
        "verdict": report.verdict,
        "exit_code": report.exit_code,
        "blocking": [_finding_dict(d) for d in report.blocking],
        "policy": [_finding_dict(d) for d in report.policy],
        "waived": [
            {**_finding_dict(d), "accepted_by": {"file": g.file, "reason": g.reason}}
            for d, g in report.waived
        ],
        "info": [_finding_dict(d) for d in report.info],
        "coverage": report.coverage,
        "policy_problems": report.policy_problems,
        "evidence": report.evidence,
        "duration_seconds": round(report.duration_seconds, 3),
    }
    return json_mod.dumps(out, indent=2)


def format_terminal(report: AutonomyReport, setup_name: str) -> str:
    lines = [f"harness-autonomy: {setup_name}", f"Verdict: {report.verdict}", ""]

    def _section(title: str, items: list[Finding]) -> None:
        if not items:
            return
        lines.append(f"{title} ({len(items)}):")
        for d in items:
            where = d.location.file
            if d.location.start_line is not None:
                where = f"{where}:{d.location.start_line}"
            lines.append(f"  {d.rule_id}\t{where}\t{d.message}")
        lines.append("")

    _section("Blocking", report.blocking)
    _section("Policy (needs a decision)", report.policy)
    if report.waived:
        lines.append(f"Waived by policy file ({len(report.waived)}):")
        for d, g in report.waived:
            lines.append(f"  {d.rule_id}\t{d.location.file}\t{g.reason}")
        lines.append("")
    _section("Info", report.info)
    if report.policy_problems:
        lines.append("Policy file problems:")
        lines.extend(f"  {p}" for p in report.policy_problems)
        lines.append("")

    cov = report.coverage
    if cov:
        lines.append("Coverage:")
        comps = ", ".join(f"{n} {t}" for t, n in cov.get("components", {}).items()) or "none"
        lines.append(f"  components: {comps}")
        lines.append(
            f"  rules: {len(cov.get('rules_run', []))} ran of {cov.get('rules_selected', 0)} selected"
        )
        for na in cov.get("not_applicable", []):
            lines.append(f"  not applicable ({na['reason']}): {', '.join(na['rules'])}")
        for sk in cov.get("skipped", []):
            lines.append(f"  skipped {sk['rules']} on {sk['component']}: {sk['reason']}")
        if cov.get("baseline_suppressed"):
            lines.append(f"  baseline suppressed: {cov['baseline_suppressed']} finding(s)")
        lines.append("")
    if report.evidence:
        ev = report.evidence
        rev = (ev.get("vcs") or {}).get("revision") or "not a git checkout"
        lines.append("Evidence:")
        lines.append(f"  fingerprint: {ev.get('setup_fingerprint')}")
        lines.append(f"  revision: {rev}")
        lines.append(f"  rules digest: {(ev.get('rules') or {}).get('digest')}")
    return "\n".join(lines).rstrip() + "\n"


@cli.command("harness-autonomy")
@click.argument("path", type=click.Path(exists=True, file_okay=False))
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["terminal", "json", "sarif"]),
    default="terminal",
    show_default=True,
)
@click.option(
    "--output",
    "output_path",
    type=click.Path(),
    default=None,
    help="Write output to a file instead of stdout.",
)
@click.option(
    "--policy",
    "policy_path",
    type=click.Path(exists=True, dir_okay=False),
    default=None,
    help=(
        "Trusted policy file whose 'accept' entries turn matching policy findings into "
        "waived ones. Keep it outside the scanned tree or protected by CODEOWNERS."
    ),
)
@click.option(
    "--baseline",
    "baseline_path",
    type=click.Path(exists=True, dir_okay=False),
    default=None,
    help="Baseline JSON file. Suppressed findings are counted in coverage, never hidden.",
)
@click.option(
    "--recursive", is_flag=True, help="Recursively search subdirectories for agent configs."
)
@exclude_option
@scan_limit_options
def harness_autonomy(
    path: str,
    fmt: str,
    output_path: str | None,
    policy_path: str | None,
    baseline_path: str | None,
    recursive: bool,
    exclude: tuple[str, ...],
    max_file_bytes: int,
    max_total_bytes: int,
    max_files: int,
    max_depth: int,
) -> None:
    """Decidable checks only, for an auto-merge policy.

    Runs the block and policy rules at gating and provisional tier. Exit 0
    PASS, 1 FAIL (a configuration defect), 2 REVIEW_REQUIRED (a policy fact
    nobody has accepted). Never loads an LLM, the network, or rules from the
    scanned tree.
    """
    t0 = time.monotonic()
    from harness_eval.config.presets import autonomy_rules
    from harness_eval.core.setup import discover_setup
    from harness_eval.inspection.engine import build_scan_catalog, inspect_setup
    from harness_eval.output.provenance import collect_scan_evidence

    config_rules: dict[str, Any] = dict(autonomy_rules())
    target = Path(path)
    setup = discover_setup(
        name=target.name,
        path=path,
        recursive=recursive,
        exclude=exclude,
        limits=scan_limits_from(max_file_bytes, max_total_bytes, max_files, max_depth),
    )
    scan_catalog = build_scan_catalog(path, load_target_yaml=False)
    results = inspect_setup(setup, config_rules, catalog=scan_catalog)

    baseline_suppressed = 0
    if baseline_path:
        from harness_eval.baseline import filter_baselined

        bl_data = json_mod.loads(Path(baseline_path).read_text())
        before = sum(len(r.diagnostics) for r in results)
        results = filter_baselined(results, bl_data)
        baseline_suppressed = before - sum(len(r.diagnostics) for r in results)

    grants: list[PolicyGrant] = []
    problems: list[str] = []
    if policy_path:
        grants, problems = load_policy(policy_path)

    report = classify(results, grants, target)
    report.policy_problems = problems
    report.coverage = _coverage(setup, results, config_rules, baseline_suppressed)
    evidence = collect_scan_evidence(
        setup,
        scan_catalog,
        config_rules,
        preset="autonomy",
        excludes=exclude,
        baseline_path=baseline_path,
        baseline_suppressed=baseline_suppressed,
    )
    report.evidence = evidence.to_dict()
    if policy_path:
        from harness_eval.output.provenance import file_digest

        report.evidence["policy"] = {"path": str(policy_path), "digest": file_digest(policy_path)}
    report.duration_seconds = time.monotonic() - t0

    if fmt == "sarif":
        from harness_eval.output.metadata import EvalMetadata
        from harness_eval.output.sarif import format_sarif

        metadata = EvalMetadata(
            version=EvalMetadata.get_version(),
            duration_seconds=report.duration_seconds,
            components_scanned=len(results),
            rules_checked=sum(len(r.rules_run) for r in results),
            invocation_source="cli",
            evidence=evidence,
        )
        sarif_doc = format_sarif(results, metadata, scan_root=path)
        sarif_doc["runs"][0].setdefault("properties", {})["harnessEval.autonomy"] = {
            "verdict": report.verdict,
            "exit_code": report.exit_code,
            "waived": len(report.waived),
            "coverage": report.coverage,
        }
        emit_output(json_mod.dumps(sarif_doc, indent=2), output_path)
    elif fmt == "json":
        emit_output(format_json(report, setup.name), output_path)
    else:
        emit_output(format_terminal(report, setup.name), output_path)

    if report.exit_code != EXIT_PASS:
        raise SystemExit(report.exit_code)
