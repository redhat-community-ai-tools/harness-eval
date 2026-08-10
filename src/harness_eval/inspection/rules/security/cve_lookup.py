from __future__ import annotations

import json
import re
from pathlib import Path

from harness_eval.inspection.types import (
    Location,
    ReportDescriptor,
    RuleCategory,
    RuleContext,
    RuleMeta,
    Severity,
)

_PIP_REQ_RE = re.compile(r"^([a-zA-Z0-9_-]+)\s*(?:[=<>!~]+\s*(.+))?$")
_TIMEOUT = 10


def _parse_requirements_txt(path: Path) -> list[dict[str, str]]:
    deps: list[dict[str, str]] = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        m = _PIP_REQ_RE.match(line)
        if m:
            deps.append({"name": m.group(1), "version": m.group(2) or "", "ecosystem": "PyPI"})
    return deps


def _parse_pyproject_toml(path: Path) -> list[dict[str, str]]:
    deps: list[dict[str, str]] = []
    content = path.read_text()
    in_deps = False
    for line in content.splitlines():
        stripped = line.strip()
        if stripped == "dependencies = [" or stripped.startswith("dependencies ="):
            in_deps = True
        if in_deps:
            if stripped == "]":
                break
            dep = stripped.strip('",').strip()
            if dep:
                m = _PIP_REQ_RE.match(dep)
                if m:
                    deps.append(
                        {"name": m.group(1), "version": m.group(2) or "", "ecosystem": "PyPI"}
                    )
    return deps


def _parse_package_json(path: Path) -> list[dict[str, str]]:
    deps: list[dict[str, str]] = []
    try:
        data = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return deps
    for section in ("dependencies", "devDependencies"):
        for name, version in (data.get(section) or {}).items():
            deps.append({"name": name, "version": version.lstrip("^~>=<"), "ecosystem": "npm"})
    return deps


def _query_osv(deps: list[dict[str, str]]) -> list[dict[str, str]] | None:
    try:
        import urllib.request
    except ImportError:
        return None

    queries: list[dict[str, object]] = []
    for dep in deps:
        q: dict[str, object] = {"package": {"name": dep["name"], "ecosystem": dep["ecosystem"]}}
        if dep["version"]:
            q["version"] = dep["version"]
        queries.append(q)

    payload = json.dumps({"queries": queries}).encode()
    req = urllib.request.Request(
        "https://api.osv.dev/v1/querybatch",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            data = json.loads(resp.read())
    except Exception:
        return None

    results: list[dict[str, str]] = []
    for i, result in enumerate(data.get("results", [])):
        vulns = result.get("vulns", [])
        if vulns:
            dep = deps[i] if i < len(deps) else {"name": "unknown", "ecosystem": "unknown"}
            for vuln in vulns:
                vuln_id = vuln.get("id", "unknown")
                summary = vuln.get("summary", "No summary available")
                severity_list = vuln.get("severity", [])
                severity_str = "UNKNOWN"
                for sev in severity_list:
                    if "score" in sev:
                        score = float(sev["score"])
                        if score >= 9.0:
                            severity_str = "CRITICAL"
                        elif score >= 7.0:
                            severity_str = "HIGH"
                        elif score >= 4.0:
                            severity_str = "MEDIUM"
                        else:
                            severity_str = "LOW"
                        break

                results.append(
                    {
                        "package": dep["name"],
                        "ecosystem": dep["ecosystem"],
                        "vuln_id": vuln_id,
                        "summary": summary[:120],
                        "severity": severity_str,
                    }
                )
    return results


class CveLookup:
    meta: RuleMeta = RuleMeta(
        id="security/cve-lookup",
        default_severity=Severity.WARNING,
        fixable=False,
        description="Check skill dependencies for known CVEs via OSV.dev",
        category=RuleCategory.SECURITY,
        messages={
            "cve_found": "{{package}} ({{ecosystem}}): {{vuln_id}} [{{severity}}] - {{summary}}",
            "cve_lookup_skipped": "CVE lookup skipped: {{reason}}",
            "cve_no_deps": "No dependency files found in skill directory; CVE lookup skipped.",
        },
        frameworks={"owasp_llm": "LLM05"},
        default_suggestion="Update the affected package to a patched version.",
    )

    def create(self, context: RuleContext) -> None:
        skill = context.skill
        if not skill.dir_path:
            return
        skill_dir = Path(skill.dir_path)
        if not skill_dir.is_dir():
            return

        deps: list[dict[str, str]] = []

        req_txt = skill_dir / "requirements.txt"
        if req_txt.is_file():
            deps.extend(_parse_requirements_txt(req_txt))

        pyproject = skill_dir / "pyproject.toml"
        if pyproject.is_file():
            deps.extend(_parse_pyproject_toml(pyproject))

        pkg_json = skill_dir / "package.json"
        if pkg_json.is_file():
            deps.extend(_parse_package_json(pkg_json))

        if not deps:
            return

        vulns = _query_osv(deps)
        if vulns is None:
            context.report(
                ReportDescriptor(
                    message_id="cve_lookup_skipped",
                    data={"reason": "network error or OSV.dev unavailable"},
                    location=Location(file=skill.skill_md_path),
                    severity_override=Severity.INFO,
                )
            )
            return

        for vuln in vulns:
            sev_map = {
                "CRITICAL": Severity.ERROR,
                "HIGH": Severity.ERROR,
                "MEDIUM": Severity.WARNING,
                "LOW": Severity.INFO,
                "UNKNOWN": Severity.WARNING,
            }
            sev_override = sev_map.get(vuln["severity"], Severity.WARNING)

            context.report(
                ReportDescriptor(
                    message_id="cve_found",
                    data={
                        "package": vuln["package"],
                        "ecosystem": vuln["ecosystem"],
                        "vuln_id": vuln["vuln_id"],
                        "severity": vuln["severity"],
                        "summary": vuln["summary"],
                    },
                    location=Location(file=skill.skill_md_path),
                    severity_override=sev_override,
                )
            )
