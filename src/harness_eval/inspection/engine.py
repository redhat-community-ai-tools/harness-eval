"""Lint orchestration for inspection. Runs rules against parsed components."""

from __future__ import annotations

import logging
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

from harness_eval.core.types import ComponentType
from harness_eval.inspection.parsers import (
    parse_agent,
    parse_claude_md,
    parse_command,
    parse_hooks,
    parse_mcp_config_file,
    parse_skill,
)
from harness_eval.inspection.registry import (
    DEPRECATED_RULES,
    get_all_rules,
    suggest_rule_id,
)
from harness_eval.inspection.suppression import is_suppressed, parse_suppressions
from harness_eval.inspection.types import (
    Finding,
    InspectionResult,
    Location,
    ParsedAgent,
    ParsedClaudeMd,
    ParsedCommand,
    ParsedHooks,
    ParsedMcpConfig,
    ParsedSkill,
    ReportDescriptor,
    Rule,
    RuleCategory,
    RuleContext,
    RuleResult,
    Severity,
)

logger = logging.getLogger(__name__)

_INTERPOLATION_RE = re.compile(r"\{\{(\w+)\}\}")


def _is_nested_repo(child: Path, scan_root: Path) -> bool:
    """True if any directory between scan_root and child is a separate git repo."""
    current = child if child.is_dir() else child.parent
    scan_root = scan_root.resolve()
    current = current.resolve()
    while current != scan_root and len(current.parts) > len(scan_root.parts):
        if (current / ".git").exists():
            return True
        current = current.parent
    return False


def _interpolate(template: str, data: dict[str, str | int] | None) -> str:
    if not data:
        return template
    return _INTERPOLATION_RE.sub(lambda m: str(data.get(m.group(1), m.group(0))), template)


def _resolve_severity(
    rule: Rule,
    config_rules: dict[str, str | list[Any]],
) -> tuple[Severity, list[Any]] | None:
    """Determine effective severity and options for a rule.

    Returns (severity, options), or None if the rule should be skipped.
    """
    severity_config = config_rules.get(rule.meta.id)
    if severity_config == "off":
        return None

    if severity_config is None and config_rules and not rule.meta.id.startswith("custom/"):
        return None

    explicitly_configured = severity_config is not None

    if isinstance(severity_config, list) and len(severity_config) > 0:
        sev_str = severity_config[0]
        options = severity_config[1:]
    elif isinstance(severity_config, str):
        sev_str = severity_config
        options = []
    else:
        sev_str = rule.meta.default_severity.value
        options = []

    if sev_str == "off":
        return None

    try:
        severity = Severity(sev_str)
    except ValueError:
        severity = rule.meta.default_severity

    return severity, options, explicitly_configured


def _make_report_fn(
    rule_id: str,
    severity: Severity,
    meta_messages: dict[str, str],
    category: RuleCategory,
    fixable: bool,
    file_path: str,
    suppressions_by_file: dict[str, dict[int | None, set[str]]],
    findings: list[Finding],
    suppression_counter: list[int],
    explicitly_configured: bool = False,
    default_suggestion: str | None = None,
) -> Callable[[ReportDescriptor], None]:
    """Build a report callback for a single rule.

    Uses a mutable list for the suppression counter so the caller can read
    the updated value after all rules have run.
    """

    def report(descriptor: ReportDescriptor) -> None:
        loc = descriptor.location or Location(file=file_path)
        sups = suppressions_by_file.get(loc.file, suppressions_by_file.get(file_path, {}))
        if is_suppressed(sups, rule_id, loc.start_line):
            suppression_counter[0] += 1
            return
        template = meta_messages.get(descriptor.message_id, descriptor.message_id)
        message = _interpolate(template, descriptor.data)
        override = descriptor.severity_override
        if explicitly_configured and override and override != Severity.INFO:
            effective_severity = severity
        else:
            effective_severity = override or severity
        findings.append(
            Finding(
                rule_id=rule_id,
                severity=effective_severity,
                message=message,
                location=loc,
                category=category,
                fix=descriptor.fix if fixable else None,
                suggestion=descriptor.suggestion or default_suggestion,
            )
        )

    return report


def _parse_errors_to_findings(
    parse_errors: list[str],
    file_path: str,
    category: RuleCategory | str = "structural",
) -> list[Finding]:
    """Convert parse errors into Finding objects."""
    return [
        Finding(
            rule_id="parser",
            severity=Severity.ERROR,
            message=error,
            location=Location(file=file_path),
            category=category,  # type: ignore[arg-type]
        )
        for error in parse_errors
    ]


def _run_rules(
    target_type: ComponentType,
    file_path: str,
    raw_content: str,
    skill: ParsedSkill | None,
    target: Any,
    config_rules: dict[str, str | list[Any]] | None,
    all_skills: list[ParsedSkill] | None = None,
    all_commands: list[ParsedCommand] | None = None,
    scan_state: dict[str, Any] | None = None,
    source_tool: str | None = None,
) -> tuple[list[Finding], int, list[RuleResult]]:
    """Run rules for a given target type. Returns (findings, suppression_count, rules_run)."""
    findings: list[Finding] = []
    rules_run: list[RuleResult] = []
    suppression_counter = [0]
    suppressions_by_file: dict[str, dict[int | None, set[str]]] = {}
    if raw_content:
        suppressions_by_file[file_path] = parse_suppressions(raw_content, file_path=file_path)
    if skill and skill.sub_file_contents and skill.dir_path:
        from pathlib import Path as _Path

        skill_dir = _Path(skill.dir_path)
        for rel_path, content in skill.sub_file_contents.items():
            if content:
                abs_path = str(skill_dir / rel_path)
                sups = parse_suppressions(content, file_path=abs_path)
                if sups:
                    suppressions_by_file[abs_path] = sups
    config_rules = config_rules or {}
    scan_state = scan_state if scan_state is not None else {}

    rules = get_all_rules()

    for rule in rules:
        if rule.meta.target_type != target_type:
            continue

        if (
            rule.meta.tools is not None
            and source_tool is not None
            and source_tool not in rule.meta.tools
        ):
            continue

        resolved = _resolve_severity(rule, config_rules)
        if resolved is None:
            continue
        severity, options, explicitly_configured = resolved

        findings_before = len(findings)

        context = RuleContext(
            report=_make_report_fn(
                rule.meta.id,
                severity,
                rule.meta.messages,
                rule.meta.category,
                rule.meta.fixable,
                file_path,
                suppressions_by_file,
                findings,
                suppression_counter,
                explicitly_configured,
                rule.meta.default_suggestion,
            ),
            severity=severity,
            skill=skill,
            options=options,
            target=target,
            all_skills=all_skills or [],
            all_commands=all_commands or [],
            scan_state=scan_state,
            source_tool=source_tool,
        )
        rule.create(context)

        passed = len(findings) == findings_before
        rules_run.append(
            RuleResult(
                rule_id=rule.meta.id,
                description=rule.meta.description,
                passed=passed,
            )
        )

    return findings, suppression_counter[0], rules_run


def _build_result(
    target_path: str,
    target_name: str,
    tokens: int,
    target_type: str,
    diagnostics: list[Finding],
    suppression_count: int,
    rules_run: list[RuleResult] | None = None,
) -> InspectionResult:
    return InspectionResult(
        target_path=target_path,
        target_name=target_name,
        tokens=tokens,
        target_type=target_type,
        diagnostics=diagnostics,
        rules_run=rules_run or [],
        error_count=sum(1 for d in diagnostics if d.severity == Severity.ERROR),
        warning_count=sum(1 for d in diagnostics if d.severity == Severity.WARNING),
        info_count=sum(1 for d in diagnostics if d.severity == Severity.INFO),
        fixable_count=sum(1 for d in diagnostics if d.fix is not None),
        suppression_count=suppression_count,
    )


def lint(
    skill_path: str,
    config_rules: dict[str, str | list[Any]] | None = None,
    scan_state: dict[str, Any] | None = None,
    all_skills: list[ParsedSkill] | None = None,
    all_commands: list[ParsedCommand] | None = None,
    source_tool: str | None = None,
    parsed: ParsedSkill | None = None,
) -> InspectionResult:
    """Lint a single skill directory or SKILL.md file."""
    skill = parsed if parsed is not None else parse_skill(skill_path)
    diagnostics = _parse_errors_to_findings(
        skill.parse_errors,
        skill.skill_md_path,
    )

    rule_diags, suppression_count, rules_run = _run_rules(
        ComponentType.SKILL,
        skill.skill_md_path,
        skill.raw_content,
        skill=skill,
        target=skill,
        config_rules=config_rules,
        scan_state=scan_state,
        all_skills=all_skills,
        all_commands=all_commands,
        source_tool=source_tool,
    )
    diagnostics.extend(rule_diags)

    return _build_result(
        skill_path,
        skill.dir_name,
        skill.tokens,
        "skill",
        diagnostics,
        suppression_count,
        rules_run,
    )


def lint_command(
    command_path: str,
    config_rules: dict[str, str | list[Any]] | None = None,
    all_skills: list[ParsedSkill] | None = None,
    all_commands: list[ParsedCommand] | None = None,
    scan_state: dict[str, Any] | None = None,
    source_tool: str | None = None,
    parsed: ParsedCommand | None = None,
) -> InspectionResult:
    """Lint a single command directory."""
    cmd = parsed if parsed is not None else parse_command(command_path)
    diagnostics = _parse_errors_to_findings(cmd.parse_errors, cmd.command_md_path)

    rule_diags, suppression_count, rules_run = _run_rules(
        ComponentType.COMMAND,
        cmd.command_md_path,
        cmd.raw_content,
        skill=None,
        target=cmd,
        config_rules=config_rules,
        all_skills=all_skills,
        all_commands=all_commands,
        scan_state=scan_state,
        source_tool=source_tool,
    )
    diagnostics.extend(rule_diags)

    return _build_result(
        command_path,
        cmd.dir_name,
        cmd.tokens,
        "command",
        diagnostics,
        suppression_count,
        rules_run,
    )


def lint_claude_md(
    file_path: str,
    config_rules: dict[str, str | list[Any]] | None = None,
    all_skills: list[ParsedSkill] | None = None,
    scan_state: dict[str, Any] | None = None,
    source_tool: str | None = None,
    parsed: ParsedClaudeMd | None = None,
) -> InspectionResult:
    """Lint a CLAUDE.md file."""
    claude_md = parsed if parsed is not None else parse_claude_md(file_path)
    diagnostics = _parse_errors_to_findings(claude_md.parse_errors, file_path)

    rule_diags, suppression_count, rules_run = _run_rules(
        ComponentType.CLAUDE_MD,
        file_path,
        claude_md.raw_content,
        skill=None,
        target=claude_md,
        config_rules=config_rules,
        all_skills=all_skills,
        scan_state=scan_state,
        source_tool=source_tool,
    )
    diagnostics.extend(rule_diags)

    return _build_result(
        file_path,
        Path(file_path).name,
        claude_md.tokens,
        "claude_md",
        diagnostics,
        suppression_count,
        rules_run,
    )


def lint_hooks(
    settings_path: str,
    config_rules: dict[str, str | list[Any]] | None = None,
    scan_state: dict[str, Any] | None = None,
    source_tool: str | None = None,
    parsed: ParsedHooks | None = None,
) -> InspectionResult:
    """Lint hooks from settings.json."""
    hooks = parsed if parsed is not None else parse_hooks(settings_path)
    diagnostics = _parse_errors_to_findings(hooks.parse_errors, settings_path)

    rule_diags, suppression_count, rules_run = _run_rules(
        ComponentType.HOOKS,
        settings_path,
        hooks.raw_content,
        skill=None,
        target=hooks,
        config_rules=config_rules,
        scan_state=scan_state,
        source_tool=source_tool,
    )
    diagnostics.extend(rule_diags)

    return _build_result(
        settings_path,
        "hooks",
        0,
        "hooks",
        diagnostics,
        suppression_count,
        rules_run,
    )


def lint_agent(
    agent_path: str,
    config_rules: dict[str, str | list[Any]] | None = None,
    all_skills: list[ParsedSkill] | None = None,
    scan_state: dict[str, Any] | None = None,
    source_tool: str | None = None,
    parsed: ParsedAgent | None = None,
) -> InspectionResult:
    """Lint a single agent .md file."""
    agent = parsed if parsed is not None else parse_agent(agent_path)
    diagnostics = _parse_errors_to_findings(agent.parse_errors, agent.agent_md_path)

    rule_diags, suppression_count, rules_run = _run_rules(
        ComponentType.AGENT,
        agent.agent_md_path,
        agent.raw_content,
        skill=None,
        target=agent,
        config_rules=config_rules,
        all_skills=all_skills,
        scan_state=scan_state,
        source_tool=source_tool,
    )
    diagnostics.extend(rule_diags)

    return _build_result(
        agent_path,
        agent.file_name.removesuffix(".md"),
        agent.tokens,
        "agent",
        diagnostics,
        suppression_count,
        rules_run,
    )


def lint_mcp_config(
    mcp_config_path: str,
    config_rules: dict[str, str | list[Any]] | None = None,
    scan_state: dict[str, Any] | None = None,
    source_tool: str | None = None,
    parsed: ParsedMcpConfig | None = None,
) -> InspectionResult:
    """Lint an MCP configuration file."""
    mcp = parsed if parsed is not None else parse_mcp_config_file(mcp_config_path)
    if not mcp.raw_content and mcp.parse_errors:
        return _build_result(mcp_config_path, Path(mcp_config_path).name, 0, "mcp_config", [], 0)

    rule_diags, suppression_count, rules_run = _run_rules(
        ComponentType.MCP_CONFIG,
        mcp.file_path,
        mcp.raw_content,
        skill=None,
        target=mcp,
        config_rules=config_rules,
        scan_state=scan_state,
        source_tool=source_tool,
    )

    return _build_result(
        mcp.file_path,
        Path(mcp.file_path).name,
        mcp.tokens,
        "mcp_config",
        rule_diags,
        suppression_count,
        rules_run,
    )


_SECURITY_ONLY_RULES = {
    "security/no-prompt-injection",
    "security/no-credential-access",
    "security/reverse-shell",
    "security/obfuscation",
    "security/data-exfiltration",
    "security/mcp-tool-poisoning",
    "security/coercive-override",
    "security/memory-write-unscoped",
    "security/prompt-exfiltration",
    "security/stealth-persistence",
    "security/unbounded-delegation",
}


def lint_text_file(
    file_path: str,
    component_type: ComponentType,
    config_rules: dict[str, str | list[Any]] | None = None,
    scan_state: dict[str, Any] | None = None,
    source_tool: str | None = None,
) -> InspectionResult:
    """Lint a generic text file (rule, output-style) using security-only rules."""
    path = Path(file_path)
    if not path.exists():
        return _build_result(file_path, path.stem, 0, component_type.value, [], 0)

    from harness_eval.utils.tokens import count_tokens

    raw_content = path.read_text(encoding="utf-8", errors="replace")
    tokens = count_tokens(raw_content)

    base = config_rules or {}
    if base:
        # An explicit rule set (a preset or the gate) was passed: honor it, so a
        # security rule runs only if the set enables it; disable the rest. Without
        # this, presets that omit these rules on purpose (gate, scan, pre-workflow)
        # would still fire them on generic text files (CI workflows, shell scripts)
        # and leak false positives. Keep every key present (unlisted -> "off") so the
        # config stays non-empty: an empty config means "no filter, run everything".
        security_config: dict[str, str | list[Any]] = {
            rid: base.get(rid, "off") for rid in _SECURITY_ONLY_RULES
        }
    else:
        # No explicit config (bare single-file scan): run the full security set.
        security_config = {rid: "warning" for rid in _SECURITY_ONLY_RULES}

    dummy_skill = ParsedSkill(
        dir_path=str(path.parent),
        dir_name=path.parent.name,
        skill_md_path=file_path,
        raw_content=raw_content,
        frontmatter={},
        raw_frontmatter="",
        frontmatter_start_line=0,
        body=raw_content,
        body_start_line=1,
        files=[path.name],
        tokens=tokens,
    )

    rule_diags, suppression_count, rules_run = _run_rules(
        ComponentType.SKILL,
        file_path,
        raw_content,
        skill=dummy_skill,
        target=dummy_skill,
        config_rules=security_config,
        scan_state=scan_state,
        source_tool=source_tool,
    )

    return _build_result(
        file_path,
        path.stem,
        tokens,
        component_type.value,
        rule_diags,
        suppression_count,
        rules_run,
    )


_warned_config_rules: set[str] = set()


def _warn_unknown_config_rules(config_rules: dict[str, str | list[Any]]) -> None:
    """Log warnings for rule IDs in config that don't match any registered rule."""
    all_rule_ids = {r.meta.id for r in get_all_rules()}
    for rule_id in config_rules:
        if rule_id in all_rule_ids or rule_id in _warned_config_rules:
            continue
        _warned_config_rules.add(rule_id)
        if rule_id in DEPRECATED_RULES:
            logger.warning(
                "Config references removed rule '%s'; it is now covered by '%s'.",
                rule_id,
                DEPRECATED_RULES[rule_id],
            )
            continue
        suggestions = suggest_rule_id(rule_id)
        if suggestions:
            logger.warning(
                "Config references unknown rule '%s'. Did you mean: %s?",
                rule_id,
                ", ".join(suggestions),
            )
        else:
            logger.warning("Config references unknown rule '%s'.", rule_id)


def inspect_setup(
    setup: Any,
    config_rules: dict[str, str | list[Any]] | None = None,
    *,
    load_target_yaml: bool = False,
) -> list[InspectionResult]:
    """Run inspection on all components in a setup.

    YAML under ``<setup>/.harness-eval/rules`` is loaded only when
    *load_target_yaml* is true. Those rules are unregistered when this call
    returns so they cannot leak into a later scan in the same process.
    """
    loaded_yaml_ids: list[str] = []
    if load_target_yaml:
        from harness_eval.inspection.yaml_rules import load_yaml_rules_from_dir

        before_ids = {r.meta.id for r in get_all_rules()}
        load_yaml_rules_from_dir(Path(setup.path) / ".harness-eval" / "rules")
        loaded_yaml_ids = list({r.meta.id for r in get_all_rules()} - before_ids)
    try:
        return _inspect_setup(setup, config_rules)
    finally:
        from harness_eval.inspection.registry import unregister_rule

        for rid in loaded_yaml_ids:
            unregister_rule(rid)


def _inspect_setup(
    setup: Any,
    config_rules: dict[str, str | list[Any]] | None = None,
) -> list[InspectionResult]:
    """Run inspection on all components in a setup."""
    from harness_eval.core.types import ComponentType as CT

    if config_rules:
        _warn_unknown_config_rules(config_rules)

    scan_state: dict[str, Any] = {"project_root": setup.path}
    results: list[InspectionResult] = []

    from harness_eval.analysis.component_graph import build_component_graph

    # Discoverers store file paths. Parsers accept a file or a directory, so
    # pass comp.path through — do not re-derive command.md vs flat-file here.
    skill_comps = list(setup.by_type(CT.SKILL))
    command_comps = list(setup.by_type(CT.COMMAND))
    claude_comps = list(setup.by_type(CT.CLAUDE_MD))
    hooks_comps = list(setup.by_type(CT.HOOKS))
    agent_comps = list(setup.by_type(CT.AGENT))
    mcp_comps = list(setup.by_type(CT.MCP_CONFIG))

    all_skills = [parse_skill(c.path) for c in skill_comps]
    all_commands = [parse_command(c.path) for c in command_comps]
    all_claude = [parse_claude_md(c.path) for c in claude_comps]
    all_hooks = [parse_hooks(c.path) for c in hooks_comps]
    all_agents = [parse_agent(c.path) for c in agent_comps]
    all_mcp = [parse_mcp_config_file(c.path) for c in mcp_comps]

    scan_state["component_graph"] = build_component_graph(
        all_skills,
        all_commands,
        all_agents,
        all_hooks,
        mcp_config_paths=[c.path for c in mcp_comps],
    )

    lint_dispatch: dict[CT, Callable[..., InspectionResult]] = {
        CT.SKILL: lambda comp, parsed: lint(
            parsed.dir_path,
            config_rules,
            scan_state=scan_state,
            all_skills=all_skills,
            all_commands=all_commands,
            source_tool=comp.source_tool,
            parsed=parsed,
        ),
        CT.COMMAND: lambda comp, parsed: lint_command(
            parsed.command_md_path,
            config_rules,
            all_skills=all_skills,
            all_commands=all_commands,
            scan_state=scan_state,
            source_tool=comp.source_tool,
            parsed=parsed,
        ),
        CT.CLAUDE_MD: lambda comp, parsed: lint_claude_md(
            parsed.file_path,
            config_rules,
            all_skills=all_skills,
            scan_state=scan_state,
            source_tool=comp.source_tool,
            parsed=parsed,
        ),
        CT.HOOKS: lambda comp, parsed: lint_hooks(
            parsed.file_path,
            config_rules,
            scan_state=scan_state,
            source_tool=comp.source_tool,
            parsed=parsed,
        ),
        CT.AGENT: lambda comp, parsed: lint_agent(
            parsed.agent_md_path,
            config_rules,
            all_skills=all_skills,
            scan_state=scan_state,
            source_tool=comp.source_tool,
            parsed=parsed,
        ),
        CT.MCP_CONFIG: lambda comp, parsed: lint_mcp_config(
            parsed.file_path,
            config_rules,
            scan_state=scan_state,
            source_tool=comp.source_tool,
            parsed=parsed,
        ),
    }

    parsed_by_type: list[tuple[CT, list[Any], list[Any]]] = [
        (CT.SKILL, skill_comps, all_skills),
        (CT.COMMAND, command_comps, all_commands),
        (CT.CLAUDE_MD, claude_comps, all_claude),
        (CT.HOOKS, hooks_comps, all_hooks),
        (CT.AGENT, agent_comps, all_agents),
        (CT.MCP_CONFIG, mcp_comps, all_mcp),
    ]
    for ctype, comps, parsed_list in parsed_by_type:
        run = lint_dispatch[ctype]
        for comp, parsed in zip(comps, parsed_list, strict=True):
            results.append(run(comp, parsed))

    for ctype in (CT.RULE, CT.OUTPUT_STYLE, CT.UNCATEGORIZED):
        for comp in setup.by_type(ctype):
            results.append(
                lint_text_file(
                    comp.path,
                    ctype,
                    config_rules,
                    scan_state=scan_state,
                    source_tool=comp.source_tool,
                )
            )

    graph = scan_state.get("component_graph")
    if graph:
        from harness_eval.analysis.reachability import compute_reachability

        skill_descriptions: dict[str, str] = {}
        for s in all_skills:
            desc = s.frontmatter.get("description", "")
            if isinstance(desc, str) and desc:
                skill_descriptions[s.dir_name] = desc

        annotated_results: list[InspectionResult] = []
        for r in results:
            new_diags: list[Finding] = []
            for d in r.diagnostics:
                if d.category in (RuleCategory.SECURITY, RuleCategory.CROSS_COMPONENT):
                    reach = compute_reachability(graph, d.location.file, skill_descriptions)
                    new_diags.append(
                        Finding(
                            rule_id=d.rule_id,
                            severity=d.severity,
                            message=d.message,
                            location=d.location,
                            category=d.category,
                            fix=d.fix,
                            reachability="reachable" if reach.reachable else "unreachable",
                            suggestion=d.suggestion,
                        )
                    )
                else:
                    new_diags.append(d)
            annotated_results.append(
                InspectionResult(
                    target_path=r.target_path,
                    target_name=r.target_name,
                    tokens=r.tokens,
                    target_type=r.target_type,
                    diagnostics=new_diags,
                    rules_run=r.rules_run,
                    error_count=r.error_count,
                    warning_count=r.warning_count,
                    info_count=r.info_count,
                    fixable_count=r.fixable_count,
                    suppression_count=r.suppression_count,
                )
            )
        results = annotated_results

    return results


def lint_directory(
    scan_path: str,
    config_rules: dict[str, str | list[Any]] | None = None,
) -> list[InspectionResult]:
    """Lint all skills found under a directory."""
    path = Path(scan_path)
    results = []

    if path.is_file() and path.name.lower() == "skill.md":
        results.append(lint(str(path.parent), config_rules))
        return results

    if not path.is_dir():
        return results

    excluded = {".git", ".venv", "node_modules", "__pycache__", "tests"}
    skill_dirs: list[Path] = []
    for p in sorted(path.rglob("SKILL.md")):
        relative_parts = p.relative_to(path).parts
        if excluded.isdisjoint(relative_parts) and not _is_nested_repo(p, path):
            skill_dirs.append(p.parent)

    if not skill_dirs and (path / "SKILL.md").exists():
        skill_dirs = [path]

    seen: set[str] = set()
    for skill_dir in skill_dirs:
        resolved = str(skill_dir.resolve())
        if resolved not in seen:
            seen.add(resolved)
            results.append(lint(str(skill_dir), config_rules))

    return results
