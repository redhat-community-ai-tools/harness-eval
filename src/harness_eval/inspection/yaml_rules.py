"""Load declarative YAML rules alongside Python rules.

YAML rules support simple regex pattern matching on component content.
For complex logic (AST analysis, cross-component, taint tracking), use
Python rules instead.

YAML rule format:
    id: "custom/my-rule"
    severity: warning          # error, warning, info
    description: "What this rule checks"
    suggestion: "How to fix it"
    target: skill              # skill, command, agent, hooks, claude_md, mcp_config
    category: content          # content, security, structural, frontmatter
    patterns:
      - label: "dangerous pattern"
        regex: "rm\\s+-rf"
      - label: "another pattern"
        regex: "eval\\("
    message: "Found '{{label}}' on line {{line}}"
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from harness_eval.core.types import ComponentType
from harness_eval.inspection.registry import get_rule, register_rule
from harness_eval.inspection.types import (
    Location,
    ReportDescriptor,
    RuleCategory,
    RuleContext,
    RuleMeta,
    Severity,
)

logger = logging.getLogger(__name__)

_SEVERITY_MAP = {
    "error": Severity.ERROR,
    "warning": Severity.WARNING,
    "info": Severity.INFO,
}

_TARGET_MAP = {
    "skill": ComponentType.SKILL,
    "command": ComponentType.COMMAND,
    "agent": ComponentType.AGENT,
    "hooks": ComponentType.HOOKS,
    "claude_md": ComponentType.CLAUDE_MD,
    "mcp_config": ComponentType.MCP_CONFIG,
}

_CATEGORY_MAP = {
    "content": RuleCategory.CONTENT,
    "security": RuleCategory.SECURITY,
    "structural": RuleCategory.STRUCTURAL,
    "frontmatter": RuleCategory.FRONTMATTER,
}


@dataclass
class _CompiledPattern:
    label: str
    regex: re.Pattern[str]


class YamlRule:
    def __init__(self, meta: RuleMeta, patterns: list[_CompiledPattern], message_template: str):
        self.meta = meta
        self._patterns = patterns
        self._message_template = message_template

    def create(self, context: RuleContext) -> None:
        skill = context.skill
        if not skill.raw_content:
            return

        file_path = skill.skill_md_path
        if context.target:
            if hasattr(context.target, "skill_md_path"):
                file_path = context.target.skill_md_path
            elif hasattr(context.target, "command_md_path"):
                file_path = context.target.command_md_path
            elif hasattr(context.target, "agent_md_path"):
                file_path = context.target.agent_md_path
            elif hasattr(context.target, "file_path"):
                file_path = context.target.file_path

        content = skill.raw_content
        if context.target and hasattr(context.target, "raw_content") and context.target.raw_content:
            content = context.target.raw_content

        for i, line in enumerate(content.split("\n")):
            for pat in self._patterns:
                if pat.regex.search(line):
                    context.report(
                        ReportDescriptor(
                            message_id="yaml_match",
                            data={"label": pat.label, "line": str(i + 1)},
                            location=Location(file=file_path, start_line=i + 1),
                        )
                    )
                    break


def _parse_yaml_rule(data: dict[str, Any], source_file: str) -> YamlRule | None:
    rule_id = data.get("id")
    if not rule_id or not isinstance(rule_id, str):
        logger.warning("YAML rule in %s missing 'id' field, skipping", source_file)
        return None

    severity = _SEVERITY_MAP.get(data.get("severity", "warning"), Severity.WARNING)
    target = _TARGET_MAP.get(data.get("target", "skill"), ComponentType.SKILL)
    category = _CATEGORY_MAP.get(data.get("category", "content"), RuleCategory.CONTENT)
    description = data.get("description", "")
    suggestion = data.get("suggestion")
    message_template = data.get("message", "Found '{{label}}' on line {{line}}")

    raw_patterns = data.get("patterns", [])
    if not raw_patterns:
        logger.warning("YAML rule '%s' in %s has no patterns, skipping", rule_id, source_file)
        return None

    compiled: list[_CompiledPattern] = []
    for p in raw_patterns:
        if isinstance(p, dict):
            label = p.get("label", "pattern")
            regex_str = p.get("regex", "")
        elif isinstance(p, str):
            label = p
            regex_str = re.escape(p)
        else:
            continue
        try:
            compiled.append(_CompiledPattern(label=label, regex=re.compile(regex_str, re.I)))
        except re.error as e:
            logger.warning("Invalid regex in YAML rule '%s': %s", rule_id, e)
            continue

    if not compiled:
        return None

    meta = RuleMeta(
        id=rule_id,
        default_severity=severity,
        fixable=False,
        description=description,
        category=category,
        messages={"yaml_match": message_template},
        target_type=target,
        default_suggestion=suggestion,
    )

    return YamlRule(meta=meta, patterns=compiled, message_template=message_template)


def load_yaml_rules_from_dir(rules_dir: Path) -> int:
    """Load all .yaml/.yml rule files from a directory. Returns count loaded."""
    try:
        import yaml
    except ImportError:
        logger.debug("PyYAML not installed, skipping YAML rule loading")
        return 0

    if not rules_dir.is_dir():
        return 0

    count = 0
    for rule_file in sorted(rules_dir.glob("*.y*ml")):
        if not rule_file.is_file():
            continue
        try:
            docs = list(yaml.safe_load_all(rule_file.read_text()))
        except Exception as e:
            logger.warning("Failed to parse YAML rule file %s: %s", rule_file, e)
            continue

        for doc in docs:
            if not isinstance(doc, dict):
                continue
            rule = _parse_yaml_rule(doc, str(rule_file))
            if rule and get_rule(rule.meta.id) is None:
                register_rule(rule)
                count += 1

    return count


def load_yaml_rules(search_paths: list[Path] | None = None) -> int:
    """Load YAML rules from standard locations. Returns total count loaded."""
    paths = search_paths or []

    default_dir = Path(__file__).parent / "rules" / "custom"
    if default_dir.is_dir():
        paths.insert(0, default_dir)

    project_dir = Path.cwd() / ".harness-eval" / "rules"
    if project_dir.is_dir() and project_dir not in paths:
        paths.append(project_dir)

    total = 0
    for p in paths:
        total += load_yaml_rules_from_dir(p)
    return total
