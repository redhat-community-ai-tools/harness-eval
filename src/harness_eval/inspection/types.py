from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Protocol

from harness_eval.core.types import ComponentType


class Severity(str, Enum):
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


class RuleCategory(str, Enum):
    STRUCTURAL = "structural"
    FRONTMATTER = "frontmatter"
    CONTENT = "content"
    SECURITY = "security"
    BEST_PRACTICES = "best_practices"
    CROSS_COMPONENT = "cross_component"


@dataclass(frozen=True)
class Location:
    file: str
    start_line: int | None = None


@dataclass(frozen=True)
class FixSuggestion:
    description: str
    replacement: str | None = None


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: Severity
    message: str
    location: Location
    category: RuleCategory
    fix: FixSuggestion | None = None
    reachability: str | None = None
    suggestion: str | None = None


@dataclass(frozen=True)
class AdjudicatedFinding:
    finding: Finding
    verdict: str
    reasoning: str

    @property
    def is_confirmed(self) -> bool:
        return self.verdict == "CONFIRMED"

    @property
    def is_false_positive(self) -> bool:
        return self.verdict == "FALSE_POSITIVE"

    @property
    def effective_severity(self) -> Severity:
        if self.verdict == "FALSE_POSITIVE":
            return Severity.INFO
        if self.verdict == "DOWNGRADED":
            return Severity.WARNING
        return self.finding.severity


@dataclass
class RuleMeta:
    id: str
    default_severity: Severity
    fixable: bool
    description: str
    category: RuleCategory
    messages: dict[str, str]
    target_type: ComponentType = ComponentType.SKILL
    tools: tuple[str, ...] | None = None
    frameworks: dict[str, str] | None = None


@dataclass
class ReportDescriptor:
    message_id: str
    data: dict[str, str | int] | None = None
    location: Location | None = None
    fix: FixSuggestion | None = None
    severity_override: Severity | None = None
    suggestion: str | None = None


@dataclass
class ParsedSkill:
    dir_path: str
    dir_name: str
    skill_md_path: str
    raw_content: str
    frontmatter: dict[str, Any]
    raw_frontmatter: str
    frontmatter_start_line: int
    body: str
    body_start_line: int
    files: list[str]
    sub_file_contents: dict[str, str] = field(default_factory=dict)
    parse_errors: list[str] = field(default_factory=list)
    tokens: int = 0


@dataclass
class ParsedCommand:
    dir_path: str
    dir_name: str
    command_md_path: str
    raw_content: str
    frontmatter: dict[str, Any]
    body: str
    body_start_line: int
    script_references: list[str]
    files: list[str]
    parse_errors: list[str] = field(default_factory=list)
    tokens: int = 0


@dataclass
class ParsedClaudeMd:
    file_path: str
    raw_content: str
    line_count: int
    sections: list[dict[str, str]]
    parse_errors: list[str] = field(default_factory=list)
    tokens: int = 0


@dataclass
class ParsedHooks:
    file_path: str
    hooks: list[dict[str, Any]]
    raw_content: str
    parse_errors: list[str] = field(default_factory=list)


@dataclass
class ParsedAgent:
    dir_path: str
    file_name: str
    agent_md_path: str
    raw_content: str
    frontmatter: dict[str, Any]
    raw_frontmatter: str
    frontmatter_start_line: int
    body: str
    body_start_line: int
    referenced_skills: list[str]
    disallowed_tools: list[str]
    allowed_tools: list[str]
    model: str | None
    sibling_files: dict[str, list[str]]
    files: list[str]
    parse_errors: list[str] = field(default_factory=list)
    tokens: int = 0


ParsedFile = ParsedSkill | ParsedCommand | ParsedClaudeMd | ParsedHooks | ParsedAgent


@dataclass
class RuleContext:
    skill: ParsedSkill
    report: Callable[[ReportDescriptor], None]
    severity: Severity
    options: list[Any] = field(default_factory=list)
    target: ParsedFile | None = None
    all_skills: list[ParsedSkill] = field(default_factory=list)
    all_commands: list[ParsedCommand] = field(default_factory=list)
    scan_state: dict[str, Any] = field(default_factory=dict)
    source_tool: str | None = None

    @property
    def command(self) -> ParsedCommand | None:
        return self.target if isinstance(self.target, ParsedCommand) else None

    @property
    def claude_md(self) -> ParsedClaudeMd | None:
        return self.target if isinstance(self.target, ParsedClaudeMd) else None

    @property
    def hooks(self) -> ParsedHooks | None:
        return self.target if isinstance(self.target, ParsedHooks) else None

    @property
    def agent(self) -> ParsedAgent | None:
        return self.target if isinstance(self.target, ParsedAgent) else None


@dataclass
class RuleResult:
    rule_id: str
    description: str
    passed: bool


@dataclass
class InspectionResult:
    target_path: str
    target_name: str
    tokens: int
    target_type: str = "skill"
    diagnostics: list[Finding] = field(default_factory=list)
    rules_run: list[RuleResult] = field(default_factory=list)
    error_count: int = 0
    warning_count: int = 0
    info_count: int = 0
    fixable_count: int = 0
    suppression_count: int = 0


class Rule(Protocol):
    meta: RuleMeta

    def create(self, context: RuleContext) -> None: ...
