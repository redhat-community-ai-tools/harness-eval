from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, Protocol

from harness_eval.core.types import ComponentType, ScanLimits

if TYPE_CHECKING:
    from harness_eval.analysis.component_graph import ComponentGraph


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
    # What supports the reachability verdict ("explicit", "inferred",
    # "description", "transitive", "none") and how broadly the component is
    # triggered ("broad", "narrow", "unknown"). A finding on a component that is
    # only reachable through an inferred edge is weaker evidence than one on a
    # component wired up explicitly.
    reachability_evidence: str | None = None
    trigger_breadth: str | None = None
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
    default_suggestion: str | None = None
    # Evidence class: gating and provisional are structural rules validated on the
    # corpus (see docs/rule-taxonomy.md); everything else is advisory.
    tier: Literal["gating", "provisional", "advisory"] = "advisory"
    # Analysis scope: what a rule needs to see. FILE = one component's text or one
    # config file; FILE_FS = also touches the filesystem; PAIRWISE = compares two
    # components; SETUP = needs the whole component graph or an aggregate.
    scope: Literal["FILE", "FILE_FS", "PAIRWISE", "SETUP"] = "FILE"


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


@dataclass
class ParsedMcpConfig:
    file_path: str
    raw_content: str
    parse_errors: list[str] = field(default_factory=list)
    tokens: int = 0


ParsedFile = (
    ParsedSkill | ParsedCommand | ParsedClaudeMd | ParsedHooks | ParsedAgent | ParsedMcpConfig
)


class ScanArtifacts:
    """Typed view over the state dict shared by every rule in one scan.

    ``state`` is the very dict rules see as ``context.scan_state``.  The typed
    accessors read and write well-known keys in it, so there is exactly one
    store: built-in rules use the accessors, and third-party rules written
    against ``scan_state`` keep working unchanged.
    """

    __slots__ = ("state",)

    def __init__(
        self, state: dict[str, Any] | None = None, *, project_root: Path | str | None = None
    ) -> None:
        self.state: dict[str, Any] = state if state is not None else {}
        if project_root is not None:
            self.project_root = Path(project_root)

    @property
    def project_root(self) -> Path | None:
        root = self.state.get("project_root")
        return Path(root) if root else None

    @project_root.setter
    def project_root(self, value: Path | None) -> None:
        if value is None:
            self.state.pop("project_root", None)
        else:
            self.state["project_root"] = str(value)

    @property
    def component_graph(self) -> ComponentGraph | None:
        graph: ComponentGraph | None = self.state.get("component_graph")
        return graph

    @component_graph.setter
    def component_graph(self, value: ComponentGraph | None) -> None:
        self.state["component_graph"] = value

    @property
    def component_index(self) -> dict[str, set[str]] | None:
        index: dict[str, set[str]] | None = self.state.get("component_index")
        return index

    @component_index.setter
    def component_index(self, value: dict[str, set[str]] | None) -> None:
        self.state["component_index"] = value

    @property
    def mcp_config_path(self) -> str | None:
        path: str | None = self.state.get("mcp_config_path")
        return path

    @mcp_config_path.setter
    def mcp_config_path(self, value: str | None) -> None:
        self.state["mcp_config_path"] = value

    @property
    def rule_state(self) -> dict[str, Any]:
        """Scratch space for rule-private cross-component data, keyed by rule id."""
        scratch: dict[str, Any] = self.state.setdefault("_rule_state", {})
        return scratch

    def mark_once(self, key: str) -> bool:
        """Return true the first time a setup-wide rule claims ``key`` in this scan."""
        if self.state.get(key):
            return False
        self.state[key] = True
        return True

    @property
    def scan_limits(self) -> ScanLimits | None:
        limits: ScanLimits | None = self.state.get("scan_limits")
        return limits

    @scan_limits.setter
    def scan_limits(self, value: ScanLimits | None) -> None:
        if value is None:
            self.state.pop("scan_limits", None)
        else:
            self.state["scan_limits"] = value

    @property
    def allowed_paths(self) -> frozenset[str] | None:
        paths = self.state.get("allowed_paths")
        return frozenset(paths) if paths is not None else None

    @allowed_paths.setter
    def allowed_paths(self, value: frozenset[str] | set[str] | None) -> None:
        if value is None:
            self.state.pop("allowed_paths", None)
        else:
            self.state["allowed_paths"] = frozenset(value)


@dataclass
class RuleContext:
    report: Callable[[ReportDescriptor], None]
    severity: Severity
    skill: ParsedSkill | None = None
    options: list[Any] = field(default_factory=list)
    target: ParsedFile | None = None
    all_skills: list[ParsedSkill] = field(default_factory=list)
    all_commands: list[ParsedCommand] = field(default_factory=list)
    scan_state: dict[str, Any] = field(default_factory=dict)
    source_tool: str | None = None
    artifacts: ScanArtifacts = field(default_factory=ScanArtifacts)

    def __post_init__(self) -> None:
        # ``scan_state`` and ``artifacts.state`` must be the same dict so that a
        # rule using either API sees what every other rule wrote.
        if self.scan_state is not self.artifacts.state:
            if self.artifacts.state:
                self.artifacts.state.update(self.scan_state)
            else:
                self.artifacts.state = self.scan_state
        self.scan_state = self.artifacts.state

    def source_text(self) -> tuple[str, str]:
        """Raw content and file path for the component being linted."""
        t = self.target
        if isinstance(t, ParsedSkill):
            return t.raw_content, t.skill_md_path
        if isinstance(t, ParsedCommand):
            return t.raw_content, t.command_md_path
        if isinstance(t, ParsedAgent):
            return t.raw_content, t.agent_md_path
        if isinstance(t, (ParsedClaudeMd, ParsedHooks, ParsedMcpConfig)):
            return t.raw_content, t.file_path
        if self.skill is not None:
            return self.skill.raw_content, self.skill.skill_md_path
        return "", ""

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

    @property
    def mcp_config(self) -> ParsedMcpConfig | None:
        return self.target if isinstance(self.target, ParsedMcpConfig) else None


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
