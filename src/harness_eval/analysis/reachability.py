"""Reachability analysis: determine if a component is reachable from a trigger."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from harness_eval.analysis.component_graph import ComponentGraph
from harness_eval.core.types import ComponentType


@dataclass(frozen=True)
class ReachabilityResult:
    reachable: bool
    trigger_breadth: str  # "broad", "narrow", "unknown"
    # What supports the verdict: "explicit" (parser-backed edge), "inferred"
    # (only free-text mentions), "description" (skill trigger text),
    # "transitive" (reachable through other components) or "none".
    evidence_kind: str = "none"


_USE_WHEN_PHRASES = frozenset(
    [
        "use when",
        "use for",
        "applies to",
        "relevant for",
        "triggered by",
        "invoke when",
    ]
)


def _is_narrow_trigger(description: str) -> bool:
    desc_lower = description.lower()
    return any(phrase in desc_lower for phrase in _USE_WHEN_PHRASES)


def compute_reachability(
    graph: ComponentGraph,
    file_path: str,
    all_skill_descriptions: dict[str, str] | None = None,
    *,
    min_confidence: float = 0.0,
) -> ReachabilityResult:
    """Determine if the component at file_path is reachable from any trigger.

    Edges below *min_confidence* are not counted as evidence, so a caller that
    only trusts parser-backed references can pass a threshold above the
    confidence of inferred free-text edges.
    """
    file_stem = Path(file_path).stem
    file_parent = Path(file_path).parent.name

    target_node = None
    for node in graph.nodes.values():
        if node.name == file_parent or node.name == file_stem:
            target_node = node
            break
        if Path(node.file_path).resolve() == Path(file_path).resolve():
            target_node = node
            break

    if target_node is None:
        return ReachabilityResult(reachable=True, trigger_breadth="unknown")

    node_key = target_node.name
    if target_node.component_type == ComponentType.AGENT:
        node_key = f"agent:{target_node.name}"
    elif target_node.component_type == ComponentType.COMMAND:
        node_key = f"cmd:{target_node.name}"
    elif target_node.component_type == ComponentType.MCP_CONFIG:
        node_key = f"mcp:{target_node.name}"

    incoming = graph.edges_to(node_key, min_confidence=min_confidence)
    if incoming:
        if all(edge.evidence_kind == "inferred" for edge in incoming):
            # Only free-text mentions point here: reachable, but the breadth of
            # the trigger cannot be read off an inferred edge.
            return ReachabilityResult(
                reachable=True, trigger_breadth="unknown", evidence_kind="inferred"
            )
        return ReachabilityResult(reachable=True, trigger_breadth="broad", evidence_kind="explicit")

    if target_node.component_type == ComponentType.SKILL:
        desc = (all_skill_descriptions or {}).get(target_node.name, "")
        if desc:
            breadth = "narrow" if _is_narrow_trigger(desc) else "broad"
            return ReachabilityResult(
                reachable=True, trigger_breadth=breadth, evidence_kind="description"
            )

    for other_key in graph.nodes:
        reachable_set = graph.reachable_from(other_key, min_confidence=min_confidence)
        if node_key in reachable_set:
            return ReachabilityResult(
                reachable=True, trigger_breadth="unknown", evidence_kind="transitive"
            )

    return ReachabilityResult(reachable=False, trigger_breadth="unknown")
