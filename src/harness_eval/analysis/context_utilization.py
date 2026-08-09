"""Context utilization analysis: how much of each model's context window the setup consumes."""

from __future__ import annotations

from dataclasses import dataclass, field

from harness_eval.analysis.budget import BudgetReport
from harness_eval.core.types import Setup


@dataclass
class ModelSpec:
    """A model with a known context window size."""

    name: str
    context_window: int


@dataclass
class ModelUtilization:
    """Context utilization for one model."""

    model: str
    context_window: int
    always_loaded_pct: float
    peak_load_pct: float
    remaining_pct: float
    warning: bool


@dataclass
class ContextUtilizationReport:
    """Context utilization across all target models."""

    always_loaded_tokens: int = 0
    peak_tokens: int = 0
    models: list[ModelUtilization] = field(default_factory=list)


PEAK_WARNING_THRESHOLD = 0.20

DEFAULT_MODELS: list[ModelSpec] = [
    ModelSpec("claude-haiku-4.5", 200_000),
    ModelSpec("claude-sonnet-4.6", 200_000),
    ModelSpec("claude-opus-4.6", 200_000),
    ModelSpec("claude-opus-4.7", 200_000),
    ModelSpec("claude-opus-4.8", 200_000),
    ModelSpec("claude-opus-4.6-1m", 1_000_000),
    ModelSpec("claude-opus-4.7-1m", 1_000_000),
    ModelSpec("claude-opus-4.8-1m", 1_000_000),
]


def analyze_context_utilization(
    setup: Setup,
    budget: BudgetReport,
    models: list[ModelSpec] | None = None,
) -> ContextUtilizationReport:
    """Compute context window utilization per model."""
    target_models = models if models is not None else DEFAULT_MODELS
    always_loaded = budget.always_loaded_tokens
    peak = budget.total_tokens

    utilizations: list[ModelUtilization] = []
    for spec in target_models:
        if spec.context_window <= 0:
            continue
        al_pct = always_loaded / spec.context_window
        peak_pct = peak / spec.context_window
        remaining = max(0.0, 1.0 - peak_pct)
        utilizations.append(
            ModelUtilization(
                model=spec.name,
                context_window=spec.context_window,
                always_loaded_pct=al_pct,
                peak_load_pct=peak_pct,
                remaining_pct=remaining,
                warning=peak_pct > PEAK_WARNING_THRESHOLD,
            )
        )

    utilizations.sort(key=lambda m: m.peak_load_pct, reverse=True)

    return ContextUtilizationReport(
        always_loaded_tokens=always_loaded,
        peak_tokens=peak,
        models=utilizations,
    )
