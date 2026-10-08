"""Evaluation metadata for output reports."""

from __future__ import annotations

import importlib.metadata
from dataclasses import dataclass

from harness_eval.output.provenance import ScanEvidence


@dataclass
class EvalMetadata:
    version: str = ""
    duration_seconds: float = 0.0
    components_scanned: int = 0
    rules_checked: int | None = None
    invocation_source: str = "cli"
    provider: str | None = None
    model: str | None = None
    llm_calls_total: int | None = None
    llm_calls_succeeded: int | None = None
    # What the scan was computed from; set for directory scans.
    evidence: ScanEvidence | None = None

    @staticmethod
    def get_version() -> str:
        try:
            return importlib.metadata.version("harness-eval")
        except importlib.metadata.PackageNotFoundError:
            return "dev"

    def format_terminal(self) -> str:
        lines = ["---"]
        lines.append(f"Evaluated with: harness-eval v{self.version} ({self.invocation_source})")
        parts = [f"Duration: {self.duration_seconds:.1f}s"]
        parts.append(f"Components: {self.components_scanned}")
        if self.rules_checked is not None:
            parts.append(f"Rules: {self.rules_checked}")
        if self.provider and self.model:
            llm_info = f"LLM: {self.model}"
            if self.llm_calls_total is not None:
                succeeded = self.llm_calls_succeeded or 0
                llm_info += f" ({self.llm_calls_total} calls, {succeeded} succeeded)"
            parts.append(llm_info)
        lines.append(" | ".join(parts))
        if self.evidence is not None:
            ev = self.evidence
            rev = ev.vcs_revision[:12] if ev.vcs_revision else "n/a"
            lines.append(
                f"Fingerprint: {ev.setup_fingerprint[:12]} | Revision: {rev} | "
                f"Rules digest: {ev.rules_digest[:12]}"
            )
        return "\n".join(lines)

    def to_dict(self) -> dict[str, object]:
        d: dict[str, object] = {
            "version": self.version,
            "duration_seconds": round(self.duration_seconds, 1),
            "components_scanned": self.components_scanned,
            "invocation_source": self.invocation_source,
        }
        if self.rules_checked is not None:
            d["rules_checked"] = self.rules_checked
        if self.provider:
            d["provider"] = self.provider
        if self.model:
            d["model"] = self.model
        if self.llm_calls_total is not None:
            d["llm_calls_total"] = self.llm_calls_total
            d["llm_calls_succeeded"] = self.llm_calls_succeeded or 0
        if self.evidence is not None:
            d["evidence"] = self.evidence.to_dict()
        return d
