"""RubricChecker: detect issues in components via LLM-based evaluation."""

from __future__ import annotations

import json
import re

from harness_eval.rubric.dimensions import CATEGORIES_BY_TYPE
from harness_eval.rubric.prompts import SYSTEM_PROMPT, build_batch_prompt, build_issue_prompt
from harness_eval.rubric.types import IssueCategory, RubricIssue, RubricResult
from harness_eval.utils.llm import LLMClient
from harness_eval.utils.redact import redact_secrets

_ISSUE_WITH_IMPACT_RE = re.compile(
    r"ISSUE:\s*(.+?)\s*\|\s*CATEGORY:\s*(\S+)\s*\|\s*SEVERITY:\s*(\S+)\s*\|\s*EVIDENCE:\s*(.+?)\s*\|\s*SUGGESTION:\s*(.+?)\s*\|\s*IMPACT:\s*(.+)"
)
_ISSUE_RE = re.compile(
    r"ISSUE:\s*(.+?)\s*\|\s*CATEGORY:\s*(\S+)\s*\|\s*SEVERITY:\s*(\S+)\s*\|\s*EVIDENCE:\s*(.+?)\s*\|\s*SUGGESTION:\s*(.+)"
)
_ISSUE_RE_LEGACY = re.compile(
    r"ISSUE:\s*(.+?)\s*\|\s*CATEGORY:\s*(\S+)\s*\|\s*EVIDENCE:\s*(.+?)\s*\|\s*SUGGESTION:\s*(.+)"
)
_SUMMARY_RE = re.compile(r"SUMMARY:\s*(.+)")
_VERDICT_RE = re.compile(r"VERDICT:\s*(\S+)")

_JSON_BLOCK_RE = re.compile(r"```json\s*\n(.*?)\n\s*```", re.DOTALL)


class RubricChecker:
    def __init__(self, client: LLMClient) -> None:
        self.client = client

    def _ensure_client_safe(self) -> None:
        if hasattr(self.client, "_ensure_client"):
            self.client._ensure_client()  # type: ignore[union-attr]

    def check(
        self,
        component_type: str,
        component_name: str,
        content: str,
        context: str | None = None,
        category_overrides: list[IssueCategory] | None = None,
    ) -> RubricResult:
        categories = category_overrides or CATEGORIES_BY_TYPE.get(component_type, [])
        if not categories:
            return RubricResult(
                component_name=component_name,
                component_type=component_type,
                summary=f"No issue categories defined for type '{component_type}'",
            )

        prompt = build_issue_prompt(
            component_type=component_type,
            component_name=component_name,
            content=redact_secrets(content),
            categories=categories,
            context=redact_secrets(context) if context else None,
        )

        response = self.client.generate(SYSTEM_PROMPT, prompt)
        return self._parse_response(response, component_name, component_type)

    def check_batch(
        self,
        components: list[tuple[str, str, str]],
        context: str | None = None,
        category_overrides: list[IssueCategory] | None = None,
    ) -> list[RubricResult]:
        if len(components) == 1:
            ct, cn, cc = components[0]
            return [self.check(ct, cn, cc, context, category_overrides)]

        first_type = components[0][0]
        categories = category_overrides or CATEGORIES_BY_TYPE.get(first_type, [])
        if not categories:
            return [RubricResult(component_name=cn, component_type=ct) for ct, cn, _ in components]

        safe_components = [(ct, cn, redact_secrets(cc)) for ct, cn, cc in components]
        prompt = build_batch_prompt(
            safe_components,
            categories,
            redact_secrets(context) if context else None,
        )
        response = self.client.generate(SYSTEM_PROMPT, prompt)
        return self._parse_batch_response(response, components)

    def _parse_batch_response(
        self,
        response: str,
        components: list[tuple[str, str, str]],
    ) -> list[RubricResult]:
        json_str = self._extract_json_string(response)
        if json_str is not None:
            try:
                data = json.loads(json_str)
                if isinstance(data, list) and len(data) == len(components):
                    results = []
                    for i, item in enumerate(data):
                        if not isinstance(item, dict):
                            ct, cn, _ = components[i]
                            results.append(RubricResult(component_name=cn, component_type=ct))
                            continue
                        ct, cn, _ = components[i]
                        result = self._parse_single_json(item, cn, ct)
                        results.append(result)
                    return results
            except (json.JSONDecodeError, ValueError):
                pass

        return [self.check(ct, cn, cc) for ct, cn, cc in components]

    def _parse_single_json(
        self, data: dict[str, object], component_name: str, component_type: str
    ) -> RubricResult:
        issues: list[RubricIssue] = []
        for item in data.get("issues", []):
            if not isinstance(item, dict):
                continue
            issues.append(
                RubricIssue(
                    description=str(item.get("description", "")),
                    category=str(item.get("category", "")),
                    severity=str(item.get("severity", "warning")).lower(),
                    evidence=str(item.get("evidence", "")),
                    suggestion=str(item.get("suggestion", "")),
                    impact=str(item.get("impact", "")),
                )
            )
        return RubricResult(
            component_name=component_name,
            component_type=component_type,
            issues=issues,
            summary=str(data.get("summary", "")),
            verdict=str(data.get("verdict", "")),
        )

    def _parse_response(
        self,
        response: str,
        component_name: str,
        component_type: str,
    ) -> RubricResult:
        # Try JSON parsing first, fall back to regex
        result = self._try_parse_json(response, component_name, component_type)
        if result is not None:
            return result
        return self._parse_text(response, component_name, component_type)

    def _try_parse_json(
        self,
        response: str,
        component_name: str,
        component_type: str,
    ) -> RubricResult | None:
        """Attempt to parse a JSON response. Returns None if no valid JSON found."""
        json_str = self._extract_json_string(response)
        if json_str is None:
            return None

        try:
            data = json.loads(json_str)
        except (json.JSONDecodeError, ValueError):
            return None

        if not isinstance(data, dict):
            return None

        issues: list[RubricIssue] = []
        for item in data.get("issues", []):
            if not isinstance(item, dict):
                continue
            issues.append(
                RubricIssue(
                    description=str(item.get("description", "")),
                    category=str(item.get("category", "")),
                    severity=str(item.get("severity", "warning")).lower(),
                    evidence=str(item.get("evidence", "")),
                    suggestion=str(item.get("suggestion", "")),
                    impact=str(item.get("impact", "")),
                )
            )

        return RubricResult(
            component_name=component_name,
            component_type=component_type,
            issues=issues,
            summary=str(data.get("summary", "")),
            verdict=str(data.get("verdict", "")),
        )

    @staticmethod
    def _extract_json_string(response: str) -> str | None:
        """Extract a JSON string from a fenced code block or raw JSON object."""
        # Try ```json ... ``` block first
        block_match = _JSON_BLOCK_RE.search(response)
        if block_match:
            return block_match.group(1).strip()

        # Try to find a raw JSON object (first { to last })
        stripped = response.strip()
        first_brace = stripped.find("{")
        last_brace = stripped.rfind("}")
        if first_brace != -1 and last_brace > first_brace:
            return stripped[first_brace : last_brace + 1]

        return None

    def _parse_text(
        self,
        response: str,
        component_name: str,
        component_type: str,
    ) -> RubricResult:
        """Parse a text response using regex patterns (legacy/fallback)."""
        issues: list[RubricIssue] = []
        summary = ""
        verdict = ""

        for line in response.strip().split("\n"):
            line = line.strip()

            impact_match = _ISSUE_WITH_IMPACT_RE.match(line)
            if impact_match:
                issues.append(
                    RubricIssue(
                        description=impact_match.group(1).strip(),
                        category=impact_match.group(2).strip(),
                        severity=impact_match.group(3).strip().lower(),
                        evidence=impact_match.group(4).strip(),
                        suggestion=impact_match.group(5).strip(),
                        impact=impact_match.group(6).strip(),
                    )
                )
                continue

            issue_match = _ISSUE_RE.match(line)
            if issue_match:
                issues.append(
                    RubricIssue(
                        description=issue_match.group(1).strip(),
                        category=issue_match.group(2).strip(),
                        severity=issue_match.group(3).strip().lower(),
                        evidence=issue_match.group(4).strip(),
                        suggestion=issue_match.group(5).strip(),
                    )
                )
                continue

            # Fall back to legacy format (without severity)
            legacy_match = _ISSUE_RE_LEGACY.match(line)
            if legacy_match:
                issues.append(
                    RubricIssue(
                        description=legacy_match.group(1).strip(),
                        category=legacy_match.group(2).strip(),
                        evidence=legacy_match.group(3).strip(),
                        suggestion=legacy_match.group(4).strip(),
                    )
                )
                continue

            verdict_match = _VERDICT_RE.match(line)
            if verdict_match:
                verdict = verdict_match.group(1).strip()
                continue

            sum_match = _SUMMARY_RE.match(line)
            if sum_match:
                summary = sum_match.group(1).strip()

        return RubricResult(
            component_name=component_name,
            component_type=component_type,
            issues=issues,
            summary=summary,
            verdict=verdict,
        )
