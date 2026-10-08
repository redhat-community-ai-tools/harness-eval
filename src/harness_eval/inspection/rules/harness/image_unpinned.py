"""Report a harness whose sandbox image is a mutable reference: no tag, or the
``latest`` tag, with no digest. The fact is decidable from the string; whether
a floating image is acceptable is a trust decision, so the effect is policy."""

from __future__ import annotations

from harness_eval.core.types import ComponentType
from harness_eval.inspection.types import (
    Location,
    ParsedHarness,
    ReportDescriptor,
    RuleCategory,
    RuleContext,
    RuleMeta,
    Severity,
)


def image_pin(image: str) -> str:
    """``digest``, ``tag`` or ``floating`` for a container image reference."""
    if "@sha256:" in image:
        return "digest"
    last = image.rsplit("/", 1)[-1]
    if ":" in last:
        tag = last.rsplit(":", 1)[1]
        return "floating" if tag == "latest" else "tag"
    return "floating"


class HarnessImageUnpinned:
    meta = RuleMeta(
        id="harness/image-unpinned",
        tier="provisional",
        effect="policy",
        default_severity=Severity.WARNING,
        fixable=False,
        description=(
            "Report a harness whose sandbox image has no tag or the latest tag and no digest; "
            "the agent then runs in whatever image is current at dispatch time"
        ),
        category=RuleCategory.STRUCTURAL,
        messages={
            "floating": (
                "image '{{image}}' is a floating reference (no tag, or :latest); pin a tag or a "
                "digest so a run is reproducible."
            ),
        },
        target_type=ComponentType.HARNESS,
        default_suggestion="Pin the image to a version tag or an @sha256 digest.",
    )

    def create(self, context: RuleContext) -> None:
        harness = context.harness
        if harness is None or harness.fields is None:
            return
        image = harness.fields.image
        if not image or "${" in image or "$" in image:
            return
        if image_pin(image) != "floating":
            return
        context.report(
            ReportDescriptor(
                message_id="floating",
                data={"image": image},
                location=Location(file=harness.file_path, start_line=_line_of(harness, "image")),
            )
        )


def _line_of(harness: ParsedHarness, key: str) -> int | None:
    for i, line in enumerate(harness.raw_content.splitlines(), start=1):
        if line.startswith(f"{key}:"):
            return i
    return None
