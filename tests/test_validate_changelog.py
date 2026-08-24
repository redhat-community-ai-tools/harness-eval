"""Tests for changelog section scope validation."""

from scripts.validate_changelog import validate_changelog

BASE_CHANGELOG = """\
# Changelog

## [Unreleased]

## [1.1.0] - 2026-08-01

### Added
- Existing feature

## [1.0.0] - 2026-07-01

### Added
- Initial release
"""


def test_allows_unchanged_changelog() -> None:
    assert validate_changelog(BASE_CHANGELOG, BASE_CHANGELOG) == []


def test_allows_addition_under_unreleased() -> None:
    candidate = BASE_CHANGELOG.replace(
        "## [Unreleased]\n",
        "## [Unreleased]\n\n### Fixed\n- Correct changelog validation\n",
    )

    assert validate_changelog(BASE_CHANGELOG, candidate) == []


def test_rejects_addition_to_existing_release() -> None:
    candidate = BASE_CHANGELOG.replace(
        "- Existing feature\n",
        "- Existing feature\n- Accidentally duplicated entry\n",
    )

    violations = validate_changelog(BASE_CHANGELOG, candidate)

    assert len(violations) == 1
    assert violations[0].section == "1.1.0"
    assert violations[0].content == "- Accidentally duplicated entry"


def test_allows_new_release_section() -> None:
    candidate = BASE_CHANGELOG.replace(
        "## [Unreleased]\n",
        "## [Unreleased]\n\n## [1.2.0] - 2026-08-17\n\n### Added\n- New release\n",
    )

    assert validate_changelog(BASE_CHANGELOG, candidate) == []


def test_rejects_only_historical_part_of_mixed_changes() -> None:
    candidate = BASE_CHANGELOG.replace(
        "## [Unreleased]\n",
        "## [Unreleased]\n\n### Fixed\n- Valid fix\n",
    ).replace(
        "- Initial release\n",
        "- Initial release\n- Invalid historical addition\n",
    )

    violations = validate_changelog(BASE_CHANGELOG, candidate)

    assert [violation.section for violation in violations] == ["1.0.0"]
    assert violations[0].content == "- Invalid historical addition"


def test_rejects_addition_to_preamble() -> None:
    candidate = BASE_CHANGELOG.replace(
        "# Changelog\n",
        "# Changelog\n\nDo not edit released entries.\n",
    )

    violations = validate_changelog(BASE_CHANGELOG, candidate)

    assert len(violations) == 1
    assert violations[0].section == "<preamble>"
    assert violations[0].content == "Do not edit released entries."


def test_rejects_changed_historical_header() -> None:
    candidate = BASE_CHANGELOG.replace(
        "## [1.1.0] - 2026-08-01",
        "## [1.1.0] - 2026-08-02",
    )

    violations = validate_changelog(BASE_CHANGELOG, candidate)

    assert len(violations) == 1
    assert violations[0].section == "1.1.0"
    assert violations[0].content == "## [1.1.0] - 2026-08-02"
