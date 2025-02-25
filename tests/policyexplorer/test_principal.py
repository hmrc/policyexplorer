import pytest

from policyexplorer.principal import Principal


@pytest.mark.parametrize(
    "pattern,subject,expected",
    [
        (
            Principal("P1", [], []),
            Principal("P1", [], []),
            True,
        ),
        # TODO: add support for "?" wildcard
        # (
        #     Principal("P?", [], []),
        #     Principal("P1", [], []),
        #     True,
        # ),
        (
            Principal("*", [], []),
            Principal("P1", [], []),
            True,
        ),
        (
            Principal("PX", [], []),
            Principal("P1", [], []),
            False,
        ),
        (
            Principal(identifier="*", excludes=[Principal("P1", [], [])], only=[]),
            Principal("P1", [], []),
            False,
        ),
        (
            Principal(identifier="*", excludes=[Principal("P1", [], [])], only=[]),
            Principal("P2", [], []),
            True,
        ),
        (
            Principal(identifier="*", excludes=[], only=[Principal("P1", [], [])]),
            Principal("P1", [], []),
            True,
        ),
        (
            Principal(identifier="*", excludes=[], only=[Principal("P1", [], [])]),
            Principal("P2", [], []),
            False,
        ),
    ]
)
def test_principal_match(pattern: Principal, subject: Principal, expected: bool) -> None:
    assert pattern.match(subject=subject) is expected