import pytest

from policyexplorer.permission import PermissionEffect


@pytest.mark.parametrize(
    "effect,expected",
    [
        (PermissionEffect.ALLOW, PermissionEffect.IMPLICIT_DENY),
        (PermissionEffect.DENY, PermissionEffect.IMPLICIT_DENY),
    ],
)
def test_permission_effect_invert(effect: PermissionEffect, expected: PermissionEffect) -> None:
    assert effect.invert == expected


@pytest.mark.parametrize(
    "effect,precendence",
    [
        (PermissionEffect.IMPLICIT_DENY, 0),
        (PermissionEffect.ALLOW, 1),
        (PermissionEffect.DENY, 2),
    ],
)
def test_permission_effect_precedence(effect: PermissionEffect, precendence: int) -> None:
    assert PermissionEffect.precedence()[effect] == precendence


@pytest.mark.parametrize(
    "this,other,expected",
    [
        (PermissionEffect.IMPLICIT_DENY, PermissionEffect.ALLOW, False),
        (PermissionEffect.IMPLICIT_DENY, PermissionEffect.DENY, False),
        (PermissionEffect.ALLOW, PermissionEffect.DENY, False),
        (PermissionEffect.ALLOW, PermissionEffect.IMPLICIT_DENY, True),
        (PermissionEffect.DENY, PermissionEffect.ALLOW, True),
        (PermissionEffect.DENY, PermissionEffect.IMPLICIT_DENY, True),
    ],
)
def test_permission_effect_greater_than(this: PermissionEffect, other: PermissionEffect, expected: bool) -> None:
    assert (this > other) == expected


@pytest.mark.parametrize(
    "this,other,expected",
    [
        (PermissionEffect.IMPLICIT_DENY, PermissionEffect.ALLOW, True),
        (PermissionEffect.IMPLICIT_DENY, PermissionEffect.DENY, True),
        (PermissionEffect.ALLOW, PermissionEffect.DENY, True),
        (PermissionEffect.ALLOW, PermissionEffect.IMPLICIT_DENY, False),
        (PermissionEffect.DENY, PermissionEffect.ALLOW, False),
        (PermissionEffect.DENY, PermissionEffect.IMPLICIT_DENY, False),
    ],
)
def test_permission_effect_less_than(this: PermissionEffect, other: PermissionEffect, expected: bool) -> None:
    assert (this < other) == expected
