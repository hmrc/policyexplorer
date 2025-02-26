from typing import Any, Dict, List
import pytest

from policyexplorer.condition import Condition, ConditionItem
from policyexplorer.principal import Principal
from policyexplorer.request_context import RequestContext, RequestContextItem


@pytest.mark.parametrize(
    "condition,condition_items",
    [
        (
            {
                "op1": {
                    "key1": "value1",
                },
            },
            [ConditionItem(operator="op1", key="key1", value=["value1"])],
        ),
        (
            {
                "op1": {
                    "key1": ["value1", "value2"],
                },
            },
            [ConditionItem(operator="op1", key="key1", value=["value1", "value2"])],
        ),
        (
            {
                "op1": {
                    "key1": ["value1", "value2"],
                    "keyX": "valueX",
                },
            },
            [
                ConditionItem(operator="op1", key="key1", value=["value1", "value2"]),
                ConditionItem(operator="op1", key="keyX", value=["valueX"]),
            ],
        ),
        (
            {
                "op1": {
                    "key1": ["value1", "value2"],
                    "keyX": "valueX",
                },
                "op2": {
                    "keyY": "valueY",
                },
            },
            [
                ConditionItem(operator="op1", key="key1", value=["value1", "value2"]),
                ConditionItem(operator="op1", key="keyX", value=["valueX"]),
                ConditionItem(operator="op2", key="keyY", value=["valueY"]),
            ],
        ),
    ],
)
def test_condition_parsing(condition: Dict[str, Any], condition_items: List[ConditionItem]) -> None:
    assert Condition(raw=condition).items == condition_items


@pytest.mark.parametrize(
    "condition,request_context,expected",
    [
        (
            Condition(
                raw={
                    "ArnLike": {"aws:PrincipalArn": "arn:aws:iam:*:123456789012:role/*Role*"},
                }
            ),
            RequestContext(
                items={
                    "aws:PrincipalArn": RequestContextItem(
                        key="aws:PrincipalArn", value="arn:aws:iam:us-east-1:123456789012:role/RoleAdmin"
                    ),
                }
            ),
            True,
        ),
        (
            Condition(
                raw={
                    "ArnNotLike": {"aws:PrincipalArn": "arn:aws:iam:*:123456789012:role/*Role*"},
                }
            ),
            RequestContext(
                items={
                    "aws:PrincipalArn": RequestContextItem(
                        key="aws:PrincipalArn", value="arn:aws:iam:us-east-1:123456789012:role/RoleAdmin"
                    ),
                }
            ),
            False,
        ),
        (
            Condition(
                raw={
                    "ArnLike": {"aws:PrincipalArn": "arn:aws:iam:*:123456789012:role/*Role*"},
                }
            ),
            RequestContext(
                items={
                    "aws:username": RequestContextItem(key="aws:username", value="john.doe"),
                }
            ),
            False,
        ),
        (
            Condition(
                raw={
                    "ArnLike": {"aws:PrincipalArn": "arn:aws:iam:*:123456789012:role/*Role*"},
                    "Bool": {"aws:MultiFactorAuthPresent": True},
                }
            ),
            RequestContext(
                items={
                    "aws:PrincipalArn": RequestContextItem(
                        key="aws:PrincipalArn", value="arn:aws:iam:us-east-1:123456789012:role/RoleAdmin"
                    ),
                    "aws:MultiFactorAuthPresent": RequestContextItem(key="aws:MultiFactorAuthPresent", value=True),
                }
            ),
            True,
        ),
    ],
)
def test_evaluate_condition(condition: Condition, request_context: RequestContext, expected: bool) -> None:
    assert condition.evaluate(request_context=request_context) == expected


@pytest.mark.parametrize(
    "condition,principals",
    [
        (
            Condition(
                raw={
                    "ArnLike": {"aws:PrincipalArn": "arn:aws:iam:*:123456789012:role/*Role*"},
                }
            ),
            [Principal("arn:aws:iam:*:123456789012:role/*Role*", excludes=[], only=[])],
        ),
        (
            Condition(
                raw={
                    "ArnNotLike": {"aws:PrincipalArn": "arn:aws:iam:*:123456789012:role/*Role*"},
                }
            ),
            [Principal("arn:aws:iam:*:123456789012:role/*Role*", excludes=[], only=[])],
        ),
        (
            Condition(
                raw={
                    "ArnLike": {"aws:PrincipalArn": "arn:aws:iam:*:123456789012:role/*Role*"},
                    "Bool": {"aws:MultiFactorAuthPresent": True},
                }
            ),
            [Principal("arn:aws:iam:*:123456789012:role/*Role*", excludes=[], only=[])],
        ),
        (
            Condition(
                raw={
                    "StringLike": {"aws:PrincipalArn": "arn:aws:iam:*:123456789012:role/RoleAdmin"},
                    "StringNotLike": {"aws:PrincipalArn": "arn:aws:iam:*:123456789012:role/RoleEngineer"},
                    "Bool": {"aws:MultiFactorAuthPresent": True},
                }
            ),
            [
                Principal("arn:aws:iam:*:123456789012:role/RoleAdmin", excludes=[], only=[]),
                Principal("arn:aws:iam:*:123456789012:role/RoleEngineer", excludes=[], only=[]),
            ],
        ),
        (
            Condition(
                raw={
                    "StringLike": {
                        "aws:username": "john.doe",
                        "aws:PrincipalArn": "arn:aws:iam:*:123456789012:role/RoleAdmin",
                    },
                    "StringNotLike": {
                        "aws:userid": "id-jane.smith",
                        "aws:PrincipalArn": "arn:aws:iam:*:123456789012:role/RoleEngineer",
                    },
                    "Bool": {"aws:MultiFactorAuthPresent": True},
                }
            ),
            [
                Principal("john.doe", excludes=[], only=[]),
                Principal("arn:aws:iam:*:123456789012:role/RoleAdmin", excludes=[], only=[]),
                Principal("id-jane.smith", excludes=[], only=[]),
                Principal("arn:aws:iam:*:123456789012:role/RoleEngineer", excludes=[], only=[]),
            ],
        ),
        (
            Condition(
                raw={
                    "Bool": {"aws:MultiFactorAuthPresent": True},
                    "IpAddress": {"aws:SourceIp": ["203.0.113.0/24"]},
                }
            ),
            [],
        ),
    ],
)
def test_condition_get_principals(condition: Condition, principals: List[str]) -> None:
    assert condition.get_principals() == principals
