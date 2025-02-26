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
    "operator,expected",
    [
        ("ArnEquals", False),
        ("ArnNotLike", True),
        ("StringLike", False),
        ("StringNotEquals", True),
    ],
)
def test_condition_item_is_negated(operator: str, expected: bool) -> None:
    assert ConditionItem(operator=operator, key="", value=[]).is_operator_negated() == expected


@pytest.mark.parametrize(
    "condition_item,request_context,expected",
    [
        (
            ConditionItem(operator="ArnLike", key="aws:PrincipalArn", value=["arn:aws:iam:*:123456789012:role/*Role*"]),
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
            ConditionItem(
                operator="ArnNotLike", key="aws:PrincipalArn", value=["arn:aws:iam:*:123456789012:role/*Role*"]
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
            ConditionItem(
                operator="ArnNotLike", key="aws:PrincipalArn", value=["arn:aws:iam:*:123456789012:role/*Role*"]
            ),
            RequestContext(
                items={
                    "aws:username": RequestContextItem(key="aws:username", value="john.doe"),
                }
            ),
            False,
        ),
        (
            ConditionItem(operator="Bool", key="aws:MultiFactorAuthPresent", value=True),
            RequestContext(
                items={
                    "aws:MultiFactorAuthPresent": RequestContextItem(key="aws:MultiFactorAuthPresent", value=True),
                }
            ),
            True,
        ),
    ],
)
def test_evaluate_condition_item(
    condition_item: ConditionItem, request_context: RequestContext, expected: bool
) -> None:
    assert condition_item.evaluate(request_context=request_context) == expected


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
    "condition_item,principals",
    [
        (
            ConditionItem(operator="ArnLike", key="aws:PrincipalArn", value=["arn:aws:iam:*:123456789012:role/*Role*"]),
            [Principal("arn:aws:iam:*:123456789012:role/*Role*", excludes=[], only=[])],
        ),
        (
            ConditionItem(
                operator="ArnNotLike",
                key="aws:PrincipalArn",
                value=["arn:aws:iam:us-east-1:123456789012:role/RoleAdmin"],
            ),
            [Principal(identifier="arn:aws:iam:us-east-1:123456789012:role/RoleAdmin", excludes=[], only=[])],
        ),
        (
            ConditionItem(operator="StringLike", key="aws:username", value=["john.doe", "jane.smith"]),
            [Principal("john.doe", excludes=[], only=[]), Principal("jane.smith", excludes=[], only=[])],
        ),
        (
            ConditionItem(operator="StringNotLike", key="aws:userid", value=["id-john.doe"]),
            [Principal(identifier="id-john.doe", excludes=[], only=[])],
        ),
        (ConditionItem(operator="Bool", key="aws:MultiFactorAuthPresent", value=True), []),
        (ConditionItem(operator="IpAddress", key="aws:SourceIp", value=["203.0.113.0/24"]), []),
    ],
)
def test_condition_item_get_principals(condition_item: ConditionItem, principals: List[str]) -> None:
    assert condition_item.get_principals() == principals
