from typing import List
import pytest

from policyexplorer.condition import ConditionItem
from policyexplorer.principal import Principal
from policyexplorer.request_context import RequestContext, RequestContextItem


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
def test_condition_item_get_principals(condition_item: ConditionItem, principals: List[Principal]) -> None:
    assert condition_item.get_principals() == principals
