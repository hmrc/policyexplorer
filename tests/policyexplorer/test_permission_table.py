import pytest

from policyexplorer.exception import RequestContextItemNotFoundException
from policyexplorer.permission import PermissionEffect
from policyexplorer.permission_table import PermissionTable
from policyexplorer.principal import Principal
from policyexplorer.request_context import RequestContext, RequestContextItem


@pytest.mark.parametrize(
    "permission_table,other_table,expected",
    [
        (
            PermissionTable(table={}),
            PermissionTable(table={Principal("*", [], []): {"*:*-*": PermissionEffect.ALLOW}}),
            False,
        ),
        (
            PermissionTable(
                table={Principal("P1", [], []): {"A1-R1": PermissionEffect.ALLOW, "A2-R1": PermissionEffect.ALLOW}}
            ),
            PermissionTable(
                table={Principal("P1", [], []): {"A1-R1": PermissionEffect.ALLOW, "A2-R1": PermissionEffect.ALLOW}}
            ),
            True,
        ),
        (
            PermissionTable(
                table={Principal("P1", [], []): {"A1-R1": PermissionEffect.ALLOW, "A2-R1": PermissionEffect.ALLOW}}
            ),
            PermissionTable(
                table={Principal("P2", [], []): {"A1-R1": PermissionEffect.ALLOW, "A2-R1": PermissionEffect.ALLOW}}
            ),
            False,
        ),
        (
            "",
            PermissionTable(table={Principal("P1", [], []): {"A1-R1": PermissionEffect.ALLOW}}),
            False,
        ),
    ],
)
def test_permission_table_equality(
    permission_table: PermissionTable, other_table: PermissionTable, expected: bool
) -> None:
    assert (permission_table == other_table) == expected


@pytest.mark.parametrize(
    "perm_table,other_table,expected",
    [
        (
            PermissionTable(table={}),
            PermissionTable(table={Principal("*", [], []): {"*:*-*": PermissionEffect.ALLOW}}),
            PermissionTable(table={Principal("*", [], []): {"*:*-*": PermissionEffect.ALLOW}}),
        ),
        (
            PermissionTable(table={Principal("P1", [], []): {"A1-R1": PermissionEffect.ALLOW}}),
            PermissionTable(table={Principal("P1", [], []): {"A2-R1": PermissionEffect.ALLOW}}),
            PermissionTable(
                table={Principal("P1", [], []): {"A1-R1": PermissionEffect.ALLOW, "A2-R1": PermissionEffect.ALLOW}}
            ),
        ),
        (
            PermissionTable(table={Principal("P1", [], []): {"A1-R1": PermissionEffect.ALLOW}}),
            PermissionTable(table={Principal("P1", [], []): {"A1-R1": PermissionEffect.DENY}}),
            PermissionTable(table={Principal("P1", [], []): {"A1-R1": PermissionEffect.DENY}}),
        ),
        (
            PermissionTable(table={Principal("P1", [], []): {"A1-R1": PermissionEffect.ALLOW}}),
            PermissionTable(table={Principal("P1", [], []): {"A1-R1": PermissionEffect.IMPLICIT_DENY}}),
            PermissionTable(table={Principal("P1", [], []): {"A1-R1": PermissionEffect.ALLOW}}),
        ),
        (
            PermissionTable(table={Principal("P1", [], []): {"A1-R1": PermissionEffect.DENY}}),
            PermissionTable(table={Principal("P1", [], []): {"A1-R1": PermissionEffect.IMPLICIT_DENY}}),
            PermissionTable(table={Principal("P1", [], []): {"A1-R1": PermissionEffect.DENY}}),
        ),
    ],
)
def test_permission_table_merge(
    perm_table: PermissionTable, other_table: PermissionTable, expected: PermissionTable
) -> None:
    perm_table.merge(other=other_table)
    assert perm_table.table == expected.table


@pytest.mark.parametrize(
    "permission_table,principal,action,expected",
    [
        (
            PermissionTable(table={Principal("*", [], []): {"*:*-*": PermissionEffect.ALLOW}}),
            Principal("john.doe", [], []),
            "ec2:RunInstances",
            True,
        ),
        (
            PermissionTable(
                table={
                    Principal("arn:aws:iam::123456789012:role/RoleEngineer", [], []): {
                        "ec2:*-*": PermissionEffect.ALLOW,
                        "s3:*-*": PermissionEffect.ALLOW,
                    },
                }
            ),
            Principal("arn:aws:iam::123456789012:role/RoleAdmin", [], []),
            "s3:GetBucketAcl",
            False,
        ),
        (
            PermissionTable(
                table={
                    Principal("arn:aws:iam::123456789012:role/RoleE*", [], []): {
                        "ec2:*-*": PermissionEffect.ALLOW,
                        "s3:*-*": PermissionEffect.ALLOW,
                    },
                    Principal("arn:aws:iam::123456789012:role/RoleEngineer", [], []): {
                        "ec2:*-*": PermissionEffect.DENY,
                        "s3:*-*": PermissionEffect.DENY,
                    },
                }
            ),
            Principal("arn:aws:iam::123456789012:role/RoleEngineer", [], []),
            "s3:GetBucketAcl",
            False,
        ),
        (
            PermissionTable(
                table={
                    Principal("arn:aws:iam::123456789012:role/RoleE*", [], []): {
                        "s3:DeleteBucket-arn:aws:s3:::bucketA": PermissionEffect.ALLOW,
                        "s3:DeleteBucket-arn:aws:s3:::bucketB": PermissionEffect.ALLOW,
                        "s3:Get*-*": PermissionEffect.ALLOW,
                        "s3:List*-*": PermissionEffect.ALLOW,
                    }
                }
            ),
            Principal("arn:aws:iam::123456789012:role/RoleEngineer", [], []),
            "s3:DeleteBucket",
            True,
        ),
        (
            PermissionTable(
                table={
                    Principal("*", [], []): {"kms:*-*": PermissionEffect.ALLOW},
                    Principal("arn:aws:iam::123456789012:role/RoleAdmin", [], []): {
                        "kms:*-*": PermissionEffect.IMPLICIT_DENY
                    },
                }
            ),
            Principal("arn:aws:iam::123456789012:role/RoleAdmin", [], []),
            "kms:ScheduleKeyDeletion",
            True,
        ),
        (
            PermissionTable(
                table={
                    Principal("*", [], []): {"ec2:*-*": PermissionEffect.DENY},
                    Principal("arn:aws:iam::123456789012:role/RoleAdmin", [], []): {
                        "ec2:*-*": PermissionEffect.IMPLICIT_DENY
                    },
                }
            ),
            Principal("arn:aws:iam::123456789012:role/RoleAdmin", [], []),
            "ec2:RunInstances",
            False,
        ),
        (
            PermissionTable(
                table={
                    Principal("*", [], []): {"ec2:*-*": PermissionEffect.DENY},
                    Principal("arn:aws:iam::123456789012:role/RoleEngineer", [], []): {
                        "ec2:*-*": PermissionEffect.DENY
                    },
                }
            ),
            Principal("arn:aws:iam::123456789012:role/RoleEngineer", [], []),
            "ec2:RunInstances",
            False,
        ),
        (
            PermissionTable(
                table={
                    Principal(identifier="*", excludes=[], only=[]): {
                        "kms:ScheduleKeyDeletion-*": PermissionEffect.DENY
                    },
                    Principal("arn:aws:iam::123456789012:role/RoleEngineer", [], []): {
                        "kms:ScheduleKeyDeletion-*": PermissionEffect.ALLOW
                    },
                }
            ),
            Principal("arn:aws:iam::123456789012:role/RoleEngineer", [], []),
            "kms:ScheduleKeyDeletion",
            False,
        ),
        (
            PermissionTable(
                table={
                    Principal(
                        identifier="*",
                        excludes=[Principal("arn:aws:iam::123456789012:role/RoleEngineer", [], [])],
                        only=[],
                    ): {"kms:ScheduleKeyDeletion-*": PermissionEffect.DENY},
                    Principal("arn:aws:iam::123456789012:role/RoleEngineer", [], []): {
                        "kms:ScheduleKeyDeletion-*": PermissionEffect.ALLOW
                    },
                }
            ),
            Principal("arn:aws:iam::123456789012:role/RoleEngineer", [], []),
            "kms:ScheduleKeyDeletion",
            True,
        ),
        (
            PermissionTable(
                table={
                    Principal(
                        identifier="*",
                        excludes=[Principal("arn:aws:iam::123456789012:role/RoleAdmin", [], [])],
                        only=[],
                    ): {
                        "s3:PutObject*-arn:aws:s3:::bucketA": PermissionEffect.DENY,
                        "s3:ListMultipartUploadParts-arn:aws:s3:::bucketA": PermissionEffect.DENY,
                        "s3:DeleteObject*-arn:aws:s3:::bucketA": PermissionEffect.DENY,
                        "s3:PutObject*-arn:aws:s3:::bucketB": PermissionEffect.DENY,
                        "s3:ListMultipartUploadParts-arn:aws:s3:::bucketB": PermissionEffect.DENY,
                        "s3:DeleteObject*-arn:aws:s3:::bucketB": PermissionEffect.DENY,
                    },
                    Principal("arn:aws:iam::123456789012:role/RoleAdmin", [], []): {
                        "s3:PutObject*-arn:aws:s3:::bucketA": PermissionEffect.ALLOW,
                        "s3:ListMultipartUploadParts-arn:aws:s3:::bucketA": PermissionEffect.ALLOW,
                        "s3:DeleteObject*-arn:aws:s3:::bucketA": PermissionEffect.ALLOW,
                        "s3:PutObject*-arn:aws:s3:::bucketB": PermissionEffect.IMPLICIT_DENY,
                        "s3:ListMultipartUploadParts-arn:aws:s3:::bucketB": PermissionEffect.ALLOW,
                        "s3:DeleteObject*-arn:aws:s3:::bucketB": PermissionEffect.IMPLICIT_DENY,
                    },
                }
            ),
            Principal("arn:aws:iam::123456789012:role/RoleAdmin", [], []),
            "s3:PutObject",
            True,
        ),
    ],
)
def test_permission_table_is_principal_allowed_action(
    permission_table: PermissionTable, principal: Principal, action: str, expected: bool
) -> None:
    assert permission_table.is_principal_allowed_action(principal=principal, action=action) == expected


@pytest.mark.parametrize(
    "string,expected",
    [
        ("*abcde", True),
        ("abc*de", True),
        ("abcde*", True),
        ("?abcef", True),
        ("abc?ef", True),
        ("abcef?", True),
        ("abcef", False),
    ],
)
def test_has_wildcard(string: str, expected: bool) -> None:
    PermissionTable.has_wildcard(string=string) == expected


@pytest.mark.parametrize(
    "permission_table,request_context,expected",
    [
        (
            PermissionTable(
                table={
                    Principal("P1", [], []): {
                        "A1-R1": PermissionEffect.ALLOW,
                        "A1-R2": PermissionEffect.ALLOW,
                        "A2-R1": PermissionEffect.ALLOW,
                        "A2-R2": PermissionEffect.ALLOW,
                    },
                    Principal("P2", [], []): {
                        "A1-R1": PermissionEffect.ALLOW,
                        "A1-R2": PermissionEffect.ALLOW,
                        "A2-R1": PermissionEffect.ALLOW,
                        "A2-R2": PermissionEffect.ALLOW,
                    },
                }
            ),
            RequestContext(
                items={
                    "aws:PrincipalArn": RequestContextItem(key="aws:PrincipalArn", value="P1"),
                    "Action": RequestContextItem(key="Action", value="A1"),
                    "Resource": RequestContextItem(key="Resource", value="R1"),
                }
            ),
            True,
        ),
        (
            PermissionTable(
                table={
                    Principal("P1", [], []): {
                        "A1-R1": PermissionEffect.ALLOW,
                        "A1-R2": PermissionEffect.ALLOW,
                        "A2-R1": PermissionEffect.ALLOW,
                        "A2-R2": PermissionEffect.ALLOW,
                    },
                    Principal("P2", [], []): {
                        "A1-R1": PermissionEffect.ALLOW,
                        "A1-R2": PermissionEffect.ALLOW,
                        "A2-R1": PermissionEffect.ALLOW,
                        "A2-R2": PermissionEffect.ALLOW,
                    },
                }
            ),
            RequestContext(
                items={
                    "aws:PrincipalArn": RequestContextItem(key="aws:PrincipalArn", value="P2"),
                    "Action": RequestContextItem(key="Action", value="A1"),
                    "Resource": RequestContextItem(key="Resource", value="R2"),
                }
            ),
            True,
        ),
        (
            PermissionTable(
                table={
                    Principal("P1", [], []): {
                        "A1-R1": PermissionEffect.ALLOW,
                        "A1-R2": PermissionEffect.ALLOW,
                        "A2-R1": PermissionEffect.ALLOW,
                        "A2-R2": PermissionEffect.ALLOW,
                    },
                    Principal("P2", [], []): {
                        "A1-R1": PermissionEffect.ALLOW,
                        "A1-R2": PermissionEffect.ALLOW,
                        "A2-R1": PermissionEffect.ALLOW,
                        "A2-R2": PermissionEffect.ALLOW,
                    },
                }
            ),
            RequestContext(
                items={
                    "aws:PrincipalArn": RequestContextItem(key="aws:PrincipalArn", value="PX"),
                    "Action": RequestContextItem(key="Action", value="A1"),
                    "Resource": RequestContextItem(key="Resource", value="R1"),
                }
            ),
            False,
        ),
        (
            PermissionTable(
                table={
                    Principal("P1", [], []): {
                        "A1-R1": PermissionEffect.ALLOW,
                        "A1-R2": PermissionEffect.ALLOW,
                        "A2-R1": PermissionEffect.ALLOW,
                        "A2-R2": PermissionEffect.ALLOW,
                    },
                    Principal("P2", [], []): {
                        "A1-R1": PermissionEffect.ALLOW,
                        "A1-R2": PermissionEffect.ALLOW,
                        "A2-R1": PermissionEffect.ALLOW,
                        "A2-R2": PermissionEffect.ALLOW,
                    },
                }
            ),
            RequestContext(
                items={
                    "aws:PrincipalArn": RequestContextItem(key="aws:PrincipalArn", value="P2"),
                    "Action": RequestContextItem(key="Action", value="A1"),
                    "Resource": RequestContextItem(key="Resource", value="RX"),
                }
            ),
            False,
        ),
        (
            PermissionTable(table={Principal("*", [], []): {"*:*-*": PermissionEffect.ALLOW}}),
            RequestContext(
                items={
                    "aws:PrincipalArn": RequestContextItem(
                        key="aws:PrincipalArn", value="arn:aws:iam::123456789012:role/RoleAdmin"
                    ),
                    "Action": RequestContextItem(key="Action", value="s3:CreateBucket"),
                    "Resource": RequestContextItem(key="Resource", value="arn:aws:s3:::bucketA"),
                }
            ),
            True,
        ),
        (
            PermissionTable(
                table={
                    Principal("arn:aws:iam::123456789012:role/RoleAdmin", [], []): {
                        "ec2:*-arn:aws:ec2:eu-west-2:123456789012:instance/*": PermissionEffect.ALLOW,
                        "s3:*-arn:aws:ec2:eu-west-2:123456789012:instance/*": PermissionEffect.ALLOW,
                    },
                }
            ),
            RequestContext(
                items={
                    "aws:PrincipalArn": RequestContextItem(
                        key="aws:PrincipalArn", value="arn:aws:iam::123456789012:role/RoleAdmin"
                    ),
                    "Action": RequestContextItem(key="Action", value="ec2:RunInstances"),
                    "Resource": RequestContextItem(
                        key="Resource", value="arn:aws:ec2:eu-west-2:123456789012:instance/i-5203422c"
                    ),
                }
            ),
            True,
        ),
        (
            PermissionTable(
                table={
                    Principal("arn:aws:iam::123456789012:role/RoleEngineer", [], []): {
                        "ec2:*-*": PermissionEffect.DENY,
                        "s3:*-*": PermissionEffect.DENY,
                    },
                }
            ),
            RequestContext(
                items={
                    "aws:PrincipalArn": RequestContextItem(
                        key="aws:PrincipalArn", value="arn:aws:iam::123456789012:role/RoleEngineer"
                    ),
                    "Action": RequestContextItem(key="Action", value="s3:DeleteBucket"),
                    "Resource": RequestContextItem(key="Resource", value="arn:aws:s3:::bucketA"),
                }
            ),
            True,
        ),
    ],
)
def test_is_matched_by_permission_table(
    permission_table: PermissionTable, request_context: RequestContext, expected: bool
) -> None:
    assert permission_table.match(request_context=request_context) == expected


@pytest.mark.parametrize(
    "permission_table,request_context,missing_context_key",
    [
        (
            PermissionTable(table={Principal("*", [], []): {"*:*-*": PermissionEffect.ALLOW}}),
            RequestContext(
                items={
                    "Action": RequestContextItem(key="Action", value="s3:CreateBucket"),
                    "Resource": RequestContextItem(key="Resource", value="arn:aws:s3:::bucketA"),
                }
            ),
            "aws:PrincipalArn",
        ),
        (
            PermissionTable(table={Principal("*", [], []): {"*:*-*": PermissionEffect.ALLOW}}),
            RequestContext(
                items={
                    "aws:PrincipalArn": RequestContextItem(
                        key="aws:PrincipalArn", value="arn:aws:iam::123456789012:role/RoleEngineer"
                    ),
                    "Resource": RequestContextItem(key="Resource", value="arn:aws:s3:::bucketA"),
                }
            ),
            "Action",
        ),
        (
            PermissionTable(table={Principal("*", [], []): {"*:*-*": PermissionEffect.ALLOW}}),
            RequestContext(
                items={
                    "aws:PrincipalArn": RequestContextItem(
                        key="aws:PrincipalArn", value="arn:aws:iam::123456789012:role/RoleEngineer"
                    ),
                    "Action": RequestContextItem(key="Action", value="s3:CreateBucket"),
                }
            ),
            "Resource",
        ),
    ],
)
def test_is_matched_by_permission_table_missing_request_context_item(
    permission_table: PermissionTable, request_context: RequestContext, missing_context_key: str
) -> None:
    with pytest.raises(
        RequestContextItemNotFoundException, match=f"request context item not found - {missing_context_key}"
    ):
        permission_table.match(request_context=request_context)
