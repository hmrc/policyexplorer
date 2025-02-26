from typing import Any, Dict, List, NamedTuple
import pytest

from policyexplorer.condition import Condition
from policyexplorer.effect import Effect
from policyexplorer.permission import PermissionEffect
from policyexplorer.permission_table import PermissionTable
from policyexplorer.principal import Principal
from policyexplorer.statement import Statement
from policyexplorer.request_context import RequestContext, RequestContextItem

StatementTuple = NamedTuple(
    "StatementTuple",
    [
        ("effect", str),
        ("principal", List[str]),
        ("action", List[str]),
        ("resource", List[str]),
        ("condition", Condition),
    ],
)


@pytest.mark.parametrize(
    "statement,statement_tuple",
    [
        (
            dict(
                Effect="Allow",
                Principal="*",
                Action="*:*",
                Resource="*",
            ),
            StatementTuple(
                effect="Allow",
                principal=[Principal("*", [], [])],
                action=["*:*"],
                resource=["*"],
                condition=Condition(raw={}),
            ),
        ),
        (
            dict(
                Effect="Allow",
                Principal="arn:aws:iam::123456789012:role/RoleAdmin",
                Action="*:*",
                Resource="*",
            ),
            StatementTuple(
                effect="Allow",
                principal=[Principal("arn:aws:iam::123456789012:role/RoleAdmin", [], [])],
                action=["*:*"],
                resource=["*"],
                condition=Condition(raw={}),
            ),
        ),
        (
            dict(
                Effect="Allow",
                Principal="arn:aws:iam::123456789012:role/RoleAdmin",
                Action=["ec2:*", "s3:*"],
                Resource="*",
            ),
            StatementTuple(
                effect="Allow",
                principal=[Principal("arn:aws:iam::123456789012:role/RoleAdmin", [], [])],
                action=["ec2:*", "s3:*"],
                resource=["*"],
                condition=Condition(raw={}),
            ),
        ),
        (
            dict(
                Effect="Allow",
                Principal="*",
                Action="s3:DeleteBucket",
                Resource=["arn:aws:s3:::bucketA", "arn:aws:s3:::bucketB"],
            ),
            StatementTuple(
                effect="Allow",
                principal=[Principal("*", [], [])],
                action=["s3:DeleteBucket"],
                resource=["arn:aws:s3:::bucketA", "arn:aws:s3:::bucketB"],
                condition=Condition(raw={}),
            ),
        ),
        (
            dict(
                Effect="Deny",
                Principal="*",
                Action="kms:ScheduleKeyDeletion",
                Resource="*",
                Condition={"StringNotEquals": {"aws:PrincipalArn": "arn:aws:iam::123456789012:role/RoleAdmin"}},
            ),
            StatementTuple(
                effect="Deny",
                principal=[Principal("*", [Principal("arn:aws:iam::123456789012:role/RoleAdmin", [], [])], [])],
                action=["kms:ScheduleKeyDeletion"],
                resource=["*"],
                condition=Condition(
                    raw={"StringNotEquals": {"aws:PrincipalArn": "arn:aws:iam::123456789012:role/RoleAdmin"}}
                ),
            ),
        ),
        (
            dict(
                Effect="Deny",
                Principal="*",
                Action=["iam:*AccessKey*"],
                Resource="arn:aws:iam::account-id:user/*",
                Condition={"NotIpAddress": {"aws:SourceIp": "203.0.113.0/24"}},
            ),
            StatementTuple(
                effect="Deny",
                principal=[Principal("*", [], [])],
                action=["iam:*AccessKey*"],
                resource=["arn:aws:iam::account-id:user/*"],
                condition=Condition(raw={"NotIpAddress": {"aws:SourceIp": "203.0.113.0/24"}}),
            ),
        ),
    ],
)
def test_statement_parsing(statement: Dict[str, Any], statement_tuple: StatementTuple) -> None:
    st = Statement(raw=statement)

    assert st.effect == statement_tuple.effect
    assert st.principal == statement_tuple.principal
    assert st.action == statement_tuple.action
    assert st.resource == statement_tuple.resource
    assert st.condition._condition == statement_tuple.condition._condition


@pytest.mark.parametrize(
    "statement,permission_table",
    [
        (
            dict(
                Effect="Allow",
                Principal="*",
                Action="*:*",
                Resource="*",
            ),
            PermissionTable(table={Principal("*", [], []): {"*:*-*": PermissionEffect.ALLOW}}),
        ),
        (
            dict(
                Effect="Allow",
                Principal="arn:aws:iam::123456789012:role/RoleAdmin",
                Action=["ec2:*", "s3:*"],
                Resource="*",
            ),
            PermissionTable(
                table={
                    Principal("arn:aws:iam::123456789012:role/RoleAdmin", [], []): {
                        "ec2:*-*": PermissionEffect.ALLOW,
                        "s3:*-*": PermissionEffect.ALLOW,
                    }
                }
            ),
        ),
        (
            dict(
                Effect="Allow",
                Principal="arn:aws:iam::123456789012:role/RoleAdmin",
                Action="*:*",
                Resource="*",
            ),
            PermissionTable(
                table={Principal("arn:aws:iam::123456789012:role/RoleAdmin", [], []): {"*:*-*": PermissionEffect.ALLOW}}
            ),
        ),
        (
            dict(
                Effect="Allow",
                Principal="*",
                Action="s3:DeleteBucket",
                Resource=["arn:aws:s3:::bucketA", "arn:aws:s3:::bucketB"],
            ),
            PermissionTable(
                table={
                    Principal("*", [], []): {
                        "s3:DeleteBucket-arn:aws:s3:::bucketA": PermissionEffect.ALLOW,
                        "s3:DeleteBucket-arn:aws:s3:::bucketB": PermissionEffect.ALLOW,
                    }
                }
            ),
        ),
        (
            dict(
                Effect="Allow",
                Principal="*",
                Action="kms:*",
                Resource="*",
                Condition={"StringNotLike": {"aws:PrincipalArn": "arn:aws:iam::123456789012:role/RoleAdmin"}},
            ),
            PermissionTable(
                table={
                    Principal(
                        identifier="*",
                        excludes=[Principal("arn:aws:iam::123456789012:role/RoleAdmin", [], [])],
                        only=[],
                    ): {"kms:*-*": PermissionEffect.ALLOW.value},
                    Principal("arn:aws:iam::123456789012:role/RoleAdmin", [], []): {
                        "kms:*-*": PermissionEffect.IMPLICIT_DENY.value
                    },
                }
            ),
        ),
        (
            dict(
                Effect="Deny",
                Principal="*",
                Action="ec2:*",
                Resource="*",
                Condition={"StringNotLike": {"aws:PrincipalArn": "arn:aws:iam::123456789012:role/RoleAdmin"}},
            ),
            PermissionTable(
                table={
                    Principal(
                        identifier="*",
                        excludes=[Principal("arn:aws:iam::123456789012:role/RoleAdmin", [], [])],
                        only=[],
                    ): {"ec2:*-*": PermissionEffect.DENY},
                    Principal("arn:aws:iam::123456789012:role/RoleAdmin", [], []): {
                        "ec2:*-*": PermissionEffect.IMPLICIT_DENY
                    },
                }
            ),
        ),
        (
            dict(
                Effect="Deny",
                Principal="*",
                Action="ec2:*",
                Resource="*",
                Condition={"StringLike": {"aws:PrincipalArn": "arn:aws:iam::123456789012:role/RoleEngineer"}},
            ),
            PermissionTable(
                table={
                    Principal(
                        identifier="*",
                        excludes=[],
                        only=[Principal("arn:aws:iam::123456789012:role/RoleEngineer", [], [])],
                    ): {"ec2:*-*": PermissionEffect.DENY},
                    Principal("arn:aws:iam::123456789012:role/RoleEngineer", [], []): {
                        "ec2:*-*": PermissionEffect.DENY
                    },
                }
            ),
        ),
        (
            dict(
                Effect="Deny",
                Principal="*",
                Action="kms:ScheduleKeyDeletion",
                Resource="*",
                Condition={"StringNotLike": {"aws:PrincipalArn": "arn:aws:iam::123456789012:role/RoleEngineer"}},
            ),
            PermissionTable(
                table={
                    Principal(
                        identifier="*",
                        excludes=[Principal("arn:aws:iam::123456789012:role/RoleEngineer", [], [])],
                        only=[],
                    ): {"kms:ScheduleKeyDeletion-*": PermissionEffect.DENY},
                    Principal("arn:aws:iam::123456789012:role/RoleEngineer", [], []): {
                        "kms:ScheduleKeyDeletion-*": PermissionEffect.IMPLICIT_DENY
                    },
                }
            ),
        ),
        (
            dict(
                Effect="Deny",
                Principal="*",
                Action=["s3:PutObject*", "s3:ListMultipartUploadParts", "s3:DeleteObject*"],
                Resource=["arn:aws:s3:::bucketA", "arn:aws:s3:::bucketB"],
                Condition={
                    "ArnNotLike": {"aws:PrincipalArn": ["arn:aws:iam::123456789012:role/RoleAdmin"]},
                    "Bool": {"aws:SecureTransport": False},
                },
            ),
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
                        "s3:PutObject*-arn:aws:s3:::bucketA": PermissionEffect.IMPLICIT_DENY,
                        "s3:ListMultipartUploadParts-arn:aws:s3:::bucketA": PermissionEffect.IMPLICIT_DENY,
                        "s3:DeleteObject*-arn:aws:s3:::bucketA": PermissionEffect.IMPLICIT_DENY,
                        "s3:PutObject*-arn:aws:s3:::bucketB": PermissionEffect.IMPLICIT_DENY,
                        "s3:ListMultipartUploadParts-arn:aws:s3:::bucketB": PermissionEffect.IMPLICIT_DENY,
                        "s3:DeleteObject*-arn:aws:s3:::bucketB": PermissionEffect.IMPLICIT_DENY,
                    },
                }
            ),
        ),
    ],
)
def test_statement_permission_table(statement: Dict[str, Any], permission_table: PermissionTable) -> None:
    st = Statement(raw=statement)
    assert st.permission_table == permission_table


# effect    | is_matched_by_permission_table | is_matched_by_condition | Result
# ------    | ----------------------------- | ----------------------- | ------
# 0 (Allow) | 0 (False)                     | 0 (False)               | Deny
# 0 (Allow) | 0 (False)                     | 1 (True)                | Deny
# 0 (Allow) | 1 (True)                      | 0 (False)               | Deny
# 0 (Allow) | 1 (True)                      | 1 (True)                | ALLOW
# 1 (Deny)  | 0 (False)                     | 0 (False)               | Deny
# 1 (Deny)  | 0 (False)                     | 1 (True)                | Deny
# 1 (Deny)  | 1 (True)                      | 0 (False)               | ALLOW
# 1 (Deny)  | 1 (True)                      | 1 (True)                | Deny


@pytest.mark.parametrize(
    "statement,request_context,expected",
    [
        # effect | is_matched_by_permission_table | is_matched_by_condition | Result
        # ------ | ----------------------------- | ----------------------- | ------
        # Allow  | True                          | True                    | ALLOW
        (
            dict(
                Effect="Allow",
                Principal="*",
                Action="*:*",
                Resource="*",
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
            Effect.ALLOW,
        ),
        (
            dict(
                Effect="Allow",
                Principal="arn:aws:iam::123456789012:role/RoleAdmin",
                Action=["ec2:*", "s3:*"],
                Resource="*",
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
            Effect.ALLOW,
        ),
        # effect | is_matched_by_permission_table | is_matched_by_condition | Result
        # ------ | ----------------------------- | ----------------------- | ------
        # Allow  | False                         | True                    | Deny
        (
            dict(
                Effect="Allow",
                Principal="arn:aws:iam::123456789012:role/RoleAdmin",
                Action="*:*",
                Resource="*",
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
            Effect.DENY,
        ),
        (
            dict(
                Effect="Allow",
                Principal="*",
                Action="s3:DeleteBucket",
                Resource=["arn:aws:s3:::bucketA", "arn:aws:s3:::bucketB"],
            ),
            RequestContext(
                items={
                    "aws:PrincipalArn": RequestContextItem(
                        key="aws:PrincipalArn", value="arn:aws:iam::123456789012:role/RoleEngineer"
                    ),
                    "Action": RequestContextItem(key="Action", value="s3:DeleteBucket"),
                    "Resource": RequestContextItem(key="Resource", value="arn:aws:s3:::bucketXXX"),
                }
            ),
            Effect.DENY,
        ),
        # effect | is_matched_by_permission_table | is_matched_by_condition | Result
        # ------ | ----------------------------- | ----------------------- | ------
        # Allow  | True                          | False                   | Deny
        (
            dict(
                Effect="Allow",
                Principal="*",
                Action="kms:*",
                Resource="*",
                Condition={"StringNotLike": {"aws:PrincipalArn": "arn:aws:iam::123456789012:role/RoleAdmin"}},
            ),
            RequestContext(
                items={
                    "aws:PrincipalArn": RequestContextItem(
                        key="aws:PrincipalArn", value="arn:aws:iam::123456789012:role/RoleAdmin"
                    ),
                    "Action": RequestContextItem(key="Action", value="kms:ScheduleKeyDeletion"),
                    "Resource": RequestContextItem(
                        key="Resource", value="arn:aws:kms:us-west-2:123456789012:key/k1234"
                    ),
                }
            ),
            Effect.DENY,
        ),
        # effect | is_matched_by_permission_table | is_matched_by_condition | Result
        # ------ | ----------------------------- | ----------------------- | ------
        # Deny   | False                         | False                   | Deny (implicit)
        (
            dict(
                Effect="Deny",
                Principal="*",
                Action="ec2:*",
                Resource="*",
                Condition={"StringNotLike": {"aws:PrincipalArn": "arn:aws:iam::123456789012:role/RoleAdmin"}},
            ),
            RequestContext(
                items={
                    "aws:PrincipalArn": RequestContextItem(
                        key="aws:PrincipalArn", value="arn:aws:iam::123456789012:role/RoleAdmin"
                    ),
                    "Action": RequestContextItem(key="Action", value="s3:PutObject"),
                    "Resource": RequestContextItem(
                        key="Resource", value="arn:aws:kms:us-west-2:123456789012:key/k1234"
                    ),
                }
            ),
            Effect.DENY,
        ),
        # effect | is_matched_by_permission_table | is_matched_by_condition | Result
        # ------ | ----------------------------- | ----------------------- | ------
        # Deny   | False                         | True                    | Deny (implicit)
        (
            dict(
                Effect="Deny",
                Principal="*",
                Action="ec2:*",
                Resource="*",
                Condition={"StringLike": {"aws:PrincipalArn": "arn:aws:iam::123456789012:role/RoleAdmin"}},
            ),
            RequestContext(
                items={
                    "aws:PrincipalArn": RequestContextItem(
                        key="aws:PrincipalArn", value="arn:aws:iam::123456789012:role/RoleAdmin"
                    ),
                    "Action": RequestContextItem(key="Action", value="s3:PutObject"),
                    "Resource": RequestContextItem(
                        key="Resource", value="arn:aws:kms:us-west-2:123456789012:key/k1234"
                    ),
                }
            ),
            Effect.DENY,
        ),
        # effect | is_matched_by_permission_table | is_matched_by_condition | Result
        # ------ | ----------------------------- | ----------------------- | ------
        # Deny   | True                          | False                   | ALLOW
        (
            dict(
                Effect="Deny",
                Principal="*",
                Action="kms:ScheduleKeyDeletion",
                Resource="*",
                Condition={"StringNotLike": {"aws:PrincipalArn": "arn:aws:iam::123456789012:role/RoleAdmin"}},
            ),
            RequestContext(
                items={
                    "aws:PrincipalArn": RequestContextItem(
                        key="aws:PrincipalArn", value="arn:aws:iam::123456789012:role/RoleAdmin"
                    ),
                    "Action": RequestContextItem(key="Action", value="kms:ScheduleKeyDeletion"),
                    "Resource": RequestContextItem(
                        key="Resource", value="arn:aws:kms:us-west-2:123456789012:key/k1234"
                    ),
                }
            ),
            Effect.ALLOW,
        ),
        (
            dict(
                Effect="Deny",
                Principal="*",
                Action=["s3:PutObject*", "s3:ListMultipartUploadParts", "s3:DeleteObject*"],
                Resource=["arn:aws:s3:::bucketA", "arn:aws:s3:::bucketB"],
                Condition={
                    "ArnNotLike": {"aws:PrincipalArn": ["arn:aws:iam::132732819912:role/RoleAdmin"]},
                    "Bool": {"aws:SecureTransport": False},
                },
            ),
            RequestContext(
                items={
                    "aws:PrincipalArn": RequestContextItem(
                        key="aws:PrincipalArn", value="arn:aws:iam::123456789012:role/RoleAdmin"
                    ),
                    "Action": RequestContextItem(key="Action", value="s3:PutObjectAcl"),
                    "Resource": RequestContextItem(key="Resource", value="arn:aws:s3:::bucketA"),
                    "aws:SecureTransport": RequestContextItem(key="aws:SecureTransport", value=True),
                }
            ),
            Effect.ALLOW,
        ),
        # effect | is_matched_by_permission_table | is_matched_by_condition | Result
        # ------ | ----------------------------- | ----------------------- | ------
        # Deny   | True                          | True                    | Deny
        (
            dict(
                Effect="Deny",
                Principal="*",
                Action="kms:ScheduleKeyDeletion",
                Resource="*",
                Condition={"StringNotLike": {"aws:PrincipalArn": "arn:aws:iam::123456789012:role/RoleAdmin"}},
            ),
            RequestContext(
                items={
                    "aws:PrincipalArn": RequestContextItem(
                        key="aws:PrincipalArn", value="arn:aws:iam::123456789012:role/RoleEngineer"
                    ),
                    "Action": RequestContextItem(key="Action", value="kms:ScheduleKeyDeletion"),
                    "Resource": RequestContextItem(
                        key="Resource", value="arn:aws:kms:us-west-2:123456789012:key/k1234"
                    ),
                }
            ),
            Effect.DENY,
        ),
    ],
)
def test_statement_evaluate(statement: Dict[str, Any], request_context: RequestContext, expected: str) -> None:
    st = Statement(raw=statement)
    assert st.evaluate(request_context=request_context) == expected
