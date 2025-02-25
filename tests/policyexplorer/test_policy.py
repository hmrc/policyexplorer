from typing import Any, Dict, List, NamedTuple
import pytest

from policyexplorer.permission import PermissionEffect
from policyexplorer.permission_table import PermissionTable
from policyexplorer.policy import Policy
from policyexplorer.principal import Principal
from policyexplorer.statement import Statement

PolicyTuple = NamedTuple("PolicyTuple", [("version", str), ("statement", List[Statement])])


@pytest.mark.parametrize(
    "policy,policy_tuple",
    [
        (
            dict(
                Version="2012-10-17",
                Statement=[
                    dict(
                        Effect='Allow',
                        Principal='arn:aws:iam::123456789012:role/RoleAdmin',
                        Action=["ec2:*", "s3:*", "kms:*"],
                        Resource='*',
                    ),
                    dict(
                        Effect='Deny',
                        Principal='*',
                        Action="kms:ScheduleKeyDeletion",
                        Resource='*',
                        Condition={
                            "StringNotEquals": {
                                "aws:PrincipalArn": "arn:aws:iam::123456789012:role/RoleAdmin"
                            }
                        }
                    ),
                ]
            ),
            PolicyTuple(
                version="2012-10-17",
                statement=[
                    Statement(raw=dict(
                        Effect='Allow',
                        Principal='arn:aws:iam::123456789012:role/RoleAdmin',
                        Action=["ec2:*", "s3:*", "kms:*"],
                        Resource='*',
                    )),
                    Statement(raw=dict(
                        Effect='Deny',
                        Principal='*',
                        Action="kms:ScheduleKeyDeletion",
                        Resource='*',
                        Condition={
                            "StringNotEquals": {
                                "aws:PrincipalArn": "arn:aws:iam::123456789012:role/RoleAdmin"
                            }
                        }
                    )),
                ]
            )
        ),
        (
            dict(
                Version="2012-10-17",
                Statement=[
                    dict(
                        Effect='Deny',
                        Principal='*',
                        Action=["s3:Get*", "s3:List*", "s3:PutObject*"],
                        Resource="arn:aws:s3:::bucketA/*",
                        Condition={
                            "ArnNotLike": {
                                "aws:PrincipalArn": [
                                    "arn:aws:iam::123456789012:role/RoleAdmin",
                                    "arn:aws:iam::123456789012:role/RoleEngineer"
                                ],
                            }
                        }
                    ),
                    dict(
                        Effect='Allow',
                        Principal='*',
                        Action="s3:*",
                        Resource=["arn:aws:s3:::bucketA", "arn:aws:s3:::bucketA/*"],
                        Condition={
                            "ArnLike": {
                                "aws:PrincipalArn": [
                                    "arn:aws:iam::123456789012:role/RoleAdmin",
                                    "arn:aws:iam::123456789012:role/RoleEngineer"
                                ],
                            }
                        }
                    ),
                ]
            ),
            PolicyTuple(
                version="2012-10-17",
                statement=[
                    Statement(raw=dict(
                        Effect='Deny',
                        Principal='*',
                        Action=["s3:Get*", "s3:List*", "s3:PutObject*"],
                        Resource="arn:aws:s3:::bucketA/*",
                        Condition={
                            "ArnNotLike": {
                                "aws:PrincipalArn": [
                                    "arn:aws:iam::123456789012:role/RoleAdmin",
                                    "arn:aws:iam::123456789012:role/RoleEngineer"
                                ],
                            }
                        }
                    )),
                    Statement(raw=dict(
                        Effect='Allow',
                        Principal='*',
                        Action="s3:*",
                        Resource=["arn:aws:s3:::bucketA", "arn:aws:s3:::bucketA/*"],
                        Condition={
                            "ArnLike": {
                                "aws:PrincipalArn": [
                                    "arn:aws:iam::123456789012:role/RoleAdmin",
                                    "arn:aws:iam::123456789012:role/RoleEngineer"
                                ],
                            }
                        }
                    )),
                ]
            )
        ),
    ]
)
def test_policy_parsing(policy: Dict[str, Any], policy_tuple: PolicyTuple) -> None:
    p = Policy(raw=policy)

    assert len(p.statement) == len(policy_tuple.statement)
    assert p.version == policy_tuple.version
    for i, st in enumerate(p.statement):
        assert st._statement == policy_tuple.statement[i]._statement


@pytest.mark.parametrize(
    "policy,permission_table",
    [
        (
            dict(
                Version="2012-10-17",
                Statement=[
                    dict(
                        Effect='Allow',
                        Principal='*',
                        Action="*:*",
                        Resource='*',
                    ),
                ]
            ),
            PermissionTable(
                table={
                    Principal("*", [], []): {"*:*-*": PermissionEffect.ALLOW}
                }
            ),
        ),
        (
            dict(
                Version="2012-10-17",
                Statement=[
                    dict(
                        Effect='Allow',
                        Principal='arn:aws:iam::123456789012:role/RoleAdmin',
                        Action=["ec2:*", "s3:*"],
                        Resource='*',
                    ), 
                    dict(
                        Effect='Deny',
                        Principal='arn:aws:iam::123456789012:role/RoleEngineer',
                        Action=["ec2:*", "s3:*"],
                        Resource='*',
                    ), 
                ]
            ),
            PermissionTable(
                table={
                    Principal("arn:aws:iam::123456789012:role/RoleAdmin", [], []): {
                        "ec2:*-*": PermissionEffect.ALLOW,
                        "s3:*-*": PermissionEffect.ALLOW,
                    },
                    Principal("arn:aws:iam::123456789012:role/RoleEngineer", [], []): {
                        "ec2:*-*": PermissionEffect.DENY,
                        "s3:*-*": PermissionEffect.DENY,
                    },
                }
            ),
        ),
        (
            dict(
                Version="2012-10-17",
                Statement=[
                    dict(
                        Effect='Allow',
                        Principal='arn:aws:iam::123456789012:role/RoleAdmin',
                        Action="s3:DeleteBucket",
                        Resource=["arn:aws:s3:::bucketA", "arn:aws:s3:::bucketB"],
                    ),
                    dict(
                        Effect='Allow',
                        Principal='arn:aws:iam::123456789012:role/RoleAdmin',
                        Action=["s3:Get*", "s3:List*"],
                        Resource='*',
                    ), 
                ]
            ),
            PermissionTable(
                table={
                    Principal("arn:aws:iam::123456789012:role/RoleAdmin", [], []): {
                        "s3:DeleteBucket-arn:aws:s3:::bucketA": PermissionEffect.ALLOW,
                        "s3:DeleteBucket-arn:aws:s3:::bucketB": PermissionEffect.ALLOW,
                        "s3:Get*-*": PermissionEffect.ALLOW,
                        "s3:List*-*": PermissionEffect.ALLOW,
                    }
                }
            ),
        ),
        (
            dict(
                Version="2012-10-17",
                Statement=[
                    dict(
                        Effect='Allow',
                        Principal='*',
                        Action="kms:*",
                        Resource='*',
                        Condition={
                            "StringNotLike": {
                                "aws:PrincipalArn": "arn:aws:iam::123456789012:role/RoleAdmin"
                            }
                        }
                    ),
                ]
            ),
            PermissionTable(
                table={
                    Principal(identifier="*", excludes=[Principal("arn:aws:iam::123456789012:role/RoleAdmin", [], [])], only=[]): {"kms:*-*": PermissionEffect.ALLOW},
                    Principal("arn:aws:iam::123456789012:role/RoleAdmin", [], []): {"kms:*-*": PermissionEffect.IMPLICIT_DENY},
                }
            ),
        ),
        (
            dict(
                Version="2012-10-17",
                Statement=[
                    dict(
                        Effect='Deny',
                        Principal='*',
                        Action="ec2:*",
                        Resource='*',
                        Condition={
                            "StringNotLike": {
                                "aws:PrincipalArn": "arn:aws:iam::123456789012:role/RoleAdmin"
                            }
                        }
                    ),
                ]
            ),
            PermissionTable(
                table={
                    Principal(identifier="*", excludes=[Principal("arn:aws:iam::123456789012:role/RoleAdmin", [], [])], only=[]): {"ec2:*-*": PermissionEffect.DENY},
                    Principal("arn:aws:iam::123456789012:role/RoleAdmin", [], []): {"ec2:*-*": PermissionEffect.IMPLICIT_DENY},
                }
            ),
        ),
        (
            dict(
                Version="2012-10-17",
                Statement=[
                    dict(
                        Effect='Deny',
                        Principal='*',
                        Action="ec2:*",
                        Resource='*',
                        Condition={
                            "StringLike": {
                                "aws:PrincipalArn": "arn:aws:iam::123456789012:role/RoleEngineer"
                            }
                        }
                    ),
                ]
            ),
            PermissionTable(
                table={
                    Principal(identifier="*", excludes=[], only=[Principal("arn:aws:iam::123456789012:role/RoleEngineer", [], [])]): {"ec2:*-*": PermissionEffect.DENY},
                    Principal("arn:aws:iam::123456789012:role/RoleEngineer", [], []): {"ec2:*-*": PermissionEffect.DENY},
                }
            ),
        ),
        (
            dict(
                Version="2012-10-17",
                Statement=[
                    dict(
                        Effect='Deny',
                        Principal='*',
                        Action="kms:ScheduleKeyDeletion",
                        Resource='*',
                    ),
                    dict(
                        Effect='Allow',
                        Principal="arn:aws:iam::123456789012:role/RoleEngineer",
                        Action="kms:ScheduleKeyDeletion",
                        Resource='*',
                    ),
                ]
            ),
            PermissionTable(
                table={
                    Principal(identifier="*", excludes=[], only=[]): {"kms:ScheduleKeyDeletion-*": PermissionEffect.DENY},
                    Principal("arn:aws:iam::123456789012:role/RoleEngineer", [], []): {"kms:ScheduleKeyDeletion-*": PermissionEffect.ALLOW},
                }
            ),
        ),
        (
            dict(
                Version="2012-10-17",
                Statement=[
                    dict(
                        Effect='Deny',
                        Principal='*',
                        Action="kms:ScheduleKeyDeletion",
                        Resource='*',
                        Condition={
                            "StringNotLike": {
                                "aws:PrincipalArn": "arn:aws:iam::123456789012:role/RoleEngineer"
                            }
                        }
                    ),
                    dict(
                        Effect='Allow',
                        Principal='*',
                        Action="kms:ScheduleKeyDeletion",
                        Resource='*',
                        Condition={
                            "StringLike": {
                                "aws:PrincipalArn": "arn:aws:iam::123456789012:role/RoleEngineer"
                            }
                        }
                    ),
                ]
            ),
            PermissionTable(
                table={
                    Principal(identifier="*", excludes=[Principal("arn:aws:iam::123456789012:role/RoleEngineer", [], [])], only=[]): {"kms:ScheduleKeyDeletion-*": PermissionEffect.DENY},
                    Principal(identifier="*", excludes=[], only=[Principal("arn:aws:iam::123456789012:role/RoleEngineer", [], [])]): {"kms:ScheduleKeyDeletion-*": PermissionEffect.ALLOW},
                    Principal("arn:aws:iam::123456789012:role/RoleEngineer", [], []): {"kms:ScheduleKeyDeletion-*": PermissionEffect.ALLOW},
                }
            ),
        ),
        (
            dict(
                Version="2012-10-17",
                Statement=[
                    dict(
                        Effect='Deny',
                        Principal='*',
                        Action=["s3:PutObject*", "s3:ListMultipartUploadParts", "s3:DeleteObject*"],
                        Resource=["arn:aws:s3:::bucketA", "arn:aws:s3:::bucketB"],
                        Condition={
                            "ArnNotLike": {"aws:PrincipalArn": ["arn:aws:iam::123456789012:role/RoleAdmin"]},
                            "Bool": {"aws:SecureTransport": False},
                        }
                    ),
                    dict(
                        Effect="Allow",
                        Principal='*',
                        Action=["s3:PutObject*", "s3:ListMultipartUploadParts", "s3:DeleteObject*"],
                        Resource=["arn:aws:s3:::bucketA"],
                        Condition={
                            "ArnLike": {"aws:PrincipalArn": ["arn:aws:iam::123456789012:role/RoleAdmin"]},
                            "Bool": {"aws:SecureTransport": False},
                        }
                    ),
                    dict(
                        Effect="Allow",
                        Principal='*',
                        Action=["s3:ListMultipartUploadParts"],
                        Resource=["arn:aws:s3:::bucketB"],
                        Condition={
                            "ArnLike": {"aws:PrincipalArn": ["arn:aws:iam::123456789012:role/RoleAdmin"]},
                            "Bool": {"aws:SecureTransport": False},
                        }
                    ),
                ]
            ),
            PermissionTable(
                table={
                    Principal(identifier="*", excludes=[Principal("arn:aws:iam::123456789012:role/RoleAdmin", [], [])], only=[]): {
                        "s3:PutObject*-arn:aws:s3:::bucketA": PermissionEffect.DENY,
                        "s3:ListMultipartUploadParts-arn:aws:s3:::bucketA": PermissionEffect.DENY,
                        "s3:DeleteObject*-arn:aws:s3:::bucketA": PermissionEffect.DENY,
                        "s3:PutObject*-arn:aws:s3:::bucketB": PermissionEffect.DENY,
                        "s3:ListMultipartUploadParts-arn:aws:s3:::bucketB": PermissionEffect.DENY,
                        "s3:DeleteObject*-arn:aws:s3:::bucketB": PermissionEffect.DENY,
                    },
                    Principal(identifier="*", excludes=[], only=[Principal("arn:aws:iam::123456789012:role/RoleAdmin", [], [])]): {
                        "s3:PutObject*-arn:aws:s3:::bucketA": PermissionEffect.ALLOW,
                        "s3:ListMultipartUploadParts-arn:aws:s3:::bucketA": PermissionEffect.ALLOW,
                        "s3:DeleteObject*-arn:aws:s3:::bucketA": PermissionEffect.ALLOW,
                        "s3:ListMultipartUploadParts-arn:aws:s3:::bucketB": PermissionEffect.ALLOW,
                    },
                    Principal("arn:aws:iam::123456789012:role/RoleAdmin", [], []): {
                        "s3:PutObject*-arn:aws:s3:::bucketA": PermissionEffect.ALLOW,
                        "s3:ListMultipartUploadParts-arn:aws:s3:::bucketA": PermissionEffect.ALLOW,
                        "s3:DeleteObject*-arn:aws:s3:::bucketA": PermissionEffect.ALLOW,
                        "s3:PutObject*-arn:aws:s3:::bucketB": PermissionEffect.IMPLICIT_DENY,
                        "s3:ListMultipartUploadParts-arn:aws:s3:::bucketB": PermissionEffect.ALLOW,
                        "s3:DeleteObject*-arn:aws:s3:::bucketB": PermissionEffect.IMPLICIT_DENY
                    },
                }
            ),
        ),
    ]
)
def test_policy_permission_table(policy: Dict[str, Any], permission_table: PermissionTable) -> None:
    p = Policy(raw=policy)
    assert p._permission_table().table == permission_table.table



@pytest.mark.parametrize(
    "policy,action,principals",
    [
        (
            dict(
                Version="2012-10-17",
                Statement=[
                    dict(
                        Effect='Allow',
                        Principal='arn:aws:iam::123456789012:role/RoleAdmin',
                        Action=["ec2:*", "s3:*", "kms:*"],
                        Resource='*',
                    ),
                    dict(
                        Effect='Deny',
                        Principal='*',
                        Action="kms:ScheduleKeyDeletion",
                        Resource='*',
                        Condition={
                            "StringNotEquals": {
                                "aws:PrincipalArn": "arn:aws:iam::123456789012:role/RoleAdmin"
                            }
                        }
                    ),
                ]
            ),
            "ec2:RunInstances",
            {Principal("arn:aws:iam::123456789012:role/RoleAdmin", [], [])},
        ),
        (
            dict(
                Version="2012-10-17",
                Statement=[
                    dict(
                        Effect='Allow',
                        Principal='arn:aws:iam::123456789012:role/RoleAdmin',
                        Action=["ec2:*", "s3:*", "kms:*"],
                        Resource='*',
                    ),
                    dict(
                        Effect='Deny',
                        Principal='*',
                        Action="kms:ScheduleKeyDeletion",
                        Resource='*',
                        Condition={
                            "StringNotEquals": {
                                "aws:PrincipalArn": "arn:aws:iam::123456789012:role/RoleAdmin"
                            }
                        }
                    ),
                ]
            ),
            "kms:ScheduleKeyDeletion",
            {Principal("arn:aws:iam::123456789012:role/RoleAdmin", [], [])},
        ),
        (
            dict(
                Version="2012-10-17",
                Statement=[
                    dict(
                        Effect='Allow',
                        Principal='arn:aws:iam::123456789012:role/RoleAdmin',
                        Action=["ec2:*", "s3:*"],
                        Resource='*',
                    ),
                    dict(
                        Effect='Deny',
                        Principal='*',
                        Action="kms:ScheduleKeyDeletion",
                        Resource='*',
                        Condition={
                            "StringNotEquals": {
                                "aws:PrincipalArn": "arn:aws:iam::123456789012:role/RoleAdmin"
                            }
                        }
                    ),
                ]
            ),
            "lambda:InvokeFunction",
            set(),
        ),
        (
            dict(
                Version="2012-10-17",
                Statement=[
                    dict(
                        Effect='Deny',
                        Principal='*',
                        Action=["s3:Get*", "s3:List*", "s3:PutObject*"],
                        Resource="arn:aws:s3:::bucketA/*",
                        Condition={
                            "ArnNotLike": {
                                "aws:PrincipalArn": [
                                    "arn:aws:iam::123456789012:role/RoleAdmin",
                                    "arn:aws:iam::123456789012:role/RoleEngineer"
                                ],
                            }
                        }
                    ),
                    dict(
                        Effect='Allow',
                        Principal='*',
                        Action="s3:*",
                        Resource=["arn:aws:s3:::bucketA", "arn:aws:s3:::bucketA/*"],
                        Condition={
                            "ArnLike": {
                                "aws:PrincipalArn": [
                                    "arn:aws:iam::123456789012:role/RoleAdmin",
                                    "arn:aws:iam::123456789012:role/RoleEngineer"
                                ],
                            }
                        }
                    ),
                ]
            ),
            "s3:GetObject",
            {
                Principal("arn:aws:iam::123456789012:role/RoleAdmin", [], []),
                Principal("arn:aws:iam::123456789012:role/RoleEngineer", [], [])
            },
        )
    ]
)
def test_policy_allowed_principals(policy: Dict[str, Any], action: str, principals: List[str]) -> None:
    p = Policy(raw=policy)
    assert p.allowed_principals(action=action) == principals

