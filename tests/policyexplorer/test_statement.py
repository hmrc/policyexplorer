from typing import Any, Dict, List, NamedTuple, Tuple
import pytest

from policyexplorer.condition import Condition
from policyexplorer.exception import RequestContextItemNotFoundException
from policyexplorer.statement import Effect, Statement
from policyexplorer.request_context import RequestContext, RequestContextItem

StatementTuple = NamedTuple("StatementTuple", [("effect", str), ("principal", List[str]), ("action", List[str]), ("resource", List[str]), ("condition", Condition)])

@pytest.mark.parametrize(
    "statement,statement_tuple",
    [
        (
            dict(
                Effect='Allow',
                Principal='*',
                Action="*:*",
                Resource='*',
            ),
            StatementTuple(
                effect="Allow",
                principal=["*"],
                action=["*:*"],
                resource=["*"],
                condition=Condition(condition={}),
            )
        ),
        (
            dict(
                Effect='Allow',
                Principal='arn:aws:iam::123456789012:role/RoleAdmin',
                Action="*:*",
                Resource='*',
            ),
            StatementTuple(
                effect="Allow",
                principal=["arn:aws:iam::123456789012:role/RoleAdmin"],
                action=["*:*"],
                resource=["*"],
                condition=Condition(condition={}),
            )
        ),
        (
            dict(
                Effect='Allow',
                Principal='arn:aws:iam::123456789012:role/RoleAdmin',
                Action=["ec2:*", "s3:*"],
                Resource='*',
            ),
            StatementTuple(
                effect="Allow",
                principal=["arn:aws:iam::123456789012:role/RoleAdmin"],
                action=["ec2:*", "s3:*"],
                resource=["*"],
                condition=Condition(condition={}),
            )
        ),
        (
            dict(
                Effect='Allow',
                Principal="*",
                Action="s3:DeleteBucket",
                Resource=["arn:aws:s3:::bucketA", "arn:aws:s3:::bucketB"],
            ),
            StatementTuple(
                effect="Allow",
                principal=["*"],
                action=["s3:DeleteBucket"],
                resource=["arn:aws:s3:::bucketA", "arn:aws:s3:::bucketB"],
                condition=Condition(condition={}),
            )
        ),
        (
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
            StatementTuple(
                effect="Deny",
                principal=["*"],
                action=["kms:ScheduleKeyDeletion"],
                resource=["*"],
                condition=Condition(condition={ 
                    "StringNotEquals": { "aws:PrincipalArn": "arn:aws:iam::123456789012:role/RoleAdmin" }
                })
            )
        ),
        (
            dict(
                Effect='Deny',
                Principal='*',
                Action=["iam:*AccessKey*"],
                Resource="arn:aws:iam::account-id:user/*",
                Condition={
                    "NotIpAddress": {"aws:SourceIp": "203.0.113.0/24"}
                }
            ),
            StatementTuple(
                effect="Deny",
                principal=["*"],
                action=["iam:*AccessKey*"],
                resource=["arn:aws:iam::account-id:user/*"],
                condition=Condition(condition={ "NotIpAddress": {"aws:SourceIp": "203.0.113.0/24"} })
            )
        ),
    ]
)
def test_statement_parsing(statement: Dict[str, Any], statement_tuple: StatementTuple) -> None:
    st = Statement(statement=statement)

    assert st.effect == statement_tuple.effect
    assert st.principal == statement_tuple.principal
    assert st.action == statement_tuple.action
    assert st.resource == statement_tuple.resource
    assert st.condition._condition == statement_tuple.condition._condition


@pytest.mark.parametrize(
    "statement,statement_table",
    [
        (
            dict(
                Effect="Allow",
                Principal=["P1", "P2"],
                Action=["A1", "A2"],
                Resource=["R1", "R2"],
            ),
            {
                "P1": {
                    "A1-R1": "R1",
                    "A1-R2": "R2",
                    "A2-R1": "R1",
                    "A2-R2": "R2",
                },
                "P2": {
                    "A1-R1": "R1",
                    "A1-R2": "R2",
                    "A2-R1": "R1",
                    "A2-R2": "R2",
                },
            }
        ),
        (
            dict(
                Effect='Allow',
                Principal='*',
                Action="*:*",
                Resource='*',
            ),
            {
                "*": {
                    "*:*-*": "*"
                }
            }
        ),
        (
            dict(
                Effect='Allow',
                Principal='arn:aws:iam::123456789012:role/RoleAdmin',
                Action="*:*",
                Resource='*',
            ),
            {
                "arn:aws:iam::123456789012:role/RoleAdmin": {
                    "*:*-*": "*"
                }
            }
        ),
        (
            dict(
                Effect='Allow',
                Principal='arn:aws:iam::123456789012:role/RoleAdmin',
                Action=["ec2:*", "s3:*"],
                Resource='*',
            ),
            {
                "arn:aws:iam::123456789012:role/RoleAdmin": {
                    "ec2:*-*": "*",
                    "s3:*-*": "*",
                }
            }
        ),
        (
            dict(
                Effect='Allow',
                Principal="*",
                Action="s3:DeleteBucket",
                Resource=["arn:aws:s3:::bucketA", "arn:aws:s3:::bucketB"],
            ),
            {
                "*": {
                    "s3:DeleteBucket-arn:aws:s3:::bucketA": "arn:aws:s3:::bucketA",
                    "s3:DeleteBucket-arn:aws:s3:::bucketB": "arn:aws:s3:::bucketB",
                }
            }
        ),
        (
            dict(
                Effect='Deny',
                Principal=["arn:aws:iam::123456789012:user/Bob", "arn:aws:iam::123456789012:user/Jane", ],
                Action=["s3:DeleteBucket", "s3:PutBucketPolicy"],
                Resource=["arn:aws:s3:::bucketA", "arn:aws:s3:::bucketB"]
            ),
            {
                "arn:aws:iam::123456789012:user/Bob": {
                    "s3:DeleteBucket-arn:aws:s3:::bucketA": "arn:aws:s3:::bucketA",
                    "s3:DeleteBucket-arn:aws:s3:::bucketB": "arn:aws:s3:::bucketB",
                    "s3:PutBucketPolicy-arn:aws:s3:::bucketA": "arn:aws:s3:::bucketA",
                    "s3:PutBucketPolicy-arn:aws:s3:::bucketB": "arn:aws:s3:::bucketB",
                },
                "arn:aws:iam::123456789012:user/Jane": {
                    "s3:DeleteBucket-arn:aws:s3:::bucketA": "arn:aws:s3:::bucketA",
                    "s3:DeleteBucket-arn:aws:s3:::bucketB": "arn:aws:s3:::bucketB",
                    "s3:PutBucketPolicy-arn:aws:s3:::bucketA": "arn:aws:s3:::bucketA",
                    "s3:PutBucketPolicy-arn:aws:s3:::bucketB": "arn:aws:s3:::bucketB",
                }
            }
        ),
    ]
)
def test_statement_table(statement: Dict[str, Any], statement_table: Dict[str, Any]) -> None:
    st = Statement(statement=statement)
    assert st.statement_table() == statement_table


@pytest.mark.parametrize(
    "statement,request_context,expected",
    [
        (
            dict(
                Effect="Allow",
                Principal=["P1", "P2"],
                Action=["A1", "A2"],
                Resource=["R1", "R2"],
            ),
            RequestContext(
                items={
                    "aws:PrincipalArn": RequestContextItem(key="aws:PrincipalArn", value="P1"),
                    "Action": RequestContextItem(key="Action", value="A1"),
                    "Resource": RequestContextItem(key="Resource", value="R1"),
                }
            ),
            True
        ),
        (
            dict(
                Effect="Allow",
                Principal=["P1", "P2"],
                Action=["A1", "A2"],
                Resource=["R1", "R2"],
            ),
            RequestContext(
                items={
                    "aws:PrincipalArn": RequestContextItem(key="aws:PrincipalArn", value="P2"),
                    "Action": RequestContextItem(key="Action", value="A1"),
                    "Resource": RequestContextItem(key="Resource", value="R2"),
                }
            ),
            True
        ),
        (
            dict(
                Effect="Allow",
                Principal=["P1", "P2"],
                Action=["A1", "A2"],
                Resource=["R1", "R2"],
            ),
            RequestContext(
                items={
                    "aws:PrincipalArn": RequestContextItem(key="aws:PrincipalArn", value="PX"),
                    "Action": RequestContextItem(key="Action", value="A1"),
                    "Resource": RequestContextItem(key="Resource", value="R1"),
                }
            ),
            False
        ),
        (
            dict(
                Effect="Allow",
                Principal=["P1", "P2"],
                Action=["A1", "A2"],
                Resource=["R1", "R2"],
            ),
            RequestContext(
                items={
                    "aws:PrincipalArn": RequestContextItem(key="aws:PrincipalArn", value="P2"),
                    "Action": RequestContextItem(key="Action", value="A1"),
                    "Resource": RequestContextItem(key="Resource", value="RX"),
                }
            ),
            False
        ),
        (
            dict(
                Effect='Allow',
                Principal='*',
                Action="*:*",
                Resource='*',
            ),
            RequestContext(
                items={
                    "aws:PrincipalArn": RequestContextItem(key="aws:PrincipalArn", value="arn:aws:iam::123456789012:role/RoleAdmin"),
                    "Action": RequestContextItem(key="Action", value="s3:CreateBucket"),
                    "Resource": RequestContextItem(key="Resource", value="arn:aws:s3:::bucketA"),
                }
            ),
            True
        ),
        (
            dict(
                Effect='Allow',
                Principal='arn:aws:iam::123456789012:role/RoleAdmin',
                Action=["ec2:*", "s3:*"],
                Resource="arn:aws:ec2:eu-west-2:123456789012:instance/*",
            ),
            RequestContext(
                items={
                    "aws:PrincipalArn": RequestContextItem(key="aws:PrincipalArn", value="arn:aws:iam::123456789012:role/RoleAdmin"),
                    "Action": RequestContextItem(key="Action", value="ec2:RunInstances"),
                    "Resource": RequestContextItem(key="Resource", value="arn:aws:ec2:eu-west-2:123456789012:instance/i-5203422c"),
                }
            ),
            True
        ),
        (
            dict(
                Effect='Deny',
                Principal='arn:aws:iam::123456789012:role/RoleEngineer',
                Action=["ec2:*", "s3:*"],
                Resource="*",
            ),
            RequestContext(
                items={
                    "aws:PrincipalArn": RequestContextItem(key="aws:PrincipalArn", value="arn:aws:iam::123456789012:role/RoleEngineer"),
                    "Action": RequestContextItem(key="Action", value="s3:DeleteBucket"),
                    "Resource": RequestContextItem(key="Resource", value="arn:aws:s3:::bucketA"),
                }
            ),
            True
        ),
    ]
)
def test_is_matched_by_statement_table(statement: Dict[str, Any], request_context: RequestContext, expected: bool) -> None:
    st = Statement(statement=statement)
    assert st.is_matched_by_statement_table(request_context=request_context) == expected


@pytest.mark.parametrize(
    "statement,request_context,context_key",
    [
        (
            dict(
                Effect='Allow',
                Principal='*',
                Action="*:*",
                Resource='*',
            ),
            RequestContext(
                items={
                    "Action": RequestContextItem(key="Action", value="s3:CreateBucket"),
                    "Resource": RequestContextItem(key="Resource", value="arn:aws:s3:::bucketA"),
                }
            ),
            "aws:PrincipalArn",
        ),
        (
            dict(
                Effect='Allow',
                Principal='*',
                Action="*:*",
                Resource='*',
            ),
            RequestContext(
                items={
                    "aws:PrincipalArn": RequestContextItem(key="aws:PrincipalArn", value="arn:aws:iam::123456789012:role/RoleEngineer"),
                    "Resource": RequestContextItem(key="Resource", value="arn:aws:s3:::bucketA"),
                }
            ),
            "Action",
        ),
        (
            dict(
                Effect='Allow',
                Principal='*',
                Action="*:*",
                Resource='*',
            ),
            RequestContext(
                items={
                    "aws:PrincipalArn": RequestContextItem(key="aws:PrincipalArn", value="arn:aws:iam::123456789012:role/RoleEngineer"),
                    "Action": RequestContextItem(key="Action", value="s3:CreateBucket"),
                }
            ),
            "Resource",
        ),
    ]
)
def test_is_matched_by_statement_table_missing_request_context_item(statement: Dict[str, Any], request_context: RequestContext, context_key: str) -> None:
    st = Statement(statement=statement)
    with pytest.raises(RequestContextItemNotFoundException, match=f"request context item not found - {context_key}"):
        st.is_matched_by_statement_table(request_context=request_context)



# effect    | is_matched_by_statement_table | is_matched_by_condition | Result
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
        # effect | is_matched_by_statement_table | is_matched_by_condition | Result
        # ------ | ----------------------------- | ----------------------- | ------
        # Allow  | True                          | True                    | ALLOW
        (
            dict(
                Effect='Allow',
                Principal='*',
                Action="*:*",
                Resource='*',
            ),
            RequestContext(
                items={
                    "aws:PrincipalArn": RequestContextItem(key="aws:PrincipalArn", value="arn:aws:iam::123456789012:role/RoleEngineer"),
                    "Action": RequestContextItem(key="Action", value="s3:DeleteBucket"),
                    "Resource": RequestContextItem(key="Resource", value="arn:aws:s3:::bucketA"),
                }
            ),
            Effect.ALLOW,
        ),
        (
            dict(
                Effect='Allow',
                Principal='arn:aws:iam::123456789012:role/RoleAdmin',
                Action=["ec2:*", "s3:*"],
                Resource='*',
            ), 
            RequestContext(
                items={
                    "aws:PrincipalArn": RequestContextItem(key="aws:PrincipalArn", value="arn:aws:iam::123456789012:role/RoleAdmin"),
                    "Action": RequestContextItem(key="Action", value="ec2:RunInstances"),
                    "Resource": RequestContextItem(key="Resource", value="arn:aws:ec2:eu-west-2:123456789012:instance/i-5203422c"),
                }
            ),
            Effect.ALLOW,
        ),
        # effect | is_matched_by_statement_table | is_matched_by_condition | Result
        # ------ | ----------------------------- | ----------------------- | ------
        # Allow  | False                         | True                    | Deny
        (
            dict(
                Effect='Allow',
                Principal='arn:aws:iam::123456789012:role/RoleAdmin',
                Action="*:*",
                Resource='*',
            ),
            RequestContext(
                items={
                    "aws:PrincipalArn": RequestContextItem(key="aws:PrincipalArn", value="arn:aws:iam::123456789012:role/RoleEngineer"),
                    "Action": RequestContextItem(key="Action", value="s3:DeleteBucket"),
                    "Resource": RequestContextItem(key="Resource", value="arn:aws:s3:::bucketA"),
                }
            ),
            Effect.DENY,
        ),
        (
            dict(
                Effect='Allow',
                Principal="*",
                Action="s3:DeleteBucket",
                Resource=["arn:aws:s3:::bucketA", "arn:aws:s3:::bucketB"],
            ),
            RequestContext(
                items={
                    "aws:PrincipalArn": RequestContextItem(key="aws:PrincipalArn", value="arn:aws:iam::123456789012:role/RoleEngineer"),
                    "Action": RequestContextItem(key="Action", value="s3:DeleteBucket"),
                    "Resource": RequestContextItem(key="Resource", value="arn:aws:s3:::bucketXXX"),
                }
            ),
            Effect.DENY,
        ),
        # effect | is_matched_by_statement_table | is_matched_by_condition | Result
        # ------ | ----------------------------- | ----------------------- | ------
        # Allow  | True                          | False                   | Deny
        (
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
            RequestContext(
                items={
                    "aws:PrincipalArn": RequestContextItem(key="aws:PrincipalArn", value="arn:aws:iam::123456789012:role/RoleAdmin"),
                    "Action": RequestContextItem(key="Action", value="kms:ScheduleKeyDeletion"),
                    "Resource": RequestContextItem(key="Resource", value="arn:aws:kms:us-west-2:123456789012:key/k1234"),
                }
            ),
            Effect.DENY,
        ),
        # effect | is_matched_by_statement_table | is_matched_by_condition | Result
        # ------ | ----------------------------- | ----------------------- | ------
        # Deny   | False                         | False                   | Deny (implicit)
        (
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
            RequestContext(
                items={
                    "aws:PrincipalArn": RequestContextItem(key="aws:PrincipalArn", value="arn:aws:iam::123456789012:role/RoleAdmin"),
                    "Action": RequestContextItem(key="Action", value="s3:PutObject"),
                    "Resource": RequestContextItem(key="Resource", value="arn:aws:kms:us-west-2:123456789012:key/k1234"),
                }
            ),
            Effect.DENY,
        ),
        # effect | is_matched_by_statement_table | is_matched_by_condition | Result
        # ------ | ----------------------------- | ----------------------- | ------
        # Deny   | False                         | True                    | Deny (implicit)
        (
            dict(
                Effect='Deny',
                Principal='*',
                Action="ec2:*",
                Resource='*',
                Condition={
                    "StringLike": {
                        "aws:PrincipalArn": "arn:aws:iam::123456789012:role/RoleAdmin"
                    }
                }
            ),
            RequestContext(
                items={
                    "aws:PrincipalArn": RequestContextItem(key="aws:PrincipalArn", value="arn:aws:iam::123456789012:role/RoleAdmin"),
                    "Action": RequestContextItem(key="Action", value="s3:PutObject"),
                    "Resource": RequestContextItem(key="Resource", value="arn:aws:kms:us-west-2:123456789012:key/k1234"),
                }
            ),
            Effect.DENY,
        ),
        # effect | is_matched_by_statement_table | is_matched_by_condition | Result
        # ------ | ----------------------------- | ----------------------- | ------
        # Deny   | True                          | False                   | ALLOW
        (
            dict(
                Effect='Deny',
                Principal='*',
                Action="kms:ScheduleKeyDeletion",
                Resource='*',
                Condition={
                    "StringNotLike": {
                        "aws:PrincipalArn": "arn:aws:iam::123456789012:role/RoleAdmin"
                    }
                }
            ),
            RequestContext(
                items={
                    "aws:PrincipalArn": RequestContextItem(key="aws:PrincipalArn", value="arn:aws:iam::123456789012:role/RoleAdmin"),
                    "Action": RequestContextItem(key="Action", value="kms:ScheduleKeyDeletion"),
                    "Resource": RequestContextItem(key="Resource", value="arn:aws:kms:us-west-2:123456789012:key/k1234"),
                }
            ),
            Effect.ALLOW,
        ),
        (
            dict(
                Effect='Deny',
                Principal='*',
                Action=["s3:PutObject*", "s3:ListMultipartUploadParts", "s3:DeleteObject*"],
                Resource=["arn:aws:s3:::bucketA", "arn:aws:s3:::bucketB"],
                Condition={
                    "ArnNotLike": {"aws:PrincipalArn": ["arn:aws:iam::132732819912:role/RoleAdmin"]},
                    "Bool": {"aws:SecureTransport": False},
                }
            ),
            RequestContext(
                items={
                    "aws:PrincipalArn": RequestContextItem(key="aws:PrincipalArn", value="arn:aws:iam::123456789012:role/RoleAdmin"),
                    "Action": RequestContextItem(key="Action", value="s3:PutObjectAcl"),
                    "Resource": RequestContextItem(key="Resource", value="arn:aws:s3:::bucketA"),
                    "aws:SecureTransport": RequestContextItem(key="aws:SecureTransport", value=True),
                }
            ),
            Effect.ALLOW,
        ),
        # effect | is_matched_by_statement_table | is_matched_by_condition | Result
        # ------ | ----------------------------- | ----------------------- | ------
        # Deny   | True                          | True                    | Deny
        (
            dict(
                Effect='Deny',
                Principal='*',
                Action="kms:ScheduleKeyDeletion",
                Resource='*',
                Condition={
                    "StringNotLike": {
                        "aws:PrincipalArn": "arn:aws:iam::123456789012:role/RoleAdmin"
                    }
                }
            ),
            RequestContext(
                items={
                    "aws:PrincipalArn": RequestContextItem(key="aws:PrincipalArn", value="arn:aws:iam::123456789012:role/RoleEngineer"),
                    "Action": RequestContextItem(key="Action", value="kms:ScheduleKeyDeletion"),
                    "Resource": RequestContextItem(key="Resource", value="arn:aws:kms:us-west-2:123456789012:key/k1234"),
                }
            ),
            Effect.DENY,
        ),
    ]
)
def test_statement_evaluate(statement: Dict[str, Any], request_context: RequestContext, expected: str) -> None:
    st = Statement(statement=statement)
    assert st.evaluate(request_context=request_context) == expected
