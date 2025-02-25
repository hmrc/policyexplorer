import pytest

from policyexplorer.common import matches_pattern


@pytest.mark.parametrize(
    "pattern,input,expected",
    [
        ("*", "P1", True),
        ("P*", "P12", True),
        ("P*X", "P12", False),
        ("P*X", "P12X", True),
        ("P*X", "P12XA", False),
        ("P*X*", "P12X", True),
        ("P*X*", "P12XA", True),
        ("*", "arn:aws:iam::123456789012:role/RoleAdmin", True),
        ("arn:aws:iam::123456789012:role/*", "arn:aws:iam::123456789012:role/RoleAdmin", True),
        ("arn:aws:iam::123456789012:role/*Admin", "arn:aws:iam::123456789012:role/RoleAdmin", True),
        ("arn:aws:s3:::demo-bucket/*/test/*", "arn:aws:s3:::demo-bucket/test/file.png", False),
        ("arn:aws:s3:::demo-bucket/*/test/*", "arn:aws:s3:::demo-bucket/project/test/file.png", True),
        ("*:*", "s3:CreateBucket", True),
        ("s3:*", "s3:CreateBucket", True),
    ]
)
def test_matches_pattern(pattern: str, input: str, expected: bool) -> None:
    assert matches_pattern(pattern=pattern, string=input) == expected