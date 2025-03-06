import json
import pathlib

import pytest

from policyexplorer.policy import Policy


@pytest.mark.parametrize(
    "action,principal",
    [
        ("kms:ScheduleKeyDeletion", "arn:aws:iam::111122223333:role/RoleTerraformProvisioner"),
        ("kms:GetKeyRotationStatus", "arn:aws:iam::111122223333:role/RoleAppAdmin"),
        ("kms:DescribeKey", "arn:aws:iam::111122223333:role/RoleAppEngineer"),
        ("kms:GenerateDataKeyPair", "arn:aws:iam::111122223333:role/app-lambda-role"),
    ],
)
def test_kms_cmk_policy(action: str, principal: str) -> None:
    json_file = pathlib.Path(__file__).parent.joinpath("resources/kms-cmk-resource-policy.json")
    with open(json_file) as f:
        raw = json.load(f)

    policy = Policy(raw=raw)
    assert principal in [p.identifier for p in policy.allowed_principals(action=action)]
