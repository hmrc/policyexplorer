![policyexplorer-pr-builder-status-badge](https://codebuild.eu-west-2.amazonaws.com/badges?uuid=eyJlbmNyeXB0ZWREYXRhIjoiNDA0YXRIdFZTMmtnUjc1YUNibFMzOGhDRFNKSWgxNmZubzVhK015SGpTeWVRVW54QXR0N3RpaTN3eXFUc2gvcVBMMEVzTVllWUsvTkVYcmN5andlWnZnPSIsIml2UGFyYW1ldGVyU3BlYyI6IldSL3FKMDBBQWU1cTlsVGgiLCJtYXRlcmlhbFNldFNlcmlhbCI6MX0%3D\&branch=main)

# policyexplorer

This is an open source tool for parsing and analysing an AWS IAM policy document to gain further insights
on permissions that a principal is allowed.

## Installation

`policyexplorer` can be installed using `poetry` or `pip`

```bash
poetry add git+https://github.com/hmrc/policyexplorer.git
```

or

```bash
pip install git+https://github.com/hmrc/policyexplorer.git
```

## Usage examples

> Note: The examples below assumes an IAM policy document is in a `policy.json`

* Find all principals allowed a specific action (e.g. `s3:PutBucketAcl`) on a
  specific resource (e.g. `arn:aws:s3:::bucketA`)

```python
import json
from policyexplorer.policy import Policy

with open("./policy.json") as f:
    policy = json.load(f)

Policy(raw=policy).allowed_principals_by_resource(action="s3:PutBucketAcl", resource="arn:aws:s3:::bucketA")
```

* Find all principals allowed a specific action (e.g. `s3:PutBucketAcl`) on any resource

```python
import json
from policyexplorer.policy import Policy

with open("./policy.json") as f:
    policy = json.load(f)

Policy(raw=policy).allowed_principals(action="kms:ScheduleKeyDeletion")
```

* Find all allowed permissions of a given principal

```python
import json
from policyexplorer.policy import Policy

with open("./policy.json") as f:
    policy = json.load(f)

Policy(raw=policy).principal_allow_permissions(principal="arn:aws:iam::123456789012:role/RoleAdmin")
```

## Test

```bash
make test
```

## IAM policy elements yet to be supported

This tool does not support the following policy elements yet:

* NotPrincipal
* NotResource

## License

This code is open source software licensed under the [Apache 2.0 License](http://www.apache.org/licenses/LICENSE-2.0.html).
