# For a start add support for string and arn operators

string_condition_operators = dict(
    StringEquals="Exact matching, case sensitive",
    StringNotEquals="Negated matching",
    StringEqualsIgnoreCase="Exact matching, ignoring case",
    StringNotEqualsIgnoreCase="Negated matching, ignoring case",
    StringLike="Case-sensitive matching. The values can include multi-character match wildcards (*) and single-character match wildcards (?) anywhere in the string. You must specify wildcards to achieve partial string matches.",
    StringNotLike="Negated case-sensitive matching. The values can include multi-character match wildcards (*) or single-character match wildcards (?) anywhere in the string.",
)

# If a key contains multiple values, StringLike can be qualified with set operators—ForAllValues:StringLike and ForAnyValue:StringLike. For more information, see Multivalued context keys.
#
# ArnLike vs StringLike - ArnLike uses the ARN structure for matching while StringLike ignores the ARN structure (https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html#Conditions_String)

arn_condition_operator = dict(
    ArnEquals="Case-sensitive matching of the ARN. Each of the six colon-delimited components of the ARN is checked separately and each can include multi-character match wildcards (*) or single-character match wildcards (?). The ArnEquals and ArnLike condition operators behave identically.",
    ArnLike="Case-sensitive matching of the ARN. Each of the six colon-delimited components of the ARN is checked separately and each can include multi-character match wildcards (*) or single-character match wildcards (?). The ArnEquals and ArnLike condition operators behave identically.",
    ArnNotEquals="Negated matching for ARN. The ArnNotEquals and ArnNotLike condition operators behave identically.",
    ArnNotLike="Negated matching for ARN. The ArnNotEquals and ArnNotLike condition operators behave identically.",
)


numeric_condition_operators = dict(
    NumericEquals="Matching",
    NumericNotEquals="Negated matching",
    NumericLessThan='"Less than" matching',
    NumericLessThanEquals='"Less than or equals" matching',
    NumericGreaterThan='"Greater than" matching',
    NumericGreaterThanEquals='"Greater than or equals" matching',
)


date_condition_operators = dict(
    DateEquals="Matching a specific date",
    DateNotEquals="Negated matching",
    DateLessThan="Matching before a specific date and time",
    DateLessThanEquals="Matching at or before a specific date and time",
    DateGreaterThan="Matching after a specific a date and time",
    DateGreaterThanEquals="Matching at or after a specific date and time",
)

boolean_condition_operator = dict(Bool="Boolean matching")
# works with the following context keys:
#   * aws:SecureTransport
#   * aws:PrincipalIsAWSService
#   * aws:MultiFactorAuthPresent

binary_condition_operator = dict(
    BinaryEquals="BinaryEquals matching. It compares the value of the specified key byte for byte against a base-64 encoded representation of the binary value in the policy"
)

ipaddress_condition_operator = dict(
    IpAddress="The specified IP address or range",
    NotIpAddress="All IP addresses except the specified IP address or range",
)
# works with the following context keys:
#   * aws:SourceIp

# ToDo: Consider IfExists condition operators (https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html#Conditions_IfExists)
# ToDo: Consider policy variables (https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_variables.html)
