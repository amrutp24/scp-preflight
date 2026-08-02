from scp_preflight.conditions import keys_in_policy, undeclared


def test_finds_plain_condition_keys():
    policy = {
        "Statement": [
            {
                "Effect": "Deny",
                "Action": "*",
                "Resource": "*",
                "Condition": {"StringNotEquals": {"aws:RequestedRegion": "us-east-1"}},
            }
        ]
    }
    assert keys_in_policy(policy) == {"aws:RequestedRegion"}


def test_strips_set_qualifiers():
    policy = {
        "Statement": [
            {
                "Condition": {
                    "ForAllValues:StringEquals": {"aws:TagKeys": ["team"]},
                    "ForAnyValue:StringLike": {"aws:PrincipalTag/role": "*admin*"},
                }
            }
        ]
    }
    assert keys_in_policy(policy) == {"aws:TagKeys", "aws:PrincipalTag/role"}


def test_ignores_if_exists_and_null():
    # Both treat an absent key as meaningful, so leaving it out is not an omission.
    policy = {
        "Statement": [
            {"Condition": {"StringEqualsIfExists": {"aws:PrincipalTag/team": "platform"}}},
            {"Condition": {"Null": {"aws:RequestTag/team": "true"}}},
        ]
    }
    assert keys_in_policy(policy) == set()


def test_handles_single_statement_object():
    policy = {"Statement": {"Condition": {"Bool": {"aws:SecureTransport": "false"}}}}
    assert keys_in_policy(policy) == {"aws:SecureTransport"}


def test_tolerates_policies_without_conditions():
    assert keys_in_policy({"Statement": [{"Effect": "Allow", "Action": "*"}]}) == set()
    assert keys_in_policy({}) == set()


def test_undeclared_is_case_insensitive_but_keeps_policy_casing():
    assert undeclared(["aws:RequestedRegion"], ["aws:requestedregion"]) == []
    assert undeclared(["aws:RequestedRegion"], []) == ["aws:RequestedRegion"]
