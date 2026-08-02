"""
Condition keys are only reported when they come from a statement that could apply
to the action under test. Without this, a real managed policy floods every result
with keys that have nothing to do with the check.
"""

from scp_preflight.conditions import keys_in_policies, keys_in_policy, statement_covers

REGION_LOCK = {
    "Statement": [
        {
            "Effect": "Deny",
            "NotAction": ["iam:*", "sts:*"],
            "Resource": "*",
            "Condition": {"StringNotEquals": {"aws:RequestedRegion": "us-east-1"}},
        },
        {
            "Effect": "Deny",
            "Action": ["ec2:RunInstances"],
            "Resource": "*",
            "Condition": {"StringEquals": {"aws:RequestTag/env": "prod"}},
        },
    ]
}


def test_covers_matches_wildcard_action():
    assert statement_covers({"Action": ["s3:*"]}, ["s3:GetObject"])
    assert not statement_covers({"Action": ["s3:*"]}, ["lambda:Invoke"])


def test_covers_handles_not_action():
    statement = {"NotAction": ["iam:*"]}
    assert statement_covers(statement, ["s3:GetObject"])
    assert not statement_covers(statement, ["iam:CreateRole"])


def test_covers_when_no_action_element():
    assert statement_covers({"Resource": "*"}, ["anything:AtAll"])


def test_matching_is_case_insensitive():
    assert statement_covers({"Action": ["S3:GetObject"]}, ["s3:getobject"])


def test_only_relevant_statement_contributes_keys():
    # lambda:CreateFunction hits the region statement, not the ec2 tag statement.
    assert keys_in_policy(REGION_LOCK, ["lambda:CreateFunction"]) == {"aws:RequestedRegion"}

    # ec2:RunInstances hits both.
    assert keys_in_policy(REGION_LOCK, ["ec2:RunInstances"]) == {
        "aws:RequestedRegion",
        "aws:RequestTag/env",
    }

    # iam:CreateRole is carved out of the region statement and is not ec2.
    assert keys_in_policy(REGION_LOCK, ["iam:CreateRole"]) == set()


def test_without_actions_every_statement_contributes():
    assert keys_in_policies([REGION_LOCK]) == {"aws:RequestedRegion", "aws:RequestTag/env"}
