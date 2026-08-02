import json

import pytest
from botocore.exceptions import ParamValidationError

from scp_preflight import FULL_AWS_ACCESS
from scp_preflight.simulate import SimulatorUnavailable, build_hierarchy, run
from scp_preflight.spec import Level

from .conftest import ALLOW_S3, REGION_LOCK, FakeClient, evaluation, make_spec


# --- hierarchy construction -------------------------------------------------


def test_full_aws_access_is_prepended_to_every_level():
    spec = make_spec(hierarchy_policies=[REGION_LOCK])
    spec.hierarchy.append(Level(name="account", policies=[]))

    built = build_hierarchy(spec)

    assert len(built) == 2
    for level in built:
        first = json.loads(level["ServiceControlPolicyInputList"][0])
        assert first == FULL_AWS_ACCESS


def test_injection_preserves_the_original_order():
    spec = make_spec(hierarchy_policies=[REGION_LOCK])
    built = build_hierarchy(spec)
    decoded = [json.loads(p) for p in built[0]["ServiceControlPolicyInputList"]]
    assert decoded == [FULL_AWS_ACCESS, REGION_LOCK]


def test_injection_can_be_disabled():
    spec = make_spec(hierarchy_policies=[REGION_LOCK], inject=False)
    built = build_hierarchy(spec)
    decoded = [json.loads(p) for p in built[0]["ServiceControlPolicyInputList"]]
    assert decoded == [REGION_LOCK]


def test_build_hierarchy_does_not_mutate_the_spec():
    spec = make_spec(hierarchy_policies=[REGION_LOCK])
    build_hierarchy(spec)
    build_hierarchy(spec)
    assert spec.hierarchy[0].policies == [REGION_LOCK]


# --- request shape ----------------------------------------------------------


def test_request_carries_policies_actions_and_resources():
    client = FakeClient([{"EvaluationResults": [evaluation()]}])
    run(make_spec(), client)

    sent = client.requests[0]
    assert [json.loads(p) for p in sent["PolicyInputList"]] == [ALLOW_S3]
    assert sent["ActionNames"] == ["s3:CreateBucket"]
    assert sent["ResourceArns"] == ["*"]


def test_context_entries_are_translated_to_the_api_shape(context_entry):
    client = FakeClient([{"EvaluationResults": [evaluation()]}])
    spec = make_spec(context=context_entry("aws:RequestedRegion", "eu-west-1"))
    run(spec, client)

    assert client.requests[0]["ContextEntries"] == [
        {
            "ContextKeyName": "aws:RequestedRegion",
            "ContextKeyType": "string",
            "ContextKeyValues": ["eu-west-1"],
        }
    ]


def test_context_entries_are_omitted_when_empty():
    client = FakeClient([{"EvaluationResults": [evaluation()]}])
    run(make_spec(), client)
    assert "ContextEntries" not in client.requests[0]


def test_permissions_boundary_is_sent_when_present():
    boundary = {"Version": "2012-10-17", "Statement": []}
    client = FakeClient([{"EvaluationResults": [evaluation()]}])
    run(make_spec(boundary=boundary), client)

    sent = client.requests[0]["PermissionsBoundaryPolicyInputList"]
    assert [json.loads(p) for p in sent] == [boundary]


def test_one_call_per_case_not_per_action():
    client = FakeClient(
        [{"EvaluationResults": [evaluation(action="s3:CreateBucket"),
                                evaluation(action="s3:PutObject")]}]
    )
    results = run(make_spec(actions=("s3:CreateBucket", "s3:PutObject")), client)

    assert len(client.requests) == 1
    assert len(results) == 2


# --- result parsing ---------------------------------------------------------


def test_decision_and_matched_statements_are_carried_through():
    matched = [{"SourcePolicyId": "PolicyInputList.1", "SourcePolicyType": "IAM Policy"}]
    client = FakeClient(
        [{"EvaluationResults": [evaluation(decision="allowed", matched=matched)]}]
    )
    result = run(make_spec(), client)[0]

    assert result.decision == "allowed"
    assert result.matched == matched
    assert result.passed


def test_organizations_deny_is_detected():
    client = FakeClient(
        [{"EvaluationResults": [evaluation(decision="explicitDeny",
                                           allowed_by_organizations=False)]}]
    )
    result = run(make_spec(expect="explicitDeny"), client)[0]

    assert result.denied_by_organizations is True
    assert result.passed


def test_absent_organizations_detail_is_not_treated_as_a_deny():
    client = FakeClient([{"EvaluationResults": [evaluation(decision="allowed")]}])
    assert run(make_spec(), client)[0].denied_by_organizations is False


@pytest.mark.parametrize(
    "decision,expect,passes",
    [
        ("allowed", "allowed", True),
        ("explicitDeny", "allowed", False),
        ("explicitDeny", "denied", True),
        ("implicitDeny", "denied", True),
        ("allowed", "denied", False),
        ("implicitDeny", "explicitDeny", False),
    ],
)
def test_expectation_matching(decision, expect, passes):
    client = FakeClient([{"EvaluationResults": [evaluation(decision=decision)]}])
    assert run(make_spec(expect=expect), client)[0].passed is passes


# --- unsupplied condition keys ----------------------------------------------


def test_scp_condition_keys_are_reported_when_not_supplied():
    client = FakeClient([{"EvaluationResults": [evaluation(decision="explicitDeny")]}])
    result = run(make_spec(hierarchy_policies=[REGION_LOCK], expect="explicitDeny"), client)[0]

    assert result.undeclared_context == ["aws:RequestedRegion"]
    assert result.unsupplied_keys == ["aws:RequestedRegion"]


def test_supplied_keys_are_not_reported(context_entry):
    client = FakeClient([{"EvaluationResults": [evaluation()]}])
    spec = make_spec(
        hierarchy_policies=[REGION_LOCK],
        context=context_entry("aws:RequestedRegion", "us-east-1"),
    )
    assert run(spec, client)[0].undeclared_context == []


def test_identity_policy_keys_are_left_to_the_api():
    """
    The API reports MissingContextValues correctly for identity policies, so local
    extraction deliberately ignores them. Reporting both floods real specs with
    keys that have nothing to do with the check.
    """
    conditional_identity = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:CreateBucket",
                "Resource": "*",
                "Condition": {"StringEquals": {"aws:PrincipalTag/team": "platform"}},
            }
        ],
    }
    client = FakeClient([{"EvaluationResults": [evaluation()]}])
    result = run(make_spec(principal_policies=[conditional_identity]), client)[0]

    assert result.undeclared_context == []


def test_keys_from_statements_that_cannot_apply_are_ignored():
    # REGION_LOCK carves out iam:*, so an iam action reaches no conditioned statement.
    client = FakeClient([{"EvaluationResults": [evaluation(action="iam:CreateRole")]}])
    spec = make_spec(hierarchy_policies=[REGION_LOCK], actions=("iam:CreateRole",))
    assert run(spec, client)[0].undeclared_context == []


def test_api_reported_and_locally_found_keys_are_merged_without_duplicates():
    client = FakeClient(
        [{"EvaluationResults": [evaluation(decision="explicitDeny",
                                           missing=["aws:requestedregion"])]}]
    )
    result = run(make_spec(hierarchy_policies=[REGION_LOCK], expect="explicitDeny"), client)[0]

    # Same key, different casing, from two sources. IAM keys are case-insensitive.
    assert result.unsupplied_keys == ["aws:RequestedRegion"]


# --- stale SDK --------------------------------------------------------------


def test_stale_botocore_gets_an_actionable_error():
    error = ParamValidationError(
        report='Unknown parameter in input: "OrderedOrganizationPolicyInputList", '
        "must be one of: PolicyInputList, ActionNames"
    )
    with pytest.raises(SimulatorUnavailable, match="1.43.60"):
        run(make_spec(), FakeClient(error=error))


def test_other_validation_errors_are_not_swallowed():
    error = ParamValidationError(report='Unknown parameter in input: "Nonsense"')
    with pytest.raises(ParamValidationError):
        run(make_spec(), FakeClient(error=error))
