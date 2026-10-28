"""Shared fixtures. Everything here is offline: no AWS calls, no credentials."""

from __future__ import annotations

import pytest

from scp_preflight.simulate import Result
from scp_preflight.spec import Case, Level, Principal, Spec

ALLOW_S3 = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "s3:CreateBucket", "Resource": "*"}],
}

REGION_LOCK = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "DenyOutsideApprovedRegions",
            "Effect": "Deny",
            "NotAction": ["iam:*"],
            "Resource": "*",
            "Condition": {"StringNotEquals": {"aws:RequestedRegion": "us-east-1"}},
        }
    ],
}


class FakeClient:
    """
    Stands in for the IAM client.

    Records every request so tests can assert on what was sent, which is most of
    what matters in simulate.py: the hierarchy shape, the injected FullAWSAccess,
    and the context entries.
    """

    def __init__(self, responses=None, error=None):
        self.requests: list[dict] = []
        self._responses = list(responses or [])
        self._error = error

    def simulate_custom_policy(self, **kwargs):
        self.requests.append(kwargs)
        if self._error is not None:
            raise self._error
        if self._responses:
            response = self._responses.pop(0)
            if isinstance(response, Exception):
                raise response
            return response
        return {"EvaluationResults": []}


def evaluation(
    action="s3:CreateBucket",
    resource="*",
    decision="allowed",
    matched=None,
    missing=None,
    allowed_by_organizations=None,
):
    entry = {
        "EvalActionName": action,
        "EvalResourceName": resource,
        "EvalDecision": decision,
        "MatchedStatements": matched or [],
        "MissingContextValues": missing or [],
    }
    if allowed_by_organizations is not None:
        entry["OrganizationsDecisionDetail"] = {
            "AllowedByOrganizations": allowed_by_organizations
        }
    return entry


def make_spec(
    hierarchy_policies=None,
    principal_policies=None,
    actions=("s3:CreateBucket",),
    context=None,
    expect="allowed",
    inject=True,
    boundary=None,
):
    levels = [Level(name="root", policies=list(hierarchy_policies or []))]
    principal = Principal(
        name="app",
        policies=list(principal_policies or [ALLOW_S3]),
        permissions_boundary=boundary,
    )
    case = Case(
        name="a check",
        principal="app",
        actions=list(actions),
        resources=["*"],
        context=context or {},
        expect=expect,
    )
    return Spec(
        hierarchy=levels,
        principals={"app": principal},
        cases=[case],
        inject_full_aws_access=inject,
    )


def make_result(
    decision="allowed",
    expect="allowed",
    matched=None,
    missing=None,
    undeclared=None,
    denied_by_organizations=False,
):
    case = Case(
        name="a check",
        principal="app",
        actions=["s3:CreateBucket"],
        resources=["*"],
        context={},
        expect=expect,
    )
    return Result(
        case=case,
        action="s3:CreateBucket",
        resource="*",
        decision=decision,
        matched=matched or [],
        missing_context=missing or [],
        undeclared_context=undeclared or [],
        denied_by_organizations=denied_by_organizations,
    )


@pytest.fixture
def context_entry():
    def build(key, value, ctype="string"):
        return {key: {"type": ctype, "values": [value]}}

    return build
