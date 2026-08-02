"""Run a spec against the IAM policy simulator."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from botocore.exceptions import ParamValidationError

from . import FULL_AWS_ACCESS
from .conditions import keys_in_policies, undeclared
from .spec import Case, Spec


class SimulatorUnavailable(Exception):
    """The installed botocore predates the SCP hierarchy parameter."""


@dataclass
class Result:
    case: Case
    action: str
    resource: str
    decision: str
    matched: list[dict[str, Any]]
    # Reported by the API. Covers identity policies only.
    missing_context: list[str]
    # Worked out locally. Covers the SCP hierarchy, which the API stays quiet about.
    undeclared_context: list[str]
    # True when OrganizationsDecisionDetail says the hierarchy refused the call.
    # The API does not say which policy did it. See SHARP-EDGES.md entry 5.
    denied_by_organizations: bool = False

    @property
    def unsupplied_keys(self) -> list[str]:
        merged = {k.lower(): k for k in self.undeclared_context}
        for key in self.missing_context:
            merged.setdefault(key.lower(), key)
        return sorted(merged.values())

    @property
    def passed(self) -> bool:
        if self.case.expect == "denied":
            return self.decision in ("explicitDeny", "implicitDeny")
        return self.decision == self.case.expect

    @property
    def label(self) -> str:
        return f"{self.case.name} [{self.action} on {self.resource}]"


def build_hierarchy(spec: Spec) -> list[dict[str, list[str]]]:
    """
    Turn the spec's levels into OrderedOrganizationPolicyInputList.

    Every level gets FullAWSAccess prepended unless the spec opts out. Without it
    the simulator returns implicitDeny for everything, because an SCP hierarchy
    needs an explicit allow at each level and real organizations get that from the
    FullAWSAccess policy AWS attaches automatically. See SHARP-EDGES.md entry 2.
    """
    hierarchy = []
    for level in spec.hierarchy:
        policies = list(level.policies)
        if spec.inject_full_aws_access:
            policies.insert(0, FULL_AWS_ACCESS)
        hierarchy.append(
            {"ServiceControlPolicyInputList": [json.dumps(p) for p in policies]}
        )
    return hierarchy


def _context_entries(case: Case) -> list[dict[str, Any]]:
    return [
        {"ContextKeyName": key, "ContextKeyType": v["type"], "ContextKeyValues": v["values"]}
        for key, v in case.context.items()
    ]


def run(spec: Spec, client) -> list[Result]:
    """
    Simulate every case.

    One API call per case, not per action or resource: SimulateCustomPolicy
    evaluates the full action x resource matrix in a single request and returns a
    result per combination.
    """
    hierarchy = build_hierarchy(spec)
    results: list[Result] = []

    hierarchy_policies = [policy for level in spec.hierarchy for policy in level.policies]

    for case in spec.cases:
        principal = spec.principals[case.principal]
        # Only the SCP hierarchy, and only statements that could apply to the
        # actions under test. Identity policies are deliberately excluded: the API
        # reports their missing keys correctly in MissingContextValues, and a real
        # managed policy carries dozens of keys that are irrelevant here.
        required = keys_in_policies(hierarchy_policies, case.actions)
        undeclared_keys = undeclared(required, case.context.keys())
        request: dict[str, Any] = {
            "PolicyInputList": [json.dumps(p) for p in principal.policies],
            "ActionNames": case.actions,
            "ResourceArns": case.resources,
            "OrderedOrganizationPolicyInputList": hierarchy,
        }
        if principal.permissions_boundary:
            request["PermissionsBoundaryPolicyInputList"] = [
                json.dumps(principal.permissions_boundary)
            ]
        entries = _context_entries(case)
        if entries:
            request["ContextEntries"] = entries

        try:
            response = client.simulate_custom_policy(**request)
        except ParamValidationError as exc:
            if "OrderedOrganizationPolicyInputList" in str(exc):
                raise SimulatorUnavailable(
                    "This botocore does not know OrderedOrganizationPolicyInputList. "
                    "It was added in botocore 1.43.60 (2026-07-31). "
                    "Upgrade with: pip install -U 'botocore>=1.43.60' 'boto3>=1.43.60'"
                ) from exc
            raise

        for entry in response["EvaluationResults"]:
            results.append(
                Result(
                    case=case,
                    action=entry["EvalActionName"],
                    resource=entry.get("EvalResourceName", "*"),
                    decision=entry["EvalDecision"],
                    matched=entry.get("MatchedStatements", []),
                    missing_context=entry.get("MissingContextValues", []),
                    undeclared_context=undeclared_keys,
                    denied_by_organizations=not entry.get(
                        "OrganizationsDecisionDetail", {}
                    ).get("AllowedByOrganizations", True),
                )
            )

    return results
