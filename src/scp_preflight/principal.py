"""
Read a live IAM role's policies so they can be simulated against a proposed
SCP hierarchy.

This exists because the API will not do it in one call. `SimulatePrincipalPolicy`
reads a real principal but always uses your live SCP hierarchy, and
`SimulateCustomPolicy` accepts a proposed hierarchy but only takes identity
policies as strings. Testing a real role against a proposed guardrail therefore
means exporting the role first. See SHARP-EDGES.md entry 6.

The export is a snapshot. If someone edits the role after you run this, your test
was about the role as it used to be. That is a real limitation of the workaround
and not something the tool can fix.
"""

from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from .spec import Spec


class PrincipalError(Exception):
    """Raised when a role cannot be read. The message is shown to the user as-is."""


def role_name_from(reference: str) -> str:
    """
    Accept a role name or a role ARN.

    Roles can carry a path, as in arn:aws:iam::123456789012:role/team/app-deploy,
    and GetRole wants only the trailing name.
    """
    if not reference.startswith("arn:"):
        return reference.split("/")[-1]
    try:
        resource = reference.split(":", 5)[5]
    except IndexError:
        raise PrincipalError(f"not a usable role ARN: {reference}") from None
    if not resource.startswith("role/"):
        raise PrincipalError(f"not a role ARN: {reference}")
    return resource.split("/")[-1]


def _managed_policy_documents(client, role: str) -> list[dict[str, Any]]:
    documents = []
    paginator = client.get_paginator("list_attached_role_policies")
    for page in paginator.paginate(RoleName=role):
        for attached in page["AttachedPolicies"]:
            arn = attached["PolicyArn"]
            policy = client.get_policy(PolicyArn=arn)["Policy"]
            version = client.get_policy_version(
                PolicyArn=arn, VersionId=policy["DefaultVersionId"]
            )["PolicyVersion"]
            # botocore URL-decodes the document and hands back a dict.
            documents.append(version["Document"])
    return documents


def _inline_policy_documents(client, role: str) -> list[dict[str, Any]]:
    documents = []
    paginator = client.get_paginator("list_role_policies")
    for page in paginator.paginate(RoleName=role):
        for name in page["PolicyNames"]:
            documents.append(
                client.get_role_policy(RoleName=role, PolicyName=name)["PolicyDocument"]
            )
    return documents


def fetch_role(client, reference: str) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    """Return (identity policy documents, permissions boundary document or None)."""
    role = role_name_from(reference)

    try:
        described = client.get_role(RoleName=role)["Role"]
        policies = _managed_policy_documents(client, role)
        policies += _inline_policy_documents(client, role)

        boundary = None
        boundary_arn = (described.get("PermissionsBoundary") or {}).get(
            "PermissionsBoundaryArn"
        )
        if boundary_arn:
            managed = client.get_policy(PolicyArn=boundary_arn)["Policy"]
            boundary = client.get_policy_version(
                PolicyArn=boundary_arn, VersionId=managed["DefaultVersionId"]
            )["PolicyVersion"]["Document"]

    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code == "NoSuchEntity":
            raise PrincipalError(f"role not found: {role}") from exc
        if code in ("AccessDenied", "AccessDeniedException"):
            raise PrincipalError(
                f"not allowed to read role {role}. Reading a live role needs "
                "iam:GetRole, iam:ListAttachedRolePolicies, iam:ListRolePolicies, "
                "iam:GetRolePolicy, iam:GetPolicy and iam:GetPolicyVersion. "
                "If you would rather not grant those, declare the principal's "
                "policies in the spec instead of using 'role:'."
            ) from exc
        raise

    if not policies:
        raise PrincipalError(
            f"role {role} has no attached or inline policies, so there is nothing "
            "to simulate. Check the role name."
        )

    return policies, boundary


def resolve(spec: Spec, client) -> None:
    """Fill in policies for any principal declared with 'role:'. Modifies the spec."""
    for principal in spec.principals.values():
        if not principal.role:
            continue
        policies, boundary = fetch_role(client, principal.role)
        # Anything declared inline in the spec is added on top, which is how you
        # model a policy you are proposing to attach.
        principal.policies = policies + principal.policies
        if boundary and not principal.permissions_boundary:
            principal.permissions_boundary = boundary
