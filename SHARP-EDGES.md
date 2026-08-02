# Sharp edges

Every place AWS behaved in a way that cost time while building this, recorded
exactly as it happened. Errors are verbatim. Nothing here is paraphrased.

Ordinary mistakes of my own are not here. Everything below is service or SDK
behaviour you can hit yourself.

Python 3.12, `us-east-1`, 1 and 2 August 2026. Versions are given per entry where
they matter.

---

## 1. The SDK parameter is one day old and nothing tells you that

**What happened.** The AWS documentation for `SimulateCustomPolicy` describes
`OrderedOrganizationPolicyInputList`. The installed CLI and SDK did not have it.

`aws --version` reported `aws-cli/2.24.24 Python/3.12.9 Windows/11 exe/AMD64`, and
`aws iam simulate-custom-policy --generate-cli-skeleton` returned a skeleton with
no such field:

```json
{
    "PolicyInputList": [""],
    "PermissionsBoundaryPolicyInputList": [""],
    "ActionNames": [""],
    "ResourceArns": [""],
    "ResourcePolicy": "",
    "ResourceOwner": "",
    "CallerArn": "",
    "ContextEntries": [{"ContextKeyName": "", "ContextKeyValues": [""], "ContextKeyType": "string"}],
    "ResourceHandlingOption": "",
    "MaxItems": 0,
    "Marker": ""
}
```

Calling it anyway with botocore 1.42.77:

```
botocore.exceptions.ParamValidationError
Parameter validation failed:
Unknown parameter in input: "OrderedOrganizationPolicyInputList", must be one of: PolicyInputList, PermissionsBoundaryPolicyInputList, ActionNames, ResourceArns, ResourcePolicy, ResourceOwner, CallerArn, ContextEntries, ResourceHandlingOption, MaxItems, Marker
```

**Cause.** The parameter shipped in botocore 1.43.60, released 2026-07-31, one day
after the feature was announced on 2026-07-30. The changelog entry reads
`api-change:``iam``: Improved IAM Policy Simulator accuracy. Simulator now
evaluates SCP conditions and resource scoping`.

**Fix.**

```bash
pip install -U 'botocore>=1.43.60' 'boto3>=1.43.60'
```

**Do the official docs cover it?** No. The API reference documents the parameter
with no minimum SDK version, and the launch announcement links to the API
reference without mentioning that SDK support landed separately. The failure mode
is a client-side validation error that never reaches AWS, so nothing in CloudTrail
or the console hints at the cause.

**Triage:** docs gap.

---

## 2. Omit FullAWSAccess and every answer is implicitDeny

**What happened.** A region lock that should have allowed `s3:CreateBucket` in the
approved region denied it instead.

```
RequestedRegion=us-east-1    -> implicitDeny
RequestedRegion=eu-west-1    -> explicitDeny
```

The identity policy allowed the action, and the SCP only denied outside
`us-east-1`, so `us-east-1` should have been `allowed`.

**Cause.** SCP evaluation needs an explicit allow at every level of the hierarchy.
Real organizations get that from `FullAWSAccess`, which AWS attaches to the root,
every OU and every account automatically. `OrderedOrganizationPolicyInputList`
contains only the policies you pass, so a hierarchy built from your own deny
policies has no allow anywhere and evaluates to `implicitDeny` throughout.

**Fix.** Include `FullAWSAccess` in the policy list at every level:

```
### WITHOUT FullAWSAccess at account level
   us-east-1    -> implicitDeny
   eu-west-1    -> explicitDeny

### WITH FullAWSAccess at account level
   us-east-1    -> allowed
   eu-west-1    -> explicitDeny
```

`scp-preflight` injects it automatically. Turn that off with
`inject_full_aws_access: false`.

**Do the official docs cover it?** No. The `OrderedOrganizationPolicyInputList`
description explains the ordering requirement, that the first element is the root
and the last is the account, and the seven element cap. It says nothing about
`FullAWSAccess`. The failure is silent and looks like your guardrail is far more
restrictive than it is, which is the direction that makes people abandon a correct
policy or ship a broken one.

**Triage:** docs gap.

---

## 3. The seven level cap is a server-side error, not a client-side one

**What happened.** Passing eight levels:

```
An error occurred (ValidationError) when calling the SimulateCustomPolicy operation: 1 validation error detected: Value at 'orderedOrganizationPolicyInputList' failed to satisfy constraint: Member must have length less than or equal to 7
```

**Cause.** The documented cap of seven elements is enforced by the service, not by
the SDK, so you spend a round trip to find out.

**Fix.** Keep the hierarchy to seven levels: root, up to five nested OUs, and the
account. `scp-preflight` checks this while loading the spec and fails with a
message naming the file.

**Do the official docs cover it?** Yes. `Array Members: Maximum number of 7 items`
is in the API reference. The error is clear and the docs are correct.

**Triage:** no upstream action.

---

## 4. Condition keys in SCPs are evaluated against nothing, silently

This is the significant one.

**What happened.** The same condition key, in the same simulation, is reported when
it appears in an identity policy and not reported when it appears in an SCP.

```
A) condition key in IDENTITY policy, not supplied
   decision: implicitDeny | MissingContextValues: ['aws:PrincipalTag/team']
B) same condition key in SCP, not supplied
   decision: explicitDeny | MissingContextValues: []
C) same as B, but key supplied correctly
   decision: allowed | MissingContextValues: []
```

Case B returns a confident `explicitDeny` with an empty `MissingContextValues`.
Supplying the key flips the result to `allowed`. Nothing in the response
distinguishes B from a correctly evaluated deny.

**Cause.** `MissingContextValues` is populated for condition keys in
`PolicyInputList` and not for condition keys in
`OrderedOrganizationPolicyInputList`. The SCP condition still evaluates, against
absent context, which for `StringNotEquals` means the deny fires.

**Why it matters.** Evaluating SCP conditions correctly is the entire point of the
July 2026 launch. A platform engineer testing a tag guardrail sees `explicitDeny`,
concludes the guardrail works, and ships it. In production the principal carries
the tag and the guardrail does not deny. The simulator was right about the
mechanics and wrong about the answer, and it gave no signal.

There is no API-side way to catch this either. `GetContextKeysForCustomPolicy`
accepts only `PolicyInputList`:

```
GetContextKeysForCustomPolicy -> ['PolicyInputList']
GetContextKeysForPrincipalPolicy -> ['PolicyInputList', 'PolicySourceArn']
```

so you cannot ask AWS which condition keys your proposed hierarchy needs.

**Fix.** None available through the API. `scp-preflight` parses the SCP documents
itself, collects every condition key except `*IfExists` and `Null` operators, where
absence is the thing being asserted, and fails any check whose context is missing
one:

```
FAIL  forgot to supply the principal tag [iam:CreateRole on arn:aws:iam::123456789012:role/anything]
        expected: allowed
        actual:   explicitDeny
        decided by: the SCP hierarchy (the API does not say which policy)
        unsupplied condition keys: aws:PrincipalTag/team
        a policy conditions on these but the simulation did not supply them, so this decision is not the one you get in production
```

**Do the official docs cover it?** No. Both API reference pages carry the same
note, that the simulator "evaluates statements in identity-based policies, service
control policies (SCPs) including their condition keys and resource scoping", with
no mention that missing context reporting covers only the first of those.

**Triage:** service bug, or at minimum a documented limitation that is not
documented. Worth an issue with the three-case reproduction above.

---

## 5. The simulator will not tell you which SCP denied you

**What happened.** Raw response for a deny produced by the SCP hierarchy:

```json
{
  "EvalActionName": "lambda:CreateFunction",
  "EvalResourceName": "*",
  "EvalDecision": "explicitDeny",
  "MatchedStatements": [],
  "MissingContextValues": [],
  "OrganizationsDecisionDetail": {
    "AllowedByOrganizations": false
  }
}
```

The denying SCP had a `Sid` of `DenyOutsideApprovedRegions`. It appears nowhere.

**Cause.** `MatchedStatements` is populated for identity, resource and permissions
boundary policies. For SCPs the response carries only the boolean
`OrganizationsDecisionDetail.AllowedByOrganizations`.

**Why it matters.** The production error is "explicit deny in a service control
policy" with no indication which policy, and finding the culprit by hand across an
OU hierarchy is the reason people ask about this on re:Post. The simulator knows
exactly which statement matched, because it just evaluated it, and returns a
boolean instead.

**Fix.** None. `scp-preflight` reports `the SCP hierarchy (the API does not say
which policy)` rather than pretending to know. When a check fails you still have to
bisect your own hierarchy.

**Do the official docs cover it?** Partially. `MatchedStatements` is documented as
"a list of the statements in the input policies that determine the result for this
scenario", which does not tell you SCPs are excluded. `OrganizationsDecisionDetail`
is documented accurately.

**Triage:** service gap. Reasonable feature request: populate `MatchedStatements`
with the SCP source, or add the hierarchy index and `Sid` to
`OrganizationsDecisionDetail`.

---

## 6. The two new parameters landed on different operations

**What happened.** Inspecting the botocore 1.43.62 service model:

```
--- SimulateCustomPolicy ---
    ActionNames
    CallerArn
    ContextEntries
    Marker
    MaxItems
    OrderedOrganizationPolicyInputList  <-- NEW
    PermissionsBoundaryPolicyInputList
    PolicyInputList
    ResourceArns
    ResourceHandlingOption
    ResourceOwner
    ResourcePolicy

--- SimulatePrincipalPolicy ---
    ActionNames
    CallerArn
    ContextEntries
    Marker
    MaxItems
    PermissionsBoundaryPolicyInputList
    PolicyExclusionList  <-- NEW
    PolicyInputList
    PolicySourceArn
    ResourceArns
    ResourceHandlingOption
    ResourceOwner
    ResourcePolicy
```

**Cause.** `OrderedOrganizationPolicyInputList` exists only on
`SimulateCustomPolicy`, which takes identity policies as strings.
`SimulatePrincipalPolicy`, the operation that reads a real principal's attached
policies, always uses the caller's live SCP hierarchy and has no parameter to
supply a proposed one.

**Why it matters.** The question a platform team actually asks is "will this
proposed SCP break this existing role", and no single call answers it. You have to
export the role's policies and pass them as strings, which drifts from the live
role the moment anyone edits it.

**Fix.** None. `scp-preflight` takes principals as policy documents and says so in
the README.

**Do the official docs cover it?** The parameters are documented per operation
correctly. Nothing states the combination is impossible, and the launch
announcement describes both capabilities together as if they compose.

**Triage:** Terraform-adjacent service gap. Reasonable feature request: add
`OrderedOrganizationPolicyInputList` to `SimulatePrincipalPolicy`.

---

## 7. The feature is unavailable on Python 3.9, and nothing says so

**What happened.** The first push to GitHub failed CI on the Python 3.9 job. Every
other version in the matrix passed.

```
ERROR: Ignored the following versions that require a different python version: 1.43.0 Requires-Python >=3.10; ... 1.43.60 Requires-Python >=3.10; 1.43.61 Requires-Python >=3.10; 1.43.62 Requires-Python >=3.10
ERROR: Could not find a version that satisfies the requirement boto3>=1.43.60 (from scp-preflight)
ERROR: No matching distribution found for boto3>=1.43.60
```

**Cause.** The two constraints are mutually exclusive.

```
botocore 1.43.62  requires_python: >=3.10
botocore 1.43.60  requires_python: >=3.10   <- first release with the parameter
botocore 1.42.97  requires_python: >=3.9    <- last release supporting 3.9
```

`OrderedOrganizationPolicyInputList` arrived in 1.43.60, and every 1.43.x release
requires Python 3.10. There is no combination of Python 3.9 and a botocore that has
the parameter, so conditional SCP simulation is unavailable on 3.9 through any SDK
version.

**Fix.** `requires-python = ">=3.10"`, and drop 3.9 from the CI matrix. The
constraint is real, there is nothing to work around.

**Do the official docs cover it?** No. The launch announcement and the API
reference describe the capability with no reference to an SDK version or a language
runtime requirement, which is the same omission as entry 1. Anyone still on 3.9
finds out from a dependency resolver error that mentions neither IAM nor the
feature.

**Triage:** docs gap. Folded into upstream draft 4, which already covers the
undocumented minimum SDK version.
