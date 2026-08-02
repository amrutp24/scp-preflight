# scp-preflight

Test an AWS service control policy against your workloads before you attach it.

You write down what your roles must still be able to do, and what they must not be
able to do, alongside the SCP hierarchy you are proposing. The tool runs it through
the IAM policy simulator and exits non-zero if reality disagrees. Put it in a pull
request and a guardrail change stops being something you find out about from an
on-call page.

Here is the region lock example with the global-services carve-out taken out of
the SCP, which is the mistake that breaks role creation everywhere:

```
PASS  deploys work in an approved region [lambda:CreateFunction on *]
PASS  deploys work in an approved region [s3:CreateBucket on *]
PASS  the second approved region also works [lambda:CreateFunction on *]
PASS  an unapproved region is blocked [lambda:CreateFunction on *]
FAIL  global services stay reachable from any region [iam:CreateRole on arn:aws:iam::123456789012:role/app-worker]
        expected: allowed
        actual:   explicitDeny
        decided by: the SCP hierarchy (the API does not say which policy)

4/5 checks passed
```

## Why this did not exist before

Until 30 July 2026 the policy simulator could not evaluate SCPs that used
conditions. That is most modern guardrails: region locks, tag enforcement,
"deny unless encrypted". If you asked the simulator about one, it ignored the
condition and gave you an answer that did not match production. There is a
[five year old issue](https://github.com/aws/aws-sdk/issues/102) about it, closed
without a fix when the repository was archived.

The [July 2026 update](https://aws.amazon.com/about-aws/whats-new/2026/07/iam-policy-simulator-iam-console/)
added `OrderedOrganizationPolicyInputList` to `SimulateCustomPolicy`, which takes a
proposed SCP hierarchy as an ordered list of levels and evaluates conditions and
resource scoping properly. This tool is a thin, opinionated wrapper around that.

## Requirements

Python 3.10 or newer, and botocore 1.43.60 or newer. The parameter shipped on
2026-07-31 and earlier versions reject the call rather than ignoring the field.
The Python floor comes from botocore: 1.43.60 requires 3.10, and the last botocore
that runs on 3.9 does not have the parameter, so there is no working combination
on 3.9.

```bash
pip install -U 'botocore>=1.43.60' 'boto3>=1.43.60'
```

Credentials need `iam:SimulateCustomPolicy` and nothing else. No Organizations
permissions, no management account, no delegated administrator. The hierarchy is
passed in as text, so you can test a guardrail for an organization you cannot
even read. Simulation creates nothing and is not billed.

## Quickstart

```bash
git clone https://github.com/amrutp24/scp-preflight
cd scp-preflight
pip install -e .
scp-preflight examples/region-lock/preflight.yaml
```

A spec has three parts. The hierarchy, ordered from the organization root down to
the account, at most seven levels. The principals whose access you care about.
The tests.

```yaml
version: 1

hierarchy:
  - name: root
    policies: []
  - name: ou-workloads
    policies: [guardrails/region-lock.json]
  - name: account
    policies: []

principals:
  - name: app-deploy
    policies: [principals/app-deploy.json]

tests:
  - name: deploys work in an approved region
    principal: app-deploy
    actions: [lambda:CreateFunction]
    context:
      aws:RequestedRegion: us-east-1
    expect: allowed

  - name: an unapproved region is blocked
    principal: app-deploy
    actions: [lambda:CreateFunction]
    context:
      aws:RequestedRegion: ap-south-1
    expect: explicitDeny
```

`expect` is `allowed`, `explicitDeny`, `implicitDeny`, or `denied` if you do not
care which kind of deny you got.

## Testing a role that actually exists

Instead of writing the identity policies out, point at a live role and its attached
and inline policies are read at run time:

```yaml
principals:
  - name: app-deploy
    role: arn:aws:iam::123456789012:role/app-deploy
```

A bare role name works too. Anything you also list under `policies` is added on
top, which is how you model a policy you are proposing to attach at the same time
as the guardrail.

This needs `iam:GetRole`, `iam:ListAttachedRolePolicies`, `iam:ListRolePolicies`,
`iam:GetRolePolicy`, `iam:GetPolicy` and `iam:GetPolicyVersion`. If you would
rather not grant those, keep declaring policies in the spec.

Be aware this is a snapshot. The export happens when you run, so a role edited
afterwards was not what you tested. That is a consequence of the API gap described
below, not a design choice.

## Three outcomes, not two

`PASS` and `FAIL` mean what you expect. `INCONCLUSIVE` means the decision matched
what you declared, but a condition key the guardrail depends on was never supplied,
so the simulator reached the right answer for the wrong reason:

```
INCONCLUSIVE  untagged principals are blocked [iam:CreateRole on arn:aws:iam::123456789012:role/anything]
        the guardrail conditions on aws:PrincipalTag/team, which this test did not supply
        the decision was explicitDeny as expected, but it was reached without those keys, so it is not the production answer
```

This is the failure the tool exists to catch. You write a tag guardrail, test it,
see a deny, and ship it. In production the principal carries the tag and the
guardrail does not fire. `INCONCLUSIVE` counts as a failure and exits non-zero.

## FullAWSAccess is added for you

AWS Organizations attaches `FullAWSAccess` to every root, OU and account
automatically. The simulator does not. An SCP hierarchy needs an explicit allow at
every level, so a hierarchy built only from your own deny policies evaluates to
`implicitDeny` for everything, and it looks like your guardrail blocks the world.

This tool prepends `FullAWSAccess` to every level so the simulation matches an
ordinary organization. If you have genuinely removed it somewhere, turn the
injection off and supply the allows yourself:

```yaml
inject_full_aws_access: false
```

## Unsupplied condition keys fail by default

The simulator reports unsupplied condition keys in `MissingContextValues` when the
key is in an identity policy, and says nothing when the same key is in an SCP. The
SCP condition still evaluates, against absent context, so you get a confident
decision that flips the moment you supply the key.

There is no API-side fix. `GetContextKeysForCustomPolicy` accepts only
`PolicyInputList`, so you cannot ask AWS which keys your hierarchy needs either.
This tool reads the SCP documents itself and reports any key referenced by a
statement that could apply to the action under test. Operators where an absent key
is the assertion, `Null` and anything ending in `IfExists`, are skipped.

Use `--allow-missing-context` to downgrade `INCONCLUSIVE` to a passing warning.

## In CI

```yaml
- name: Preflight guardrails
  run: scp-preflight guardrails/preflight.yaml
```

Exit codes are 0 when every check passed, 1 when a check failed, 2 for a bad spec
or too old a botocore, and 3 for an AWS error. `--json` gives you machine-readable
output.

## What this cannot do

There is no single API call that tests a live role against a proposed SCP
hierarchy. AWS put the two halves on different operations:
`OrderedOrganizationPolicyInputList` is only on `SimulateCustomPolicy`, which takes
identity policies as strings, and `SimulatePrincipalPolicy`, which reads a real
principal, always uses your live hierarchy with no way to override it.

`role:` works around this by exporting the role and passing it as strings, which is
why it needs six read permissions and why the result is a snapshot rather than a
live read. If AWS adds `OrderedOrganizationPolicyInputList` to
`SimulatePrincipalPolicy`, all of that goes away.

Resource control policies are out of scope. AWS documents them as not supported in
this release.

The simulator is a model of the evaluation engine, not the engine. AWS says
results can differ from your live environment, and that holds here too. This
catches the guardrail that was obviously going to break your deploy pipeline. It
is not a proof.

## Sharp edges

Every error hit while building this, verbatim, with the fix, is in
[SHARP-EDGES.md](SHARP-EDGES.md).

## License

MIT.
