"""Test AWS service control policies against your workloads before you attach them."""

__version__ = "0.1.0"

# AWS Organizations attaches FullAWSAccess to every root, OU, and account by
# default. The simulator does not, so a hierarchy built only from your own deny
# policies evaluates to implicitDeny at every level. This is the policy the tool
# injects unless you turn injection off. See SHARP-EDGES.md entry 2.
FULL_AWS_ACCESS = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
}

# SimulateCustomPolicy caps OrderedOrganizationPolicyInputList at 7 elements,
# which matches root + 5 nested OUs + account.
MAX_HIERARCHY_LEVELS = 7
