import pytest

from scp_preflight.principal import PrincipalError, role_name_from


def test_plain_role_name():
    assert role_name_from("app-deploy") == "app-deploy"


def test_role_arn():
    assert role_name_from("arn:aws:iam::123456789012:role/app-deploy") == "app-deploy"


def test_role_arn_with_a_path():
    # GetRole wants the trailing name, not the path.
    assert role_name_from("arn:aws:iam::123456789012:role/team/platform/app-deploy") == "app-deploy"


def test_arn_partitions_other_than_aws():
    assert role_name_from("arn:aws-us-gov:iam::123456789012:role/app") == "app"


def test_rejects_a_non_role_arn():
    with pytest.raises(PrincipalError, match="not a role ARN"):
        role_name_from("arn:aws:iam::123456789012:user/someone")
