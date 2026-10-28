import json

import pytest

from scp_preflight.simulate import build_hierarchy
from scp_preflight.spec import SpecError, load

MINIMAL = """
version: 1
hierarchy:
  - name: root
    policies: []
principals:
  - name: app
    policies:
      - app.json
tests:
  - name: allows the thing
    principal: app
    actions: [s3:GetObject]
    expect: allowed
"""


def write_spec(tmp_path, body, policy=None):
    (tmp_path / "app.json").write_text(
        json.dumps(policy or {"Version": "2012-10-17", "Statement": []})
    )
    path = tmp_path / "preflight.yaml"
    path.write_text(body)
    return path


def test_loads_a_minimal_spec(tmp_path):
    spec = load(write_spec(tmp_path, MINIMAL))
    assert len(spec.cases) == 1
    assert spec.cases[0].resources == ["*"]
    assert spec.inject_full_aws_access is True


def test_rejects_unknown_expectation(tmp_path):
    body = MINIMAL.replace("expect: allowed", "expect: probably")
    with pytest.raises(SpecError, match="'expect' must be one of"):
        load(write_spec(tmp_path, body))


def test_rejects_unknown_principal(tmp_path):
    body = MINIMAL.replace("principal: app", "principal: nobody")
    with pytest.raises(SpecError, match="unknown principal"):
        load(write_spec(tmp_path, body))


def test_rejects_too_many_levels(tmp_path):
    levels = "\n".join(f"  - name: level{i}\n    policies: []" for i in range(8))
    body = MINIMAL.replace("hierarchy:\n  - name: root\n    policies: []", f"hierarchy:\n{levels}")
    with pytest.raises(SpecError, match="at most 7"):
        load(write_spec(tmp_path, body))


def test_rejects_wildcard_action_names(tmp_path):
    # The API accepts s3:* without expanding it and answers allowed, hiding a deny
    # on any specific action in that service. Better to refuse the spec.
    body = MINIMAL.replace("actions: [s3:GetObject]", "actions: ['s3:*']")
    with pytest.raises(SpecError, match="wildcard action names are not usable"):
        load(write_spec(tmp_path, body))


def test_rejects_single_character_wildcards_too(tmp_path):
    body = MINIMAL.replace("actions: [s3:GetObject]", "actions: ['s3:GetObjec?']")
    with pytest.raises(SpecError, match="wildcard action names are not usable"):
        load(write_spec(tmp_path, body))


def test_ordinary_action_names_are_fine(tmp_path):
    spec = load(write_spec(tmp_path, MINIMAL))
    assert spec.cases[0].actions == ["s3:GetObject"]


def test_missing_policy_file_names_the_path(tmp_path):
    body = MINIMAL.replace("- app.json", "- nope.json")
    with pytest.raises(SpecError, match="policy file not found"):
        load(write_spec(tmp_path, body))


def test_case_context_overrides_defaults(tmp_path):
    body = MINIMAL.replace(
        "tests:",
        "defaults:\n  context:\n    aws:RequestedRegion: us-east-1\ntests:",
    ).replace(
        "    expect: allowed",
        "    context:\n      aws:RequestedRegion: eu-west-1\n    expect: allowed",
    )
    spec = load(write_spec(tmp_path, body))
    assert spec.cases[0].context["aws:RequestedRegion"]["values"] == ["eu-west-1"]


def test_full_aws_access_is_injected_at_every_level(tmp_path):
    spec = load(write_spec(tmp_path, MINIMAL))
    hierarchy = build_hierarchy(spec)
    assert len(hierarchy) == 1
    policies = [json.loads(p) for p in hierarchy[0]["ServiceControlPolicyInputList"]]
    assert policies[0]["Statement"][0]["Action"] == "*"


def test_injection_can_be_turned_off(tmp_path):
    body = MINIMAL.replace("version: 1", "version: 1\ninject_full_aws_access: false")
    spec = load(write_spec(tmp_path, body))
    assert build_hierarchy(spec)[0]["ServiceControlPolicyInputList"] == []


# --- unknown keys and version -----------------------------------------------


@pytest.mark.parametrize(
    "old,new,where,suggestion",
    [
        # The one that motivated this: a singular 'resource' used to be ignored, so
        # the test ran against '*' and could pass.
        ("    expect: allowed", "    resource: arn:aws:s3:::bucket\n    expect: allowed",
         "test 'allows the thing'", "resources"),
        ("    actions: [s3:GetObject]",
         "    actions: [s3:GetObject]\n    contxt:\n      aws:RequestedRegion: us-east-1",
         "test 'allows the thing'", "context"),
        ("version: 1", "version: 1\ntest: []", "preflight.yaml", "tests"),
        ("version: 1", "version: 1\ninject_full_aws_acess: false", "preflight.yaml",
         "inject_full_aws_access"),
        ("  - name: root\n    policies: []", "  - name: root\n    policy: []",
         "hierarchy[0]", "policies"),
        ("  - name: app\n", "  - name: app\n    permission_boundary: app.json\n",
         "principal app", "permissions_boundary"),
    ],
)
def test_rejects_misspelled_keys(tmp_path, old, new, where, suggestion):
    body = MINIMAL.replace(old, new)
    assert body != MINIMAL
    with pytest.raises(SpecError) as caught:
        load(write_spec(tmp_path, body))
    message = str(caught.value)
    assert "unknown key" in message
    assert where in message
    assert f"did you mean {suggestion!r}" in message


def test_rejects_unknown_keys_in_defaults(tmp_path):
    body = MINIMAL.replace("tests:", "defaults:\n  contexts: {}\ntests:")
    with pytest.raises(SpecError, match="defaults: unknown key 'contexts'"):
        load(write_spec(tmp_path, body))


def test_rejects_unknown_keys_in_explicit_context_values(tmp_path):
    body = MINIMAL.replace(
        "    expect: allowed",
        "    context:\n      aws:RequestedRegion: {type: string, value: us-east-1}\n"
        "    expect: allowed",
    )
    with pytest.raises(SpecError, match="context key aws:RequestedRegion: unknown key 'value'"):
        load(write_spec(tmp_path, body))


def test_reports_every_unknown_key_at_once(tmp_path):
    body = MINIMAL.replace("version: 1", "version: 1\nfoo: 1\nbar: 2")
    with pytest.raises(SpecError, match="unknown keys 'foo', 'bar'"):
        load(write_spec(tmp_path, body))


def test_unknown_key_with_no_close_match_lists_the_valid_ones(tmp_path):
    body = MINIMAL.replace("version: 1", "version: 1\nzzzz: 1")
    with pytest.raises(SpecError, match="Valid keys: defaults, hierarchy"):
        load(write_spec(tmp_path, body))


@pytest.mark.parametrize("version", ["2", "'1'", "true"])
def test_rejects_unsupported_versions(tmp_path, version):
    body = MINIMAL.replace("version: 1", f"version: {version}")
    with pytest.raises(SpecError, match="unsupported spec version"):
        load(write_spec(tmp_path, body))


def test_version_may_be_omitted(tmp_path):
    body = MINIMAL.replace("version: 1\n", "")
    assert len(load(write_spec(tmp_path, body)).cases) == 1
