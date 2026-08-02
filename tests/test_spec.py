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
