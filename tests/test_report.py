import io
import json

import pytest

from scp_preflight.report import as_json, text

from .conftest import make_result


def render(results, strict=True):
    stream = io.StringIO()
    count = text(results, strict, stream=stream)
    return stream.getvalue(), count


def render_json(results, strict=True):
    stream = io.StringIO()
    count = as_json(results, strict, stream=stream)
    return json.loads(stream.getvalue()), count


# --- states -----------------------------------------------------------------


def test_matching_decision_passes():
    out, count = render([make_result(decision="allowed", expect="allowed")])
    assert out.startswith("PASS")
    assert count == 0


def test_mismatched_decision_fails_and_shows_both():
    out, count = render([make_result(decision="explicitDeny", expect="allowed")])
    assert out.startswith("FAIL")
    assert "expected: allowed" in out
    assert "actual:   explicitDeny" in out
    assert count == 1


def test_right_answer_reached_without_context_is_inconclusive():
    out, count = render(
        [make_result(decision="explicitDeny", expect="explicitDeny",
                     undeclared=["aws:PrincipalTag/team"])]
    )
    assert out.startswith("INCONCLUSIVE")
    assert "aws:PrincipalTag/team" in out
    assert "not the production answer" in out
    assert count == 1


def test_allow_missing_context_downgrades_inconclusive_to_pass():
    results = [make_result(decision="explicitDeny", expect="explicitDeny",
                           undeclared=["aws:PrincipalTag/team"])]
    out, count = render(results, strict=False)

    assert out.startswith("PASS")
    assert count == 0
    # Still mentioned, just not fatal.
    assert "aws:PrincipalTag/team" in out


def test_a_real_mismatch_stays_a_fail_even_when_relaxed():
    results = [make_result(decision="allowed", expect="explicitDeny",
                           undeclared=["aws:PrincipalTag/team"])]
    out, count = render(results, strict=False)
    assert out.startswith("FAIL")
    assert count == 1


# --- attribution ------------------------------------------------------------


def test_identity_policy_source_is_named():
    matched = [{"SourcePolicyId": "PolicyInputList.1", "SourcePolicyType": "IAM Policy"}]
    out, _ = render([make_result(decision="allowed", expect="explicitDeny", matched=matched)])
    assert "decided by: PolicyInputList.1 (IAM Policy)" in out


def test_duplicate_sources_are_collapsed():
    matched = [
        {"SourcePolicyId": "PolicyInputList.1", "SourcePolicyType": "IAM Policy"},
        {"SourcePolicyId": "PolicyInputList.1", "SourcePolicyType": "IAM Policy"},
    ]
    out, _ = render([make_result(decision="allowed", expect="explicitDeny", matched=matched)])
    assert out.count("PolicyInputList.1") == 1


def test_scp_deny_says_so_without_inventing_a_policy_name():
    out, _ = render(
        [make_result(decision="explicitDeny", expect="allowed", denied_by_organizations=True)]
    )
    assert "the SCP hierarchy (the API does not say which policy)" in out


def test_no_match_and_no_organizations_deny():
    out, _ = render([make_result(decision="implicitDeny", expect="allowed")])
    assert "no statement matched" in out


# --- totals and JSON --------------------------------------------------------


def test_totals_line_counts_only_passes():
    results = [
        make_result(decision="allowed", expect="allowed"),
        make_result(decision="allowed", expect="explicitDeny"),
        make_result(decision="allowed", expect="allowed", undeclared=["aws:TagKeys"]),
    ]
    out, count = render(results)
    assert "1/3 checks passed" in out
    assert count == 2


def test_json_shape():
    payload, count = render_json(
        [make_result(decision="explicitDeny", expect="allowed", denied_by_organizations=True)]
    )
    assert payload["total"] == 1
    assert payload["failed"] == 1
    assert payload["passed"] == 0
    assert count == 1

    row = payload["results"][0]
    assert row["state"] == "FAIL"
    assert row["expected"] == "allowed"
    assert row["decision"] == "explicitDeny"
    assert row["action"] == "s3:CreateBucket"


def test_json_reports_both_key_sources_separately():
    payload, _ = render_json(
        [make_result(decision="allowed", expect="allowed",
                     undeclared=["aws:PrincipalTag/team"], missing=["aws:SourceVpc"])]
    )
    row = payload["results"][0]
    assert row["missing_context_values_from_api"] == ["aws:SourceVpc"]
    assert set(row["unsupplied_context_keys"]) == {"aws:PrincipalTag/team", "aws:SourceVpc"}


@pytest.mark.parametrize("emit", [text, as_json])
def test_empty_result_set_is_not_a_failure(emit):
    stream = io.StringIO()
    assert emit([], True, stream=stream) == 0
