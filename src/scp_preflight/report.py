"""Turn simulation results into something a human or a CI log can read."""

from __future__ import annotations

import json
import sys
from typing import Iterable

from .simulate import NO_RESULT, Result

PASS = "PASS"
FAIL = "FAIL"
# The decision matched, but a condition key the SCP depends on was not supplied,
# so the answer is not the one production would give. Treated as a failure unless
# --allow-missing-context is set.
INCONCLUSIVE = "INCONCLUSIVE"


def _state(result: Result, strict_context: bool) -> str:
    if not result.passed:
        return FAIL
    if result.unsupplied_keys and strict_context:
        return INCONCLUSIVE
    return PASS


def _sources(result: Result) -> str:
    """
    Which policy produced the decision.

    For an SCP deny the API returns an empty MatchedStatements and only tells you
    that Organizations refused, not which policy or statement. That is the same
    dead end as the production error message. See SHARP-EDGES.md entry 5.
    """
    if result.decision == NO_RESULT:
        return "nothing: the simulator returned no result for this action"
    seen = []
    for statement in result.matched:
        source = statement.get("SourcePolicyId") or "?"
        kind = statement.get("SourcePolicyType") or "?"
        label = f"{source} ({kind})"
        if label not in seen:
            seen.append(label)
    if seen:
        return ", ".join(seen)
    if result.denied_by_organizations:
        return "the SCP hierarchy (the API does not say which policy)"
    return "no statement matched"


def text(results: Iterable[Result], strict_context: bool, stream=sys.stdout) -> int:
    """Write a plain report. Returns the number of results that are not PASS."""
    results = list(results)
    bad = 0

    for result in results:
        state = _state(result, strict_context)
        if state != PASS:
            bad += 1
        print(f"{state}  {result.label}", file=stream)

        if state == FAIL:
            print(f"        expected: {result.case.expect}", file=stream)
            print(f"        actual:   {result.decision}", file=stream)
            print(f"        decided by: {_sources(result)}", file=stream)

        if result.unsupplied_keys:
            print(
                f"        the guardrail conditions on {', '.join(result.unsupplied_keys)}, "
                "which this test did not supply",
                file=stream,
            )
            if state == INCONCLUSIVE:
                print(
                    f"        the decision was {result.decision} as expected, but it was "
                    "reached without those keys, so it is not the production answer",
                    file=stream,
                )

    total = len(results)
    print(file=stream)
    print(f"{total - bad}/{total} checks passed", file=stream)
    return bad


def as_json(results: Iterable[Result], strict_context: bool, stream=sys.stdout) -> int:
    results = list(results)
    payload = []
    bad = 0

    for result in results:
        state = _state(result, strict_context)
        if state != PASS:
            bad += 1
        payload.append(
            {
                "test": result.case.name,
                "principal": result.case.principal,
                "action": result.action,
                "resource": result.resource,
                "expected": result.case.expect,
                "decision": result.decision,
                "state": state,
                "decided_by": _sources(result),
                "unsupplied_context_keys": result.unsupplied_keys,
                "missing_context_values_from_api": result.missing_context,
            }
        )

    json.dump(
        {
            "passed": len(results) - bad,
            "failed": bad,
            "total": len(results),
            "results": payload,
        },
        stream,
        indent=2,
    )
    print(file=stream)
    return bad
