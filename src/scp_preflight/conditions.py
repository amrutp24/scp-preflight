"""
Find the condition keys a policy depends on.

The API will not do this for the SCP half. GetContextKeysForCustomPolicy accepts
only PolicyInputList, and SimulateCustomPolicy reports MissingContextValues for
condition keys in identity policies but stays silent about condition keys in the
SCP hierarchy. That silence produces confident wrong answers, so we work it out
locally instead. See SHARP-EDGES.md entry 4.
"""

from __future__ import annotations

import fnmatch
from typing import Any, Iterable

# Condition operators can carry a set qualifier, as in ForAllValues:StringEquals.
# The key we care about sits inside the block either way.
_SET_QUALIFIERS = ("ForAllValues:", "ForAnyValue:")

# IfExists operators evaluate to true when the key is absent, so an unsupplied key
# is a deliberate, documented case rather than a hole in your test.
_IF_EXISTS_SUFFIX = "IfExists"

# Null tests presence directly. Absence is the thing being asserted, so leaving the
# key out is correct rather than an omission.
_PRESENCE_OPERATORS = {"Null"}


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    return [v for v in value if isinstance(v, str)]


def statement_covers(statement: dict[str, Any], actions: Iterable[str]) -> bool:
    """
    Could this statement apply to any of these actions?

    Used to keep irrelevant condition keys out of the report. A real managed policy
    references dozens of keys across statements that have nothing to do with the
    action under test, and reporting all of them is noise that hides the one that
    matters.
    """
    actions = list(actions)
    if not actions:
        return True

    allow = _as_list(statement.get("Action"))
    deny = _as_list(statement.get("NotAction"))

    if allow:
        return any(
            fnmatch.fnmatch(action.lower(), pattern.lower())
            for action in actions
            for pattern in allow
        )
    if deny:
        # Applies to everything the NotAction list does not name.
        return any(
            not any(fnmatch.fnmatch(action.lower(), pattern.lower()) for pattern in deny)
            for action in actions
        )
    return True


def keys_in_policy(policy: dict[str, Any], actions: Iterable[str] | None = None) -> set[str]:
    """
    Every condition key referenced by a policy document, excluding operators where
    an absent key is the thing being asserted. Pass `actions` to consider only the
    statements that could apply to them.
    """
    found: set[str] = set()

    statements = policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    for statement in statements:
        if not isinstance(statement, dict):
            continue
        if actions is not None and not statement_covers(statement, actions):
            continue
        condition = statement.get("Condition")
        if not isinstance(condition, dict):
            continue

        for operator, block in condition.items():
            if not isinstance(block, dict):
                continue
            bare = operator
            for qualifier in _SET_QUALIFIERS:
                if bare.startswith(qualifier):
                    bare = bare[len(qualifier):]
            if bare.endswith(_IF_EXISTS_SUFFIX) or bare in _PRESENCE_OPERATORS:
                continue
            found.update(block.keys())

    return found


def keys_in_policies(
    policies: Iterable[dict[str, Any]], actions: Iterable[str] | None = None
) -> set[str]:
    actions = list(actions) if actions is not None else None
    keys: set[str] = set()
    for policy in policies:
        keys |= keys_in_policy(policy, actions)
    return keys


def undeclared(required: Iterable[str], supplied: Iterable[str]) -> list[str]:
    """
    Which required keys were not supplied. IAM treats condition keys as
    case-insensitive, so the comparison is too, but the reported name keeps the
    casing the policy used.
    """
    have = {k.lower() for k in supplied}
    return sorted(k for k in required if k.lower() not in have)
