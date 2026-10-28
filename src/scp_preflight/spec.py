"""Load and validate a preflight spec file."""

from __future__ import annotations

import difflib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from . import MAX_HIERARCHY_LEVELS

# Decisions the simulator can return. "denied" is ours, not the API's: it means
# "either kind of deny", which is what you usually want to assert.
API_DECISIONS = {"allowed", "explicitDeny", "implicitDeny"}
EXPECTATIONS = API_DECISIONS | {"denied"}

SPEC_VERSIONS = {1}

# Every key the loader reads, per mapping. Anything else is a typo, and a typo is
# dangerous here: 'resource:' instead of 'resources:' would quietly test against
# '*' and pass.
TOP_LEVEL_KEYS = {"version", "hierarchy", "principals", "defaults", "tests", "inject_full_aws_access"}
LEVEL_KEYS = {"name", "policies"}
PRINCIPAL_KEYS = {"name", "policies", "permissions_boundary", "role"}
DEFAULTS_KEYS = {"context"}
TEST_KEYS = {"name", "principal", "actions", "resources", "context", "expect"}
CONTEXT_VALUE_KEYS = {"type", "values"}

CONTEXT_TYPES = {
    "string", "stringList", "numeric", "numericList", "boolean", "booleanList",
    "ip", "ipList", "binary", "binaryList", "date", "dateList",
}


class SpecError(Exception):
    """Raised when a spec file is malformed. The message is shown to the user as-is."""


@dataclass
class Level:
    """One level of the Organizations hierarchy, root first, account last."""

    name: str
    policies: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class Principal:
    name: str
    policies: list[dict[str, Any]] = field(default_factory=list)
    permissions_boundary: dict[str, Any] | None = None
    # A role name or ARN whose policies are read at run time. Resolved by
    # principal.resolve() before the simulation, not while loading the spec, so
    # that loading stays offline and testable.
    role: str | None = None


@dataclass
class Case:
    name: str
    principal: str
    actions: list[str]
    expect: str
    resources: list[str] = field(default_factory=lambda: ["*"])
    context: dict[str, Any] = field(default_factory=dict)


@dataclass
class Spec:
    hierarchy: list[Level]
    principals: dict[str, Principal]
    cases: list[Case]
    inject_full_aws_access: bool = True
    source: Path | None = None


def _check_keys(mapping: dict[str, Any], allowed: set[str], where: str) -> None:
    unknown = [k for k in mapping if k not in allowed]
    if not unknown:
        return
    described = []
    for key in unknown:
        close = difflib.get_close_matches(str(key), allowed, n=1)
        described.append(f"{key!r} (did you mean {close[0]!r}?)" if close else repr(key))
    raise SpecError(
        f"{where}: unknown key{'s' if len(unknown) > 1 else ''} {', '.join(described)}. "
        f"Valid keys: {', '.join(sorted(allowed))}"
    )


def _read_policy(ref: Any, base: Path, where: str) -> dict[str, Any]:
    """A policy is either an inline dict or a path to a JSON file, relative to the spec."""
    if isinstance(ref, dict):
        return ref
    if not isinstance(ref, str):
        raise SpecError(f"{where}: expected a file path or an inline policy object, got {type(ref).__name__}")

    path = (base / ref).resolve()
    if not path.is_file():
        raise SpecError(f"{where}: policy file not found: {path}")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SpecError(f"{where}: {path} is not valid JSON: {exc}") from exc


def _normalise_context(raw: Any, where: str) -> dict[str, Any]:
    """
    Accept both the short form and the explicit form:

        aws:RequestedRegion: us-east-1
        aws:RequestedRegion: { type: string, values: [us-east-1, us-west-2] }
    """
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise SpecError(f"{where}: context must be a mapping of condition key to value")

    out: dict[str, Any] = {}
    for key, value in raw.items():
        if isinstance(value, dict):
            _check_keys(value, CONTEXT_VALUE_KEYS, f"{where}: context key {key}")
            ctype = value.get("type", "string")
            values = value.get("values")
            if values is None:
                raise SpecError(f"{where}: context key {key} is missing 'values'")
            if not isinstance(values, list):
                values = [values]
        else:
            ctype = "boolean" if isinstance(value, bool) else "string"
            values = value if isinstance(value, list) else [value]

        if ctype not in CONTEXT_TYPES:
            raise SpecError(
                f"{where}: context key {key} has unknown type {ctype!r}. "
                f"Valid types: {', '.join(sorted(CONTEXT_TYPES))}"
            )
        # The API takes every value as a string regardless of declared type.
        out[key] = {
            "type": ctype,
            "values": [str(v).lower() if isinstance(v, bool) else str(v) for v in values],
        }
    return out


def load(path: str | Path) -> Spec:
    path = Path(path).resolve()
    if not path.is_file():
        raise SpecError(f"spec file not found: {path}")

    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise SpecError(f"{path} is not valid YAML: {exc}") from exc

    if not isinstance(raw, dict):
        raise SpecError(f"{path}: top level must be a mapping")

    _check_keys(raw, TOP_LEVEL_KEYS, str(path))

    version = raw.get("version", 1)
    # bool is an int in Python, and True == 1, so rule it out explicitly.
    if isinstance(version, bool) or version not in SPEC_VERSIONS:
        raise SpecError(
            f"{path}: unsupported spec version {version!r}. "
            f"This scp-preflight understands version {', '.join(map(str, sorted(SPEC_VERSIONS)))}"
        )

    base = path.parent

    raw_hierarchy = raw.get("hierarchy")
    if not raw_hierarchy:
        raise SpecError(f"{path}: 'hierarchy' is required and must list at least one level")
    if len(raw_hierarchy) > MAX_HIERARCHY_LEVELS:
        raise SpecError(
            f"{path}: hierarchy has {len(raw_hierarchy)} levels, "
            f"the simulator accepts at most {MAX_HIERARCHY_LEVELS} (root + 5 OUs + account)"
        )

    hierarchy = []
    for i, level in enumerate(raw_hierarchy):
        if not isinstance(level, dict):
            raise SpecError(f"{path}: hierarchy[{i}] must be a mapping with 'name' and 'policies'")
        name = level.get("name") or f"level-{i}"
        where = f"{path}: hierarchy[{i}] ({name})"
        _check_keys(level, LEVEL_KEYS, where)
        policies = [_read_policy(p, base, where) for p in (level.get("policies") or [])]
        hierarchy.append(Level(name=name, policies=policies))

    principals: dict[str, Principal] = {}
    for i, p in enumerate(raw.get("principals") or []):
        if not isinstance(p, dict) or "name" not in p:
            raise SpecError(f"{path}: principals[{i}] must be a mapping with a 'name'")
        name = p["name"]
        if name in principals:
            raise SpecError(f"{path}: duplicate principal name {name!r}")
        where = f"{path}: principal {name}"
        _check_keys(p, PRINCIPAL_KEYS, where)
        boundary = p.get("permissions_boundary")
        role = p.get("role")
        if role is not None and not isinstance(role, str):
            raise SpecError(f"{where}: 'role' must be a role name or ARN")
        policies = [_read_policy(x, base, where) for x in (p.get("policies") or [])]
        if not policies and not role:
            raise SpecError(f"{where}: needs either 'policies' or 'role'")
        principals[name] = Principal(
            name=name,
            policies=policies,
            permissions_boundary=_read_policy(boundary, base, where) if boundary else None,
            role=role,
        )
    if not principals:
        raise SpecError(f"{path}: at least one principal is required")

    raw_defaults = raw.get("defaults") or {}
    if not isinstance(raw_defaults, dict):
        raise SpecError(f"{path}: 'defaults' must be a mapping")
    _check_keys(raw_defaults, DEFAULTS_KEYS, f"{path}: defaults")
    defaults = _normalise_context(raw_defaults.get("context"), f"{path}: defaults")

    cases = []
    for i, c in enumerate(raw.get("tests") or []):
        if not isinstance(c, dict):
            raise SpecError(f"{path}: tests[{i}] must be a mapping")
        name = c.get("name") or f"test-{i}"
        where = f"{path}: test {name!r}"
        _check_keys(c, TEST_KEYS, where)

        expect = c.get("expect")
        if expect not in EXPECTATIONS:
            raise SpecError(
                f"{where}: 'expect' must be one of {', '.join(sorted(EXPECTATIONS))}, got {expect!r}"
            )
        principal = c.get("principal")
        if principal not in principals:
            raise SpecError(f"{where}: unknown principal {principal!r}")
        actions = c.get("actions")
        if not actions:
            raise SpecError(f"{where}: 'actions' is required")
        if isinstance(actions, str):
            actions = [actions]

        # The API accepts a wildcard action name, does not expand it, and returns a
        # single result for a literal action of that name. A guardrail denying one
        # action in the service is invisible: s3:DeleteBucket returns explicitDeny
        # while s3:* returns allowed. Reject it rather than let it give false
        # confidence. See SHARP-EDGES.md entry 8.
        wildcards = [a for a in actions if "*" in a or "?" in a]
        if wildcards:
            raise SpecError(
                f"{where}: wildcard action names are not usable: {', '.join(wildcards)}. "
                "The simulator accepts them without expanding them, so a wildcard "
                "returns 'allowed' even when a specific action in that service is "
                "denied. List the actions you care about individually."
            )

        resources = c.get("resources") or ["*"]
        if isinstance(resources, str):
            resources = [resources]

        context = dict(defaults)
        context.update(_normalise_context(c.get("context"), where))

        cases.append(
            Case(name=name, principal=principal, actions=actions,
                 resources=resources, context=context, expect=expect)
        )

    if not cases:
        raise SpecError(f"{path}: no tests defined")

    return Spec(
        hierarchy=hierarchy,
        principals=principals,
        cases=cases,
        inject_full_aws_access=bool(raw.get("inject_full_aws_access", True)),
        source=path,
    )
