"""Command line entry point."""

from __future__ import annotations

import argparse
import sys

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from . import __version__
from .principal import PrincipalError, resolve
from .report import as_json, text
from .simulate import IncompleteResponse, SimulatorUnavailable, run
from .spec import SpecError, load

EXIT_OK = 0
EXIT_FAILED_CHECKS = 1
EXIT_BAD_USAGE = 2
EXIT_AWS_ERROR = 3


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scp-preflight",
        description=(
            "Simulate a proposed AWS service control policy hierarchy against your "
            "workload principals, and fail if the results do not match what you declared."
        ),
    )
    parser.add_argument("spec", help="path to a preflight spec (YAML)")
    parser.add_argument("--json", action="store_true", help="emit JSON instead of text")
    parser.add_argument(
        "--profile", help="AWS profile to use (the simulator makes no changes and is not billed)"
    )
    parser.add_argument("--region", help="AWS region for the IAM endpoint")
    parser.add_argument(
        "--allow-missing-context",
        action="store_true",
        help=(
            "downgrade unsupplied condition keys from failure to warning. "
            "Off by default: if a policy conditions on a key you did not supply, "
            "the simulator skips that condition and the result is misleading."
        ),
    )
    parser.add_argument("--version", action="version", version=f"scp-preflight {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        spec = load(args.spec)
    except SpecError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_BAD_USAGE

    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    client = session.client("iam")

    try:
        # Principals declared with 'role:' are read from IAM here, before any
        # simulation runs, so a bad role name fails fast.
        resolve(spec, client)
    except PrincipalError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_AWS_ERROR
    except (ClientError, BotoCoreError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_AWS_ERROR

    try:
        results = run(spec, client)
    except SimulatorUnavailable as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_BAD_USAGE
    except (ClientError, BotoCoreError, IncompleteResponse) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_AWS_ERROR

    strict_context = not args.allow_missing_context
    emit = as_json if args.json else text
    failures = emit(results, strict_context)

    return EXIT_FAILED_CHECKS if failures else EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
