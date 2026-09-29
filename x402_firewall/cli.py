"""Command-line interface for the x402 payment firewall.

Reads a payment request as JSON from a file or stdin, evaluates it against a
policy JSON file, prints the decision + reason as JSON on stdout, and exits
non-zero when the verdict is DENY.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Optional, Sequence

from .models import Verdict
from .policy import PolicyConfig, evaluate_payment_request


def _load_json(path: Optional[str], stream) -> object:
    if path is None or path == "-":
        return json.load(stream)
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="x402_firewall",
        description="Validate an x402 payment request against a local policy.",
    )
    parser.add_argument(
        "--request",
        "-r",
        metavar="PATH",
        help="path to a request JSON file (default: read from stdin)",
    )
    parser.add_argument(
        "--policy",
        "-p",
        metavar="PATH",
        default="examples/policy.json",
        help="path to a policy JSON file (default: examples/policy.json)",
    )
    parser.add_argument(
        "--expected-amount",
        metavar="AMOUNT",
        type=float,
        default=None,
        help="optional expected amount to compare against (amount-tampering check)",
    )
    args = parser.parse_args(argv)

    try:
        request_data = _load_json(args.request, sys.stdin)
    except json.JSONDecodeError as exc:
        print(f"error: invalid JSON: {exc}", file=sys.stderr)
        return 2

    try:
        policy = PolicyConfig.from_dict(_load_json(args.policy, sys.stdin))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: failed to load policy: {exc}", file=sys.stderr)
        return 2

    try:
        result = evaluate_payment_request(request_data, policy, args.expected_amount)
    except (ValueError, TypeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(json.dumps(result.to_dict(), sort_keys=True))
    return 0 if result.decision is not Verdict.DENY else 1


if __name__ == "__main__":
    raise SystemExit(main())
