"""Command-line interface for the x402 payment firewall.

Two modes:

* guard a payment request (default) — evaluate via the signing gate, print a
  JSON result including ``allowed``, and exit with a code scripts can branch on:
      * 0  -> allowed (PAY, or ASK auto-approved)
      * 1  -> DENY (hard denial)
      * 3  -> ASK (needs human approval)
* report spend — with ``--report``, print the cumulative spent total from the
  store and exit 0.

The store is a SQLite file (default ``x402_firewall.db``); pass ``--db :memory:``
to keep everything in-memory (no file is created).
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Optional, Sequence

from .models import Verdict
from .policy import PolicyConfig
from .store import Store
from .gate import guard_payment

EXIT_OK = 0
EXIT_DENY = 1
EXIT_ASK = 3


def _load_json(path: Optional[str], stream) -> object:
    if path is None or path == "-":
        return json.load(stream)
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="x402_firewall",
        description="Validate an x402 payment request against a local policy "
        "and enforce the signing gate.",
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
        "--db",
        metavar="PATH",
        default="x402_firewall.db",
        help="SQLite store path (default: x402_firewall.db; use ':memory:' "
        "for an in-memory store)",
    )
    parser.add_argument(
        "--expected-amount",
        metavar="AMOUNT",
        type=float,
        default=None,
        help="optional expected amount to compare against (amount-tampering check)",
    )
    parser.add_argument(
        "--total-budget",
        metavar="AMOUNT",
        type=float,
        default=None,
        help="override the policy's total_budget (cumulative spend cap)",
    )
    parser.add_argument(
        "--auto-approve-ask",
        action="store_true",
        help="auto-approve ASK verdicts (bypasses the human-approval gate)",
    )
    parser.add_argument(
        "--report",
        action="store_true",
        help="print the cumulative spend total from the store and exit",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        policy = PolicyConfig.from_dict(_load_json(args.policy, sys.stdin))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: failed to load policy: {exc}", file=sys.stderr)
        return 2

    if args.total_budget is not None:
        policy.total_budget = args.total_budget

    with Store(args.db) as store:
        if args.report:
            print(json.dumps({"total_spent": store.total_spent()}, sort_keys=True))
            return EXIT_OK

        try:
            request_data = _load_json(args.request, sys.stdin)
        except json.JSONDecodeError as exc:
            print(f"error: invalid JSON: {exc}", file=sys.stderr)
            return 2

        try:
            gate_result = guard_payment(
                request_data,
                policy,
                store=store,
                expected_amount=args.expected_amount,
                auto_approve_ask=args.auto_approve_ask,
            )
        except (ValueError, TypeError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

        print(json.dumps(gate_result.to_dict(), sort_keys=True))

        if gate_result.allowed:
            return EXIT_OK
        if gate_result.result.decision is Verdict.ASK:
            return EXIT_ASK
        return EXIT_DENY


if __name__ == "__main__":
    raise SystemExit(main())
