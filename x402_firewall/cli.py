"""Command-line interface for the x402 payment firewall.

Modes:

* guard a payment request (default) — evaluate via the signing gate, print a
  JSON result including ``allowed``, and exit with a code scripts can branch on:
      * 0  -> allowed (PAY, or ASK auto-approved / human-approved)
      * 1  -> DENY (hard denial)
      * 3  -> ASK (needs human approval)
      * 4  -> ASK rejected by a human (``--interactive`` only)
      * 2  -> usage / config error
* report spend — with ``--report``, print the cumulative spent total.
* dump audit trail — with ``--audit``, print the decision rows as JSON.
* run a simulated end-to-end demo — with ``--demo SCENARIO``.

The store is a SQLite file (default ``x402_firewall.db``); pass ``--db :memory:``
to keep everything in-memory (no file is created).
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from dataclasses import asdict
from datetime import datetime, timezone
from functools import partial
from typing import Optional, Sequence

from .models import Verdict, MalformedRequestError
from .policy import PolicyConfig, evaluate_payment_request
from .store import Store
from .gate import guard_payment, approve
from .interactive import interactive_approve
from .demo import run_demo
from .wire import (
    WireError,
    WireFetchError,
    UnsupportedSchemeError,
    UnknownAssetError,
    NoMatchingOptionError,
    parse_payment_required_header,
    parse_payment_required_json,
    fetch_payment_required,
    normalize_v2,
)

EXIT_OK = 0
EXIT_DENY = 1
EXIT_ASK = 3
EXIT_REJECTED = 4


def _load_json(path: Optional[str], stream) -> object:
    if path is None or path == "-":
        return json.load(stream)
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def _read_text(path: str, stream) -> str:
    if path == "-":
        return stream.read()
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _write_jsonl(path: str, entry: dict) -> None:
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, sort_keys=True) + "\n")


def _demo_exit_code(outcome: dict) -> int:
    """Map a demo outcome status to a CLI exit code mirroring the guard codes."""
    status = outcome.get("status")
    if status in ("paid", "not_required"):
        return EXIT_OK
    if status == "blocked":
        return EXIT_DENY
    if status == "rejected":
        return EXIT_REJECTED
    return EXIT_ASK  # awaiting


def _run_demo(args, store: Store) -> int:
    """Run a simulated end-to-end demo scenario and print the outcome as JSON."""
    approval_handler = None
    if args.interactive:
        approval_handler = partial(
            interactive_approve, input_stream=sys.stdin, output_stream=sys.stderr
        )
    elif args.approve:
        approval_handler = approve

    summary = run_demo(args.demo, store=store, approval_handler=approval_handler)
    print(json.dumps(summary, sort_keys=True))
    return _demo_exit_code(summary["outcome"])


def _emit_v2_deny(reason: str, rule: str) -> int:
    print(
        json.dumps(
            {
                "normalized_request": None,
                "decision": "DENY",
                "reason": reason,
                "rule": rule,
            },
            sort_keys=True,
        )
    )
    return EXIT_DENY


def _load_v2_payload(args):
    """Read the raw v2 payload from a header file, decoded JSON, or a live fetch."""
    if args.payment_required_header is not None:
        return parse_payment_required_header(_read_text(args.payment_required_header, sys.stdin))
    if args.payment_required_json is not None:
        return parse_payment_required_json(_load_json(args.payment_required_json, sys.stdin))
    return fetch_payment_required(args.fetch_url)


def _run_v2(args, policy) -> int:
    """Parse a real x402 v2 payload, normalize it, and evaluate it.

    Prints the normalized internal request plus the gate decision as JSON and
    exits with the same codes as the guard path (PAY 0 / DENY 1 / ASK 3 / error
    2).
    """
    try:
        pr = _load_v2_payload(args)
    except WireFetchError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"error: failed to load payment-required payload: {exc}", file=sys.stderr)
        return 2
    except (WireError, MalformedRequestError) as exc:
        return _emit_v2_deny(str(exc), "malformed")

    try:
        request = normalize_v2(pr)
    except UnsupportedSchemeError as exc:
        return _emit_v2_deny(str(exc), "unsupported_scheme")
    except UnknownAssetError as exc:
        return _emit_v2_deny(str(exc), "unsupported_asset")
    except NoMatchingOptionError as exc:
        return _emit_v2_deny(str(exc), "no_matching_option")
    except MalformedRequestError as exc:
        return _emit_v2_deny(str(exc), "malformed")

    result = evaluate_payment_request(request, policy, args.expected_amount)
    print(
        json.dumps(
            {
                "normalized_request": asdict(request),
                "decision": result.decision.value,
                "reason": result.reason,
                "rule": result.rule,
            },
            sort_keys=True,
        )
    )

    if result.decision is Verdict.PAY:
        return EXIT_OK
    if result.decision is Verdict.ASK:
        return EXIT_ASK
    return EXIT_DENY


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
    approval_group = parser.add_mutually_exclusive_group()
    approval_group.add_argument(
        "--interactive",
        "-i",
        action="store_true",
        help="on an ASK verdict, prompt a human on the terminal to approve or "
        "reject (approved -> exit 0, rejected -> exit 4)",
    )
    approval_group.add_argument(
        "--approve",
        action="store_true",
        help="deterministically approve an ASK verdict (equivalent to answering "
        "yes), for reviewed scripting/automation",
    )
    parser.add_argument(
        "--signed",
        metavar="PATH",
        default=None,
        help="path to a structured signed-payload JSON file ('-' for stdin); "
        "cross-checked against the request before PAY",
    )
    parser.add_argument(
        "--require-signed",
        action="store_true",
        help="require a signed payload (DENY if absent)",
    )
    parser.add_argument(
        "--report",
        action="store_true",
        help="print the cumulative spend total from the store and exit",
    )
    parser.add_argument(
        "--audit",
        action="store_true",
        help="dump the decision audit trail as JSON and exit",
    )
    parser.add_argument(
        "--limit",
        metavar="N",
        type=int,
        default=None,
        help="with --audit: limit the number of rows returned (newest first)",
    )
    parser.add_argument(
        "--verdict",
        metavar="V",
        choices=["PAY", "ASK", "DENY"],
        default=None,
        help="with --audit: only return rows with this verdict",
    )
    parser.add_argument(
        "--log",
        metavar="PATH",
        default=None,
        help="append one JSON line per decision to this file (append-only JSONL)",
    )
    parser.add_argument(
        "--demo",
        metavar="SCENARIO",
        choices=["clean", "injected", "malicious"],
        default=None,
        help="run a simulated end-to-end demo scenario instead of guarding a "
        "single request (combine with --approve or --interactive to approve an "
        "ASK scenario)",
    )
    v2_group = parser.add_mutually_exclusive_group()
    v2_group.add_argument(
        "--payment-required-header",
        metavar="PATH",
        default=None,
        help="parse a real x402 v2 'payment-required' header value (base64) from "
        "a file, or '-' for stdin",
    )
    v2_group.add_argument(
        "--payment-required-json",
        metavar="PATH",
        default=None,
        help="parse an already-decoded x402 v2 payment-required JSON object from "
        "a file, or '-' for stdin",
    )
    v2_group.add_argument(
        "--fetch-url",
        metavar="URL",
        default=None,
        help="fetch a URL live and parse its 'payment-required' header (for "
        "one-off verification only)",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        store = Store(args.db)
    except (sqlite3.Error, OSError, ValueError) as exc:
        print(f"error: failed to open store: {exc}", file=sys.stderr)
        return 2

    with store:
        if args.report:
            print(json.dumps({"total_spent": store.total_spent()}, sort_keys=True))
            return EXIT_OK

        if args.audit:
            rows = store.list_decisions(limit=args.limit, verdict=args.verdict)
            print(json.dumps(rows, sort_keys=True))
            return EXIT_OK

        if args.demo is not None:
            return _run_demo(args, store)

        try:
            policy = PolicyConfig.from_dict(_load_json(args.policy, sys.stdin))
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"error: failed to load policy: {exc}", file=sys.stderr)
            return 2

        if args.total_budget is not None:
            policy.total_budget = args.total_budget

        if args.require_signed:
            policy.require_signed_payload = True

        if (
            args.payment_required_header is not None
            or args.payment_required_json is not None
            or args.fetch_url is not None
        ):
            return _run_v2(args, policy)

        try:
            request_data = _load_json(args.request, sys.stdin)
        except json.JSONDecodeError as exc:
            print(f"error: invalid JSON: {exc}", file=sys.stderr)
            return 2
        except OSError as exc:
            print(f"error: failed to load request: {exc}", file=sys.stderr)
            return 2

        signed_data = None
        if args.signed is not None:
            try:
                signed_data = _load_json(args.signed, sys.stdin)
            except (OSError, json.JSONDecodeError) as exc:
                print(f"error: failed to load signed payload: {exc}", file=sys.stderr)
                return 2

        try:
            gate_result = guard_payment(
                request_data,
                policy,
                store=store,
                expected_amount=args.expected_amount,
                auto_approve_ask=args.auto_approve_ask,
                signed_payload=signed_data,
            )
        except (ValueError, TypeError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

        if args.interactive and gate_result.result.decision is Verdict.ASK:
            gate_result = interactive_approve(
                gate_result, input_stream=sys.stdin, output_stream=sys.stderr
            )
            if not gate_result.allowed:
                print(json.dumps(gate_result.to_dict(), sort_keys=True))
                return EXIT_REJECTED
        elif args.approve and gate_result.result.decision is Verdict.ASK:
            gate_result = approve(gate_result)

        if args.log is not None:
            try:
                _write_jsonl(
                    args.log,
                    {
                        "timestamp": _now(),
                        "allowed": gate_result.allowed,
                        "approved": gate_result.approved,
                        "decision": gate_result.result.decision.value,
                        "rule": gate_result.result.rule,
                        "reason": gate_result.result.reason,
                        "signed_payload_present": signed_data is not None,
                    },
                )
            except OSError as exc:
                print(f"error: failed to write log: {exc}", file=sys.stderr)
                return 2

        print(json.dumps(gate_result.to_dict(), sort_keys=True))

        if gate_result.allowed:
            return EXIT_OK
        if gate_result.result.decision is Verdict.ASK:
            return EXIT_ASK
        return EXIT_DENY


if __name__ == "__main__":
    raise SystemExit(main())
