"""Interactive human approval for ASK verdicts.

When the firewall returns an ``ASK`` verdict the payment must not be signed
until a human explicitly approves it. This module presents a clear summary of
the request and prompts the user for a decision, reading from an injectable
input stream and writing to an injectable output stream so it is fully testable
without a real TTY (no hard-wired ``input()``).

Accepted answers are ``y``/``yes`` (approve) and ``n``/``no`` (reject). An
unrecognized answer re-prompts up to a bounded number of attempts, after which
the request is treated as rejected (safe default). EOF / a closed input stream
is also treated as rejected.
"""

from __future__ import annotations

import sys
from typing import Optional, TextIO

from .gate import GateResult, approve
from .models import Verdict

# Upper bound on how many times the user may enter an invalid answer before the
# request is rejected for safety.
MAX_PROMPTS = 3

# Accepted affirmative / negative answers (matched case-insensitively, trimmed).
_YES_ANSWERS = ("y", "yes")
_NO_ANSWERS = ("n", "no")


def format_summary(gate_result: GateResult) -> str:
    """Render a human-readable summary of the request awaiting approval."""
    lines = [
        "=== x402 payment request requires your approval ===",
    ]
    request = gate_result.request
    if request is not None:
        lines.append(f"  Payee:        {request.payee}")
        lines.append(f"  Amount:       {request.amount} {request.asset} on {request.network}")
        lines.append(f"  Destination:  {request.pay_to}")
        lines.append(f"  Nonce:        {request.nonce}")
        lines.append(f"  Source URL:   {request.source_url}")
        lines.append(f"  Description (UNTRUSTED): {request.description!r}")
    lines.append(f"  Flagged reason: {gate_result.result.reason}")
    if gate_result.result.rule:
        lines.append(f"  Rule:           {gate_result.result.rule}")
    lines.append("Approve this payment? [y/N] ")
    return "\n".join(lines)


def _write_prompt(output_stream: TextIO, text: str) -> None:
    output_stream.write(text)
    output_stream.flush()


def interactive_approve(
    gate_result: GateResult,
    input_stream: Optional[TextIO] = None,
    output_stream: Optional[TextIO] = None,
    max_attempts: int = MAX_PROMPTS,
) -> GateResult:
    """Prompt a human to approve or reject an ASK verdict.

    ``input_stream`` / ``output_stream`` default to ``sys.stdin`` /
    ``sys.stderr`` but are injectable for tests. Returns the (possibly approved)
    :class:`~x402_firewall.gate.GateResult`: ``allowed=True`` when the human
    approved (via :func:`x402_firewall.gate.approve`, which records the approval
    in the audit trail and commits spend), otherwise the original blocked result.

    PAY and DENY verdicts are returned unchanged (there is nothing to prompt
    for: PAY is already allowed, DENY can never be approved).
    """
    if gate_result.result.decision is not Verdict.ASK:
        return gate_result

    input_stream = sys.stdin if input_stream is None else input_stream
    output_stream = sys.stderr if output_stream is None else output_stream

    _write_prompt(output_stream, format_summary(gate_result))

    for _ in range(max_attempts):
        line = input_stream.readline()
        if line == "":
            # EOF / closed stream -> safe default: reject.
            output_stream.write("No input received (EOF); rejecting.\n")
            output_stream.flush()
            return gate_result

        answer = line.strip().lower()
        if answer in _YES_ANSWERS:
            return approve(gate_result)
        if answer in _NO_ANSWERS:
            return gate_result

        _write_prompt(
            output_stream,
            f"Unrecognized answer {answer!r}; please answer y/yes or n/no.\n"
            "Approve this payment? [y/N] ",
        )

    output_stream.write("Too many invalid answers; rejecting.\n")
    output_stream.flush()
    return gate_result
