"""Policy evaluation and prompt-injection scanning for the x402 firewall.

This module is dependency-free and uses only the Python standard library.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple, Union, TYPE_CHECKING

from .models import (
    PaymentRequest,
    Verdict,
    Result,
    MalformedRequestError,
)

if TYPE_CHECKING:
    from .store import Store

# Small epsilon for float amount comparison.
AMOUNT_EPSILON = 1e-9

CANONICAL_ASSET = "usdc"
CANONICAL_NETWORK = "base"


# ---------------------------------------------------------------------------
# Prompt-injection heuristic patterns.
#
# Each entry is (name, compiled_regex). Matching is case-insensitive and uses
# word boundaries so that benign phrasing is not over-flagged. Extend this list
# to add new detection heuristics.
# ---------------------------------------------------------------------------
PROMPT_INJECTION_PATTERNS: List[Tuple[str, "re.Pattern[str]"]] = [
    (
        "ignore_instructions",
        re.compile(
            r"\bignore\s+(all|any|the|my|our|previous|prior|above|earlier)?\s*instructions?\b",
            re.IGNORECASE,
        ),
    ),
    (
        "disregard_instructions",
        re.compile(
            r"\bdisregard\s+(all|any|the|my|our|previous|prior|above|earlier)?\s*instructions?\b",
            re.IGNORECASE,
        ),
    ),
    (
        "you_are",
        re.compile(r"\byou\s+are\s+(now\s+)?(an?|the)\b", re.IGNORECASE),
    ),
    (
        "new_instructions",
        re.compile(r"\bnew\s+instructions?\b", re.IGNORECASE),
    ),
    (
        "system_prompt",
        re.compile(r"\bsystem\s*prompt\b", re.IGNORECASE),
    ),
    (
        "role_marker",
        re.compile(
            r"\[(system|user|assistant|developer|tool|function)\]"
            r"|</?\s*(system|user|assistant|developer|tool|function)\s*>",
            re.IGNORECASE,
        ),
    ),
    (
        "exfiltration",
        re.compile(
            r"\b(reveal|leak|exfiltrate|expose|print|show|dump|repeat|output|send|display)\b"
            r"[^.!?\n]{0,60}?\b(prompt|instructions?|secret|api[ _-]?key|system|credentials|token|private[ _-]?key)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "base64",
        re.compile(r"\bbase64\b", re.IGNORECASE),
    ),
    (
        "system_message",
        re.compile(r"\bsystem\s+message\b", re.IGNORECASE),
    ),
    (
        "pretend",
        re.compile(r"\bpretend\s+(to\s+be|you\s+are)\b", re.IGNORECASE),
    ),
    (
        "act_as",
        re.compile(r"\bact\s+as\b", re.IGNORECASE),
    ),
    (
        "jailbreak",
        re.compile(r"\bjailbreak\b", re.IGNORECASE),
    ),
    (
        "developer_mode",
        re.compile(r"\bdeveloper\s+mode\b", re.IGNORECASE),
    ),
]


def scan_description(description: str) -> Optional[str]:
    """Return the name of the first matched injection pattern, or None.

    Case-insensitive, word-boundary tolerant heuristic scan of untrusted
    merchant text.
    """
    if not description:
        return None
    for name, pattern in PROMPT_INJECTION_PATTERNS:
        if pattern.search(description):
            return name
    return None


@dataclass
class PolicyConfig:
    """Local policy used to evaluate a payment request.

    Fields:
        allowed_addresses: whitelist of acceptable `pay_to` addresses.
        max_amount: per-request budget.
        total_budget: maximum cumulative approved spend across the ledger;
            ``None`` means unlimited (the default).
        ask_on_unknown_address: when True, unknown `pay_to` yields ASK instead
            of DENY.
        seen_nonces: in-memory set of already-approved nonces (replay detection),
            used only when no persistent store is supplied.
    """

    allowed_addresses: Set[str] = field(default_factory=set)
    max_amount: float = 1.0
    total_budget: Optional[float] = None
    ask_on_unknown_address: bool = False
    seen_nonces: Set[str] = field(default_factory=set)
    _spent_total: float = field(default=0.0, repr=False, compare=False)

    @classmethod
    def from_dict(cls, data: Any) -> "PolicyConfig":
        if not isinstance(data, dict):
            raise ValueError("policy must be a JSON object")

        allowed = data.get("allowed_addresses", [])
        if not isinstance(allowed, list):
            raise ValueError("policy 'allowed_addresses' must be a list of strings")
        allowed_addresses = set()
        for addr in allowed:
            if not isinstance(addr, str):
                raise ValueError("policy 'allowed_addresses' entries must be strings")
            allowed_addresses.add(addr.strip().lower())

        max_amount = data.get("max_amount", 1.0)
        if isinstance(max_amount, bool) or not isinstance(max_amount, (int, float)):
            raise ValueError("policy 'max_amount' must be a number")
        if max_amount <= 0:
            raise ValueError("policy 'max_amount' must be > 0")

        total_budget = data.get("total_budget", None)
        if total_budget is not None:
            if isinstance(total_budget, bool) or not isinstance(total_budget, (int, float)):
                raise ValueError("policy 'total_budget' must be a number or null")
            if total_budget <= 0:
                raise ValueError("policy 'total_budget' must be > 0")

        ask_on_unknown = data.get("ask_on_unknown_address", False)
        if not isinstance(ask_on_unknown, bool):
            raise ValueError("policy 'ask_on_unknown_address' must be a boolean")

        return cls(
            allowed_addresses=allowed_addresses,
            max_amount=float(max_amount),
            total_budget=None if total_budget is None else float(total_budget),
            ask_on_unknown_address=ask_on_unknown,
        )


def _coerce_request(request: Union[dict, PaymentRequest]) -> PaymentRequest:
    """Normalize a dict or PaymentRequest into a validated PaymentRequest."""
    if isinstance(request, PaymentRequest):
        # Re-validate so a hand-built object can't bypass the checks.
        return PaymentRequest.from_dict(asdict(request))
    return PaymentRequest.from_dict(request)


def _coerce_policy(policy: Union[dict, PolicyConfig]) -> PolicyConfig:
    if isinstance(policy, PolicyConfig):
        return policy
    return PolicyConfig.from_dict(policy)


def _record_nonce(
    pol: PolicyConfig, store: Optional["Store"], req: PaymentRequest, decision: str
) -> None:
    """Record a consumed nonce on an ASK verdict (no spend is added)."""
    pol.seen_nonces.add(req.nonce)
    if store is not None:
        store.record_nonce(req.nonce, req.pay_to, req.amount, decision)


def _total_budget_reason(already: float, amount: float, cap: float) -> str:
    return (
        f"cumulative spend {already + amount} would exceed total budget {cap} "
        f"(already spent {already}, request amount {amount})"
    )


def evaluate_payment_request(
    request: Union[dict, PaymentRequest],
    policy: Union[dict, PolicyConfig],
    expected_amount: Optional[float] = None,
    store: Optional["Store"] = None,
) -> Result:
    """Evaluate a payment request against the policy and return a decision.

    Rules are evaluated in order; the first hit decides:

    1. malformed request            -> DENY
    2. asset/network mismatch       -> DENY
    3. unknown pay_to address       -> ASK (if ask_on_unknown_address) else DENY
    4. amount over budget           -> DENY
    5. nonce replay                 -> DENY
    6. prompt injection             -> ASK
    7. amount tampering             -> DENY (when expected_amount supplied)
    8. cumulative total_budget      -> DENY (when configured and exceeded)
    9. all checks pass              -> PAY

    ``store`` is an optional persistent :class:`~x402_firewall.store.Store`
    injected for cross-process nonce/spend tracking. When ``None``, replay
    detection and cumulative spend fall back to in-memory state on the policy.
    """
    try:
        req = _coerce_request(request)
    except MalformedRequestError as exc:
        return Result(Verdict.DENY, str(exc), "malformed")

    pol = _coerce_policy(policy)

    # Rule 2: asset/network mismatch (case-insensitive).
    asset = req.asset.strip().lower()
    network = req.network.strip().lower()
    if asset != CANONICAL_ASSET or network != CANONICAL_NETWORK:
        return Result(
            Verdict.DENY,
            f"unsupported asset/network '{req.asset}' on '{req.network}' "
            f"(only USDC on Base is allowed)",
            "asset_network",
        )

    # Rule 3: pay_to address whitelist.
    pay_to_key = req.pay_to.strip().lower()
    if pay_to_key not in pol.allowed_addresses:
        if pol.ask_on_unknown_address:
            _record_nonce(pol, store, req, "ASK")
            return Result(
                Verdict.ASK,
                f"pay_to address '{req.pay_to}' is not in the allowed addresses",
                "unknown_address",
            )
        return Result(
            Verdict.DENY,
            f"pay_to address '{req.pay_to}' is not in the allowed addresses",
            "unknown_address",
        )

    # Rule 4: over budget (per-request).
    if req.amount > pol.max_amount:
        return Result(
            Verdict.DENY,
            f"amount {req.amount} exceeds budget {pol.max_amount}",
            "over_budget",
        )

    # Rule 5: nonce replay (in-memory and/or persistent store).
    if req.nonce in pol.seen_nonces or (
        store is not None and store.nonce_seen(req.nonce)
    ):
        return Result(
            Verdict.DENY,
            f"nonce '{req.nonce}' was already seen (replay)",
            "nonce_replay",
        )

    # Rule 6: prompt-injection scan.
    hit = scan_description(req.description)
    if hit is not None:
        _record_nonce(pol, store, req, "ASK")
        return Result(
            Verdict.ASK,
            f"description triggers prompt-injection heuristic '{hit}'",
            "prompt_injection",
        )

    # Rule 7: expected amount tampering (epsilon comparison).
    if expected_amount is not None:
        if isinstance(expected_amount, bool) or not isinstance(expected_amount, (int, float)):
            return Result(
                Verdict.DENY,
                f"expected_amount must be a number, got {type(expected_amount).__name__}",
                "malformed",
            )
        if abs(req.amount - expected_amount) > AMOUNT_EPSILON:
            return Result(
                Verdict.DENY,
                f"amount {req.amount} does not match expected amount {expected_amount}",
                "amount_tampering",
            )

    # Rule 8: cumulative spend budget.
    if pol.total_budget is not None:
        already = store.total_spent() if store is not None else pol._spent_total
        if already + req.amount > pol.total_budget:
            return Result(
                Verdict.DENY,
                _total_budget_reason(already, req.amount, pol.total_budget),
                "total_budget",
            )

    # Rule 9: all checks passed -> PAY.
    if store is not None:
        ok, rule, already = store.record_pay(
            req.nonce,
            req.pay_to,
            req.amount,
            req.asset,
            req.network,
            req.payee,
            total_budget=pol.total_budget,
        )
        if not ok:
            if rule == "nonce_replay":
                return Result(
                    Verdict.DENY,
                    f"nonce '{req.nonce}' was already seen (replay)",
                    "nonce_replay",
                )
            if rule == "total_budget":
                return Result(
                    Verdict.DENY,
                    _total_budget_reason(already, req.amount, pol.total_budget),
                    "total_budget",
                )
    else:
        pol._spent_total += req.amount

    pol.seen_nonces.add(req.nonce)
    return Result(
        Verdict.PAY,
        f"approved payment of {req.amount} USDC on Base to '{req.payee}'",
        "valid",
    )
