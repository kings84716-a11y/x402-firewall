"""The hard signing gate for the x402 payment firewall.

This is the single choke point an agent calls immediately before signing a
payment. It wraps :func:`x402_firewall.policy.evaluate_payment_request` and
enforces the authorization contract:

* ``PAY``  -> allowed.
* ``ASK``  -> blocked unless an explicit human approval is granted.
* ``DENY`` -> always blocked.

Every gate decision is persisted to the store's audit table, and the only way
to obtain signing authorization is through :meth:`GateResult.signing_authorization`,
which raises :class:`PaymentBlockedError` unless the payment is allowed. This is
pure data: no blockchain signing and no private keys live here.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Any, Optional, Union

from .models import PaymentRequest, Verdict, Result, MalformedRequestError
from .policy import evaluate_payment_request, _coerce_request
from .store import Store


class PaymentBlockedError(RuntimeError):
    """Raised when signing authorization is requested for a blocked payment."""


def _fingerprint(request: Any) -> str:
    """Deterministic SHA-256 fingerprint of a (possibly raw) request."""
    if isinstance(request, PaymentRequest):
        payload = {
            "pay_to": request.pay_to,
            "amount": request.amount,
            "asset": request.asset,
            "network": request.network,
            "payee": request.payee,
            "nonce": request.nonce,
            "description": request.description,
            "source_url": request.source_url,
        }
    else:
        payload = request
    raw = json.dumps(payload, sort_keys=True, default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _safe_fields(request: Any):
    """Extract (amount, pay_to, payee, nonce) defensively, tolerating malformed input."""
    if isinstance(request, PaymentRequest):
        return request.amount, request.pay_to, request.payee, request.nonce
    if isinstance(request, dict):
        amount = request.get("amount")
        if isinstance(amount, bool) or not isinstance(amount, (int, float)):
            amount = None
        else:
            amount = float(amount)
        pay_to = request.get("pay_to") if isinstance(request.get("pay_to"), str) else None
        payee = request.get("payee") if isinstance(request.get("payee"), str) else None
        nonce = request.get("nonce") if isinstance(request.get("nonce"), str) else None
        return amount, pay_to, payee, nonce
    return None, None, None, None


def _rich_fields(request: Any) -> dict:
    """Defensively extract all audit fields, tolerating malformed input."""
    amount, pay_to, payee, nonce = _safe_fields(request)
    fields = {
        "amount": amount,
        "pay_to": pay_to,
        "payee": payee,
        "nonce": nonce,
        "asset": None,
        "network": None,
        "source_url": None,
    }
    if isinstance(request, PaymentRequest):
        fields["asset"] = request.asset
        fields["network"] = request.network
        fields["source_url"] = request.source_url
    elif isinstance(request, dict):
        fields["asset"] = request.get("asset") if isinstance(request.get("asset"), str) else None
        fields["network"] = request.get("network") if isinstance(request.get("network"), str) else None
        fields["source_url"] = request.get("source_url") if isinstance(request.get("source_url"), str) else None
    return fields


@dataclass
class GateResult:
    """The outcome of the signing gate.

    ``allowed`` is the single unambiguous boolean; when False, the payment must
    not be signed. ``result`` is the underlying :class:`Result`.
    """

    allowed: bool
    result: Result
    request: Optional[PaymentRequest]
    approved: bool
    store: Optional[Store] = field(default=None, repr=False, compare=False)

    def to_dict(self) -> dict:
        return {
            "allowed": self.allowed,
            "approved": self.approved,
            "decision": self.result.decision.value,
            "reason": self.result.reason,
            "rule": self.result.rule,
        }

    def signing_authorization(self) -> dict:
        """Return the signing arguments, raising unless the payment is allowed.

        This is the only way to obtain the data needed to proceed; calling code
        cannot accidentally sign on a DENY/ASK verdict.
        """
        if not self.allowed:
            raise PaymentBlockedError(
                f"payment blocked ({self.result.decision.value}): {self.result.reason}"
            )
        assert self.request is not None
        return {
            "pay_to": self.request.pay_to,
            "amount": self.request.amount,
            "asset": self.request.asset,
            "network": self.request.network,
            "payee": self.request.payee,
            "nonce": self.request.nonce,
        }


def _audit(
    store: Optional[Store],
    gr: "GateResult",
    fingerprint: str,
    signed_payload_present: bool = False,
    decision_duration_ms: Optional[int] = None,
) -> None:
    if store is None:
        return
    fields = _rich_fields(gr.request)
    store.record_decision(
        request_fingerprint=fingerprint,
        verdict=gr.result.decision.value,
        rule=gr.result.rule,
        reason=gr.result.reason,
        amount=fields["amount"],
        pay_to=fields["pay_to"],
        payee=fields["payee"],
        nonce=fields["nonce"],
        asset=fields["asset"],
        network=fields["network"],
        source_url=fields["source_url"],
        signed_payload_present=signed_payload_present,
        decision_duration_ms=decision_duration_ms,
        approved=gr.approved,
    )


def guard_payment(
    request: Union[dict, PaymentRequest],
    policy: Union[dict, Any],
    store: Optional[Store] = None,
    expected_amount: Optional[float] = None,
    auto_approve_ask: bool = False,
    signed_payload: Optional[Union[dict, Any]] = None,
) -> GateResult:
    """Evaluate a request and enforce the signing-gate contract.

    Returns a :class:`GateResult` with an unambiguous ``allowed`` flag. Every
    decision (PAY/ASK/DENY) is persisted to ``store``'s audit table.

    ``signed_payload`` (optional) is cross-checked for consistency with the
    request fields before PAY is allowed.
    """
    start = time.perf_counter()
    result = evaluate_payment_request(
        request,
        policy,
        expected_amount,
        store=store,
        signed_payload=signed_payload,
    )
    decision_duration_ms = int((time.perf_counter() - start) * 1000)

    try:
        req = _coerce_request(request)
    except MalformedRequestError:
        req = None

    if result.decision is Verdict.PAY:
        allowed = True
        approved = False
    elif result.decision is Verdict.ASK:
        allowed = bool(auto_approve_ask)
        approved = bool(auto_approve_ask)
    else:
        allowed = False
        approved = False

    gr = GateResult(
        allowed=allowed,
        result=result,
        request=req,
        approved=approved,
        store=store,
    )
    _audit(
        store,
        gr,
        _fingerprint(request),
        signed_payload_present=signed_payload is not None,
        decision_duration_ms=decision_duration_ms,
    )
    return gr


def approve(gate_result: GateResult) -> GateResult:
    """Record an explicit human approval for an ASK verdict and allow it.

    DENY can never be approved (stays blocked). PAY is already allowed (no-op).
    Returns a new :class:`GateResult` reflecting the updated authorization.
    """
    if gate_result.result.decision is not Verdict.ASK:
        return GateResult(
            allowed=gate_result.result.decision is Verdict.PAY,
            result=gate_result.result,
            request=gate_result.request,
            approved=gate_result.approved,
            store=gate_result.store,
        )

    # ASK: grant approval, record it in the audit trail, and commit the spend
    # to the persistent ledger so a human-approved purchase is reflected there.
    if gate_result.store is not None:
        fields = _rich_fields(gate_result.request)
        gate_result.store.record_decision(
            request_fingerprint=_fingerprint(gate_result.request),
            verdict="ASK",
            rule=gate_result.result.rule,
            reason=gate_result.result.reason,
            amount=fields["amount"],
            pay_to=fields["pay_to"],
            payee=fields["payee"],
            nonce=fields["nonce"],
            asset=fields["asset"],
            network=fields["network"],
            source_url=fields["source_url"],
            approved=True,
        )
        if gate_result.request is not None:
            gate_result.store.record_spend(
                gate_result.request.amount,
                gate_result.request.asset,
                gate_result.request.network,
                gate_result.request.pay_to,
                gate_result.request.payee,
                gate_result.request.nonce,
            )
    return GateResult(
        allowed=True,
        result=gate_result.result,
        request=gate_result.request,
        approved=True,
        store=gate_result.store,
    )
