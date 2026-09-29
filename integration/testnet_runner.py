"""Testnet orchestrator: wire the firewall gate in front of real SDK signing.

This module drives the closed loop ``request -> 402 -> firewall -> EIP-3009
sign -> facilitator verify -> settle -> resource`` for the Base Sepolia
testnet, **without importing the x402 SDK itself**. The SDK-dependent pieces
(signer + facilitator transport) are injected, so this module stays importable
in the stdlib-only environment where the firewall's unit tests run.

The single hard requirement is enforced here: the signer/facilitator are
unreachable unless the firewall gate returned an allowed verdict. The only way
the signer is reached is through :meth:`GateResult.signing_authorization`, which
raises :class:`x402_firewall.PaymentBlockedError` unless the payment is allowed.
"""

from __future__ import annotations

import base64
import json
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Callable, Optional, Union

from x402_firewall import (
    CAIP2_BASE_SEPOLIA,
    GateResult,
    PaymentOption,
    PaymentRequired,
    PolicyConfig,
    Resource,
    Store,
    Verdict,
    approve,
    guard_payment,
    option_to_request,
    parse_payment_required_header,
    select_option,
)

# ApprovalHandler mirrors x402_firewall.client.ApprovalHandler: turns a blocked
# ASK GateResult into an allowed one (or leaves it blocked to reject).
ApprovalHandler = Callable[[GateResult], GateResult]


class Signer(ABC):
    """Builds a signed x402 payment payload for one payment option.

    The concrete implementation (``integration.sdk_adapter.Eip3009Signer``) uses
    the official x402 SDK to produce an EIP-3009 ``transferWithAuthorization``
    EIP-712 signature. Offline tests inject a fake that only records calls.
    """

    @abstractmethod
    def sign(self, option: PaymentOption, resource: Resource) -> dict:
        """Return the signed inner payment payload dict for ``option``."""
        raise NotImplementedError


class Facilitator(ABC):
    """Verifies and settles a signed payment through a facilitator.

    The concrete implementation (``integration.sdk_adapter.FacilitatorClient``)
    posts to the free facilitator at ``https://x402.org/facilitator``. Offline
    tests inject a fake that only records calls.
    """

    @abstractmethod
    def verify(self, option: PaymentOption, resource: Resource, inner_payload: dict) -> dict:
        """Verify the signed payment; return a dict with at least ``is_valid``."""
        raise NotImplementedError

    @abstractmethod
    def settle(self, option: PaymentOption, resource: Resource, inner_payload: dict) -> dict:
        """Settle the signed payment; return a dict with ``transaction``/``network``."""
        raise NotImplementedError


@dataclass
class TestnetOutcome:
    """Structured result of one testnet purchase attempt."""

    decision: str
    rule: str
    reason: str
    allowed: bool
    approved: bool
    signed: bool
    signer_calls: int
    pay_to: Optional[str] = None
    amount: Optional[float] = None
    asset: Optional[str] = None
    network: Optional[str] = None
    verify: Optional[dict] = None
    settle: Optional[dict] = None
    tx_hash: Optional[str] = None
    resource: Optional[Any] = None
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "decision": self.decision,
            "rule": self.rule,
            "reason": self.reason,
            "allowed": self.allowed,
            "approved": self.approved,
            "signed": self.signed,
            "signer_calls": self.signer_calls,
            "pay_to": self.pay_to,
            "amount": self.amount,
            "asset": self.asset,
            "network": self.network,
            "verify": self.verify,
            "settle": self.settle,
            "tx_hash": self.tx_hash,
            "resource": self.resource,
            **self.extra,
        }


class TestnetRunner:
    """Orchestrates a testnet purchase through the firewall gate.

    ``signer`` and ``facilitator`` are injected (SDK-backed for live runs, fakes
    for offline tests). ``store`` is the same persistent :class:`Store` used by
    the firewall, so a live run appears in the same audit trail.
    """

    def __init__(
        self,
        signer: Signer,
        facilitator: Facilitator,
        policy: Union[dict, PolicyConfig],
        store: Optional[Store] = None,
        approval_handler: Optional[ApprovalHandler] = None,
        desired_network: str = CAIP2_BASE_SEPOLIA,
    ) -> None:
        self.signer = signer
        self.facilitator = facilitator
        self.policy = policy
        self.store = store
        self.approval_handler = approval_handler
        self.desired_network = desired_network

    # -- core, offline-testable path -----------------------------------------
    def process(
        self,
        payment_required: PaymentRequired,
        expected_amount: Optional[float] = None,
    ) -> TestnetOutcome:
        """Parse/select an option, gate it, and sign+settle only when allowed.

        ``payment_required`` is the decoded v2 payload produced by our
        ``x402_firewall.wire`` parser (never the SDK's own parser).
        """
        option = select_option(payment_required, desired_network=self.desired_network)
        request = option_to_request(option, payment_required.resource)

        gate = guard_payment(
            request,
            self.policy,
            store=self.store,
            expected_amount=expected_amount,
        )

        if gate.allowed:
            return self._pay(gate, option, payment_required.resource)

        if gate.result.decision is Verdict.ASK:
            if self.approval_handler is None:
                return self._outcome(gate, signed=False)
            approved = self.approval_handler(gate)
            if approved.allowed:
                return self._pay(approved, option, payment_required.resource)
            return self._outcome(approved, signed=False)

        return self._outcome(gate, signed=False)

    def _pay(
        self,
        gate: GateResult,
        option: PaymentOption,
        resource: Resource,
    ) -> TestnetOutcome:
        """Sign + verify + settle an allowed payment.

        ``signing_authorization()`` is the single choke point: it raises
        :class:`PaymentBlockedError` unless the gate is allowed, so the signer
        and facilitator below are unreachable on any blocked verdict.
        """
        gate.signing_authorization()  # raises unless allowed
        inner = self.signer.sign(option, resource)
        verify = self.facilitator.verify(option, resource, inner)
        outcome = self._outcome(gate, signed=True)
        outcome.verify = verify

        # A real x402 flow settles only after a successful verify. Guard on the
        # verification result so a failed verify never reaches the facilitator's
        # settle endpoint (and never fabricates a transaction).
        if not (isinstance(verify, dict) and verify.get("is_valid")):
            return outcome

        settle = self.facilitator.settle(option, resource, inner)
        outcome.settle = settle
        outcome.tx_hash = settle.get("transaction") if isinstance(settle, dict) else None
        if settle and isinstance(settle, dict) and settle.get("success"):
            outcome.resource = resource.url
        return outcome

    def _outcome(self, gate: GateResult, signed: bool) -> TestnetOutcome:
        req = gate.request
        return TestnetOutcome(
            decision=gate.result.decision.value,
            rule=gate.result.rule or "",
            reason=gate.result.reason,
            allowed=gate.allowed,
            approved=gate.approved,
            signed=signed,
            signer_calls=self._signer_call_count(),
            pay_to=getattr(req, "pay_to", None),
            amount=getattr(req, "amount", None),
            asset=getattr(req, "asset", None),
            network=getattr(req, "network", None),
        )

    def _signer_call_count(self) -> int:
        calls = getattr(self.signer, "calls", None)
        return len(calls) if isinstance(calls, list) else 0

    # -- live transport wrapper ---------------------------------------------
    def run(
        self,
        url: str,
        expected_amount: Optional[float] = None,
        fetch: Optional[Callable[[str], "FetchResult"]] = None,
    ) -> TestnetOutcome:
        """Fetch a URL, parse a real 402 ``payment-required`` header, and process it.

        A ``200`` response short-circuits to a ``not_required`` outcome. On a
        ``402``, the header is parsed with our wire parser and handed to
        :meth:`process`. ``fetch`` is injectable for tests; the default is a
        real HTTP GET via stdlib ``urllib``.
        """
        fetcher = fetch or _urllib_fetch
        result = fetcher(url)

        if result.status == 200:
            return TestnetOutcome(
                decision="PAY",
                rule="not_required",
                reason="resource returned 200 (no payment required)",
                allowed=True,
                approved=False,
                signed=False,
                signer_calls=0,
                resource=result.body,
            )

        if result.status != 402:
            return TestnetOutcome(
                decision="DENY",
                rule="http_error",
                reason=f"unexpected HTTP status {result.status}",
                allowed=False,
                approved=False,
                signed=False,
                signer_calls=0,
            )

        header_value = result.body
        if not isinstance(header_value, str):
            return TestnetOutcome(
                decision="DENY",
                rule="malformed",
                reason="402 response had no payment-required header",
                allowed=False,
                approved=False,
                signed=False,
                signer_calls=0,
            )

        payment_required = parse_payment_required_header(header_value)
        return self.process(payment_required, expected_amount=expected_amount)


@dataclass
class FetchResult:
    """Result of a transport fetch: HTTP status + body.

    For ``402``, ``body`` is the raw ``payment-required`` header value (base64).
    For ``200``, ``body`` is the resource.
    """

    status: int
    body: Any = None


def _urllib_fetch(url: str) -> FetchResult:
    request = urllib.request.Request(url, method="GET", headers={"Accept": "application/json"})
    try:
        response = urllib.request.urlopen(request, timeout=15.0)
    except urllib.error.HTTPError as exc:
        response = exc

    status = response.status
    try:
        if status == 402:
            for key, value in response.headers.items():
                if key.lower() == "payment-required":
                    response.read()
                    return FetchResult(status=402, body=value)
            response.read()
            return FetchResult(status=402, body=None)
        body = response.read().decode("utf-8")
        try:
            body = json.loads(body)
        except json.JSONDecodeError:
            pass
        return FetchResult(status=status, body=body)
    finally:
        try:
            response.close()
        except Exception:
            pass


def decode_header_for_debug(header_value: str) -> dict:
    """Base64-decode a payment-required header for logging (never signing)."""
    return json.loads(base64.b64decode(header_value, validate=True).decode("utf-8"))
