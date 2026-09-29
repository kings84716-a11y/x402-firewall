"""End-to-end x402 purchase flow with a simulated transport and settler.

This module drives the full x402 purchase loop with the firewall as the
mandatory decision point. Because tests must not hit the network, the transport
is an injectable interface and an in-memory server simulation is provided; the
settler is likewise an injectable interface with an in-memory fake that records
settlements without any crypto or keys.

Flow:

1. The client requests a resource (URL + optional expected amount).
2. The transport replies either ``200`` with the resource, or
   ``402 Payment Required`` carrying a payment-request payload (and optionally a
   structured signed payload).
3. The client normalizes the payload into a :class:`PaymentRequest`, calls
   ``guard_payment``, and branches on the verdict:
       * ``PAY``  -> settle.
       * ``ASK``  -> do not settle by default; if an approval handler is
         supplied, invoke it and settle only if the human approves.
       * ``DENY`` -> abort and return a structured ``blocked`` outcome.
4. Settlement is centralized behind :meth:`Client._settle`, which refuses to call
   the settler unless the gate result is allowed. There is no code path that can
   reach the settler without an allowed :class:`GateResult`.
5. After settlement the client re-requests the resource and returns a final
   :class:`ClientOutcome`.

``Transport`` and ``Settler`` are small ABCs so a real HTTP transport and a real
on-chain settler can be dropped in later without changing the orchestrator.
"""

from __future__ import annotations

import itertools
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Callable, Optional, Union

from .gate import GateResult, PaymentBlockedError, guard_payment
from .models import Verdict
from .policy import PolicyConfig
from .store import Store

# Final outcome statuses.
STATUS_NOT_REQUIRED = "not_required"
STATUS_PAID = "paid"
STATUS_BLOCKED = "blocked"
STATUS_REJECTED = "rejected"
STATUS_AWAITING = "awaiting"

# An approval handler turns a (blocked) ASK GateResult into an allowed one, or
# returns it still-blocked to reject. ``approve`` and ``interactive_approve``
# both satisfy this signature.
ApprovalHandler = Callable[[GateResult], GateResult]


class Transport(ABC):
    """Protocol for fetching a resource, possibly replying ``402``.

    A real HTTP client transport would implement this by performing a request
    and returning the HTTP status + body. The in-memory simulation is
    :class:`InMemoryServer`.
    """

    @abstractmethod
    def request(self, url: str) -> "TransportResponse":
        raise NotImplementedError


class Settler(ABC):
    """Protocol for settling an allowed payment.

    A real implementation would sign and broadcast an on-chain transaction and
    return a transaction/reference id. The in-memory fake is
    :class:`FakeSettler`, which does no crypto and returns a synthetic id.
    """

    @abstractmethod
    def settle(self, authorization: dict) -> str:
        raise NotImplementedError


@dataclass
class TransportResponse:
    """The result of a transport request.

    ``status`` is ``200`` (resource available) or ``402`` (payment required).
    ``body`` is the resource (for 200) or the payment-request payload (for 402).
    ``signed_payload`` is the optional structured signed payload carried by a 402.
    """

    status: int
    body: Any = None
    signed_payload: Optional[dict] = None


@dataclass
class ClientOutcome:
    """The final result of a purchase attempt."""

    status: str
    decision: Optional[str] = None
    rule: Optional[str] = None
    reason: Optional[str] = None
    settlement_reference: Optional[str] = None
    resource: Optional[Any] = None

    def to_dict(self) -> dict:
        return {
            "status": self.status,
            "decision": self.decision,
            "rule": self.rule,
            "reason": self.reason,
            "settlement_reference": self.settlement_reference,
            "resource": self.resource,
        }


class InMemoryServer(Transport):
    """In-memory simulation of a 402-capable server.

    Routes are registered either as free resources (always ``200``) or as paid
    resources (``402`` with a payment request until the request's nonce has been
    marked paid, then ``200`` with the resource). ``mark_paid`` is typically
    wired to a :class:`FakeSettler` so a settled payment makes the resource
    available.
    """

    def __init__(self) -> None:
        self._routes: dict = {}
        self._paid_nonces: set = set()
        self.request_count = 0

    def add_free_resource(self, url: str, resource: Any) -> None:
        self._routes[url] = {"kind": "free", "resource": resource}

    def add_paid_resource(
        self,
        url: str,
        payment_request: dict,
        resource: Any,
        signed_payload: Optional[dict] = None,
    ) -> None:
        self._routes[url] = {
            "kind": "paid",
            "payment_request": payment_request,
            "resource": resource,
            "signed_payload": signed_payload,
        }

    def mark_paid(self, nonce: str) -> None:
        self._paid_nonces.add(nonce)

    def request(self, url: str) -> TransportResponse:
        self.request_count += 1
        route = self._routes[url]
        if route["kind"] == "free":
            return TransportResponse(status=200, body=route["resource"])

        payment_request = route["payment_request"]
        if payment_request.get("nonce") in self._paid_nonces:
            return TransportResponse(status=200, body=route["resource"])

        return TransportResponse(
            status=402,
            body=payment_request,
            signed_payload=route["signed_payload"],
        )


class FakeSettler(Settler):
    """In-memory settler that simulates a successful settlement.

    Returns a synthetic transaction reference (no crypto, no keys) and records
    every settlement call. An optional ``on_settle`` callback receives the
    nonce; wiring it to :meth:`InMemoryServer.mark_paid` makes a settled payment
    "unlock" the resource on the next request.
    """

    def __init__(self, on_settle: Optional[Callable[[str], None]] = None) -> None:
        self._on_settle = on_settle
        self._counter = itertools.count(1)
        self.calls: list = []

    def settle(self, authorization: dict) -> str:
        reference = f"tx-{next(self._counter):04d}"
        self.calls.append((dict(authorization), reference))
        if self._on_settle is not None:
            self._on_settle(authorization.get("nonce"))
        return reference


class Client:
    """Orchestrates the x402 purchase loop around the firewall gate.

    ``settle`` can only be reached through :meth:`_settle`, which checks
    ``allowed`` and obtains the signing authorization (raising
    :class:`PaymentBlockedError` if blocked), so a settler cannot be invoked on a
    DENY or un-approved ASK.
    """

    def __init__(
        self,
        transport: Transport,
        settler: Settler,
        policy: Union[dict, PolicyConfig],
        store: Optional[Store] = None,
    ) -> None:
        self.transport = transport
        self.settler = settler
        self.policy = policy
        self.store = store

    def _settle(self, gate_result: GateResult) -> str:
        """Settle an allowed payment; raise ``PaymentBlockedError`` otherwise.

        This is the single choke point between the gate and the settler. It
        checks ``allowed`` and obtains the signing authorization (which itself
        raises unless allowed), so the settler is unreachable on any blocked
        path.
        """
        if not gate_result.allowed:
            raise PaymentBlockedError("cannot settle a blocked payment")
        authorization = gate_result.signing_authorization()
        return self.settler.settle(authorization)

    def run(
        self,
        url: str,
        expected_amount: Optional[float] = None,
        approval_handler: Optional[ApprovalHandler] = None,
    ) -> ClientOutcome:
        """Run one full purchase attempt and return a :class:`ClientOutcome`."""
        first = self.transport.request(url)

        if first.status == 200:
            return ClientOutcome(status=STATUS_NOT_REQUIRED, resource=first.body)

        request = first.body
        gate_result = guard_payment(
            request,
            self.policy,
            store=self.store,
            expected_amount=expected_amount,
            signed_payload=first.signed_payload,
        )

        if gate_result.allowed:
            reference = self._settle(gate_result)
            final = self.transport.request(url)
            return ClientOutcome(
                status=STATUS_PAID,
                decision=gate_result.result.decision.value,
                rule=gate_result.result.rule,
                reason=gate_result.result.reason,
                settlement_reference=reference,
                resource=final.body if final.status == 200 else None,
            )

        if gate_result.result.decision is Verdict.ASK:
            if approval_handler is None:
                return ClientOutcome(
                    status=STATUS_AWAITING,
                    decision=gate_result.result.decision.value,
                    rule=gate_result.result.rule,
                    reason=gate_result.result.reason,
                )

            approved = approval_handler(gate_result)
            if approved.allowed:
                reference = self._settle(approved)
                final = self.transport.request(url)
                return ClientOutcome(
                    status=STATUS_PAID,
                    decision=approved.result.decision.value,
                    rule=approved.result.rule,
                    reason=approved.result.reason,
                    settlement_reference=reference,
                    resource=final.body if final.status == 200 else None,
                )

            return ClientOutcome(
                status=STATUS_REJECTED,
                decision=gate_result.result.decision.value,
                rule=gate_result.result.rule,
                reason=gate_result.result.reason,
            )

        return ClientOutcome(
            status=STATUS_BLOCKED,
            decision=gate_result.result.decision.value,
            rule=gate_result.result.rule,
            reason=gate_result.result.reason,
        )
