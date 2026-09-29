"""Data structures for the x402 payment firewall.

This module is dependency-free and uses only the Python standard library.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass
from typing import Any, Optional


class Verdict(str, enum.Enum):
    """The decision a validator can return."""

    PAY = "PAY"
    ASK = "ASK"
    DENY = "DENY"


class MalformedRequestError(ValueError):
    """Raised when a payment request object is missing/invalid fields."""


_REQUIRED_STRING_FIELDS = ("pay_to", "asset", "network", "payee", "nonce", "source_url")


@dataclass(frozen=True)
class PaymentRequest:
    """A validated x402 payment request.

    Fields:
        pay_to: destination address.
        amount: payment amount in human units (USDC), > 0.
        asset: asset id, canonical value "USDC".
        network: network id, canonical value "Base".
        payee: payee identity/name.
        nonce: one-time nonce.
        description: merchant-provided description (untrusted text).
        source_url: the URL that issued the 402.
    """

    pay_to: str
    amount: float
    asset: str
    network: str
    payee: str
    nonce: str
    description: str
    source_url: str

    @classmethod
    def from_dict(cls, data: Any) -> "PaymentRequest":
        """Build a PaymentRequest from a JSON-decoded object, validating fields."""
        if not isinstance(data, dict):
            raise MalformedRequestError("request must be a JSON object")

        for field in _REQUIRED_STRING_FIELDS:
            if field not in data:
                raise MalformedRequestError(f"missing required field '{field}'")
            value = data[field]
            if not isinstance(value, str):
                raise MalformedRequestError(
                    f"field '{field}' must be a string, got {type(value).__name__}"
                )
            if not value.strip():
                raise MalformedRequestError(f"field '{field}' must be non-empty")

        if "amount" not in data:
            raise MalformedRequestError("missing required field 'amount'")
        amount = data["amount"]
        if isinstance(amount, bool) or not isinstance(amount, (int, float)):
            raise MalformedRequestError(
                f"field 'amount' must be a number, got {type(amount).__name__}"
            )
        if amount <= 0:
            raise MalformedRequestError(f"amount must be > 0, got {amount}")

        if "description" not in data:
            raise MalformedRequestError("missing required field 'description'")
        description = data["description"]
        if not isinstance(description, str):
            raise MalformedRequestError(
                f"field 'description' must be a string, got {type(description).__name__}"
            )

        return cls(
            pay_to=data["pay_to"],
            amount=float(amount),
            asset=data["asset"],
            network=data["network"],
            payee=data["payee"],
            nonce=data["nonce"],
            description=description,
            source_url=data["source_url"],
        )


@dataclass(frozen=True)
class Result:
    """A firewall decision.

    Fields:
        decision: PAY | ASK | DENY.
        reason: human-readable explanation.
        rule: id/name of the matched rule (optional).
    """

    decision: Verdict
    reason: str
    rule: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "decision": self.decision.value,
            "reason": self.reason,
            "rule": self.rule,
        }
