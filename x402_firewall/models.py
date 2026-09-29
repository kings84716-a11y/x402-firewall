"""Data structures for the x402 payment firewall.

This module is dependency-free and uses only the Python standard library.
"""

from __future__ import annotations

import enum
import math
import re
from dataclasses import dataclass
from typing import Any, Optional


class Verdict(str, enum.Enum):
    """The decision a validator can return."""

    PAY = "PAY"
    ASK = "ASK"
    DENY = "DENY"


class MalformedRequestError(ValueError):
    """Raised when a payment request object is missing/invalid fields."""


_REQUIRED_STRING_FIELDS = ("pay_to", "asset", "network", "payee", "source_url")

# An EVM address must look like ``0x`` + 40 hex chars. EIP-55 mixed-case as
# well as all-lower/all-upper are accepted (checksum is not verified here).
_EVM_ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")


def is_valid_evm_address(value: Any) -> bool:
    """Return True if ``value`` looks like a valid EVM (Base) address."""
    return isinstance(value, str) and _EVM_ADDRESS_RE.match(value) is not None


def _parse_uint(value: Any) -> Optional[int]:
    """Parse an on-chain integer amount (int or digit-only string).

    Returns ``None`` on anything else (including bool, floats, negatives).
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, int) and value >= 0:
        return value
    if isinstance(value, str):
        s = value.strip()
        if s.isdigit():
            return int(s)
    return None


@dataclass(frozen=True)
class SignedPayload:
    """A structured representation of the signed (EIP-712-style) payload.

    Pure data — no crypto, no signatures. It carries the fields that must stay
    consistent with the validated request:

        recipient:  destination address (must equal request.pay_to).
        amount_raw: integer amount in base units (the on-chain integer form).
        decimals:   token decimals used to convert amount_raw to human units
                    (default 6 for USDC).
        asset:      optional asset symbol (must equal request.asset).
        network:    optional chain/network id (must equal request.network).
        nonce:      optional nonce carried in the signed payload.
    """

    recipient: str
    amount_raw: int
    decimals: int = 6
    asset: Optional[str] = None
    network: Optional[str] = None
    nonce: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Any) -> "SignedPayload":
        """Build a SignedPayload from a JSON-decoded object, validating shape."""
        if not isinstance(data, dict):
            raise MalformedRequestError("signed payload must be a JSON object")

        recipient = data.get("recipient")
        if not isinstance(recipient, str) or not recipient.strip():
            raise MalformedRequestError(
                "signed payload 'recipient' must be a non-empty string"
            )

        if "amount_raw" not in data:
            raise MalformedRequestError("signed payload missing 'amount_raw'")
        amount_raw = _parse_uint(data["amount_raw"])
        if amount_raw is None:
            raise MalformedRequestError(
                "signed payload 'amount_raw' must be an integer or digit-only string"
            )

        decimals = data.get("decimals", 6)
        if isinstance(decimals, bool) or not isinstance(decimals, int) or decimals < 0:
            raise MalformedRequestError(
                "signed payload 'decimals' must be a non-negative integer"
            )

        asset = data.get("asset")
        if asset is not None and not isinstance(asset, str):
            raise MalformedRequestError("signed payload 'asset' must be a string")

        network = data.get("network", data.get("chain"))
        if network is not None and not isinstance(network, str):
            raise MalformedRequestError("signed payload 'network' must be a string")

        nonce = data.get("nonce")
        if nonce is not None and not isinstance(nonce, str):
            raise MalformedRequestError("signed payload 'nonce' must be a string")

        return cls(
            recipient=recipient,
            amount_raw=amount_raw,
            decimals=decimals,
            asset=asset,
            network=network,
            nonce=nonce,
        )


@dataclass(frozen=True)
class PaymentRequest:
    """A validated x402 payment request.

    Fields:
        pay_to: destination address.
        amount: payment amount in human units (USDC), > 0.
        asset: asset id, canonical value "USDC".
        network: network id, canonical value "Base".
        payee: payee identity/name.
        nonce: one-time nonce (optional; None for v2-derived requests, where
            real replay protection happens on the signed authorization).
        description: merchant-provided description (untrusted text).
        source_url: the URL that issued the 402.
    """

    pay_to: str
    amount: float
    asset: str
    network: str
    payee: str
    description: str
    source_url: str
    nonce: Optional[str] = None

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

        nonce = data.get("nonce")
        if nonce is not None:
            if not isinstance(nonce, str):
                raise MalformedRequestError(
                    f"field 'nonce' must be a string, got {type(nonce).__name__}"
                )
            if not nonce.strip():
                raise MalformedRequestError("field 'nonce' must be non-empty")

        if "amount" not in data:
            raise MalformedRequestError("missing required field 'amount'")
        amount = data["amount"]
        if isinstance(amount, bool) or not isinstance(amount, (int, float)):
            raise MalformedRequestError(
                f"field 'amount' must be a number, got {type(amount).__name__}"
            )
        if not math.isfinite(float(amount)):
            raise MalformedRequestError(f"amount must be finite, got {amount}")
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
            description=description,
            source_url=data["source_url"],
            nonce=nonce,
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
