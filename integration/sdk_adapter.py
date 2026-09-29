"""SDK-backed signer + facilitator adapter for the testnet runner.

This is the ONLY module that imports the official ``x402`` SDK (plus
``eth_account`` / ``httpx``). It converts our stdlib wire types
(:class:`~x402_firewall.wire.PaymentOption` /
:class:`~x402_firewall.wire.Resource`) into the SDK's pydantic models, produces
a real EIP-3009 ``transferWithAuthorization`` signature, and posts to the free
facilitator at ``https://x402.org/facilitator``.

Nothing in this module is imported by the dependency-free ``x402_firewall``
package. It is loaded lazily by the live runner so offline wiring tests never
need the SDK installed.
"""

from __future__ import annotations

import os
from typing import Any, Optional

from x402_firewall import PaymentOption, Resource

# --- SDK imports (only inside the isolated .venv) ---------------------------
from eth_account import Account
from x402.mechanisms.evm.default_assets import find_default_asset
from x402.mechanisms.evm.exact import ExactEvmScheme
from x402.mechanisms.evm.signers import EthAccountSigner
from x402.schemas import (
    FacilitatorConfig,
    PaymentPayload,
    PaymentRequirements,
    ResourceInfo,
)
from x402.http import HTTPFacilitatorClientSync

FACILITATOR_URL = os.environ.get("X402_FACILITATOR_URL", "https://x402.org/facilitator")
DEFAULT_MAX_TIMEOUT_SECONDS = 3600


def option_to_requirements(option: PaymentOption) -> PaymentRequirements:
    """Convert our wire ``PaymentOption`` into an SDK ``PaymentRequirements``.

    The EIP-3009 domain ``name``/``version`` are required by the facilitator's
    verify step; when the 402 payload's ``extra`` omits them, fall back to the
    SDK's built-in asset table for the network/contract.
    """
    extra = dict(option.extra or {})
    if "name" not in extra or "version" not in extra:
        info = find_default_asset(option.network, option.asset)
        if info is not None:
            extra.setdefault("name", info["name"])
            extra.setdefault("version", info["version"])

    return PaymentRequirements(
        scheme=option.scheme,
        network=option.network,
        asset=option.asset,
        amount=str(option.amount_raw),
        pay_to=option.pay_to,
        max_timeout_seconds=option.max_timeout_seconds or DEFAULT_MAX_TIMEOUT_SECONDS,
        extra=extra,
    )


def _resource_to_sdk(resource: Resource) -> ResourceInfo:
    return ResourceInfo(
        url=resource.url,
        description=resource.description or None,
        mime_type=resource.mime_type,
        service_name=resource.service_name,
        tags=list(resource.tags) if resource.tags else None,
        icon_url=resource.icon_url,
    )


def build_payload(option: PaymentOption, resource: Resource, inner_payload: dict) -> PaymentPayload:
    """Wrap the signed inner payload into a full SDK ``PaymentPayload``."""
    return PaymentPayload(
        x402_version=2,
        payload=inner_payload,
        accepted=option_to_requirements(option),
        resource=_resource_to_sdk(resource),
    )


class Eip3009Signer:
    """Signs EIP-3009 authorizations with an ``eth_account`` local key.

    Exposes ``.calls`` (a list) so the offline wiring can assert how many times
    a signer was invoked, mirroring the firewall's ``FakeSettler`` pattern.
    """

    def __init__(self, private_key: str) -> None:
        key = private_key.strip()
        if not key.startswith("0x"):
            key = "0x" + key
        account = Account.from_key(key)
        self.address = account.address
        self.calls: list[dict] = []
        self._scheme = ExactEvmScheme(EthAccountSigner(account))

    def sign(self, option: PaymentOption, resource: Resource) -> dict:
        """Build the signed EIP-3009 inner payload for ``option``."""
        self.calls.append(
            {
                "network": option.network,
                "scheme": option.scheme,
                "asset": option.asset,
                "amount_raw": option.amount_raw,
                "pay_to": option.pay_to,
            }
        )
        requirements = option_to_requirements(option)
        return self._scheme.create_payment_payload(requirements)


class FacilitatorClient:
    """Talks to the free facilitator's ``/verify`` and ``/settle`` endpoints."""

    def __init__(self, url: Optional[str] = None) -> None:
        self.url = url or FACILITATOR_URL
        self._client = HTTPFacilitatorClientSync(FacilitatorConfig(url=self.url))
        self.verify_calls: list[dict] = []
        self.settle_calls: list[dict] = []

    def get_supported(self) -> dict:
        supported = self._client.get_supported()
        return {
            "kinds": [k.model_dump() for k in supported.kinds],
            "extensions": supported.extensions,
            "signers": supported.signers,
        }

    def verify(self, option: PaymentOption, resource: Resource, inner_payload: dict) -> dict:
        self.verify_calls.append({"pay_to": option.pay_to, "amount_raw": option.amount_raw})
        payload = build_payload(option, resource, inner_payload)
        result = self._client.verify(payload, payload.accepted)
        return {
            "is_valid": result.is_valid,
            "invalid_reason": result.invalid_reason,
            "invalid_message": result.invalid_message,
            "payer": result.payer,
        }

    def settle(self, option: PaymentOption, resource: Resource, inner_payload: dict) -> dict:
        self.settle_calls.append({"pay_to": option.pay_to, "amount_raw": option.amount_raw})
        payload = build_payload(option, resource, inner_payload)
        result = self._client.settle(payload, payload.accepted)
        return {
            "success": result.success,
            "transaction": result.transaction,
            "network": result.network,
            "payer": result.payer,
            "amount": result.amount,
            "error_reason": result.error_reason,
            "error_message": result.error_message,
        }


def load_private_key(path: str = ".env.testnet") -> str:
    """Read the throwaway testnet private key from a gitignored env file.

    Accepts either a bare hex key or ``PRIVATE_KEY=0x...`` on the first line.
    Never echoes the key.
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"missing testnet key file: {path} (run create_eoa.py)")
    for line in open(path, "r", encoding="utf-8"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            _, _, value = line.partition("=")
            return value.strip().strip('"').strip("'")
        return line
    raise ValueError(f"no private key found in {path}")


def make_signer(path: str = ".env.testnet") -> Eip3009Signer:
    """Build an :class:`Eip3009Signer` from the gitignored testnet key file."""
    return Eip3009Signer(load_private_key(path))
