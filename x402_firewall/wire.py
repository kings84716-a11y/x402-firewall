"""Parser and normalizer for the real x402 protocol v2 wire payload.

Live x402 v2 servers reply ``402 Payment Required`` with an HTTP header named
``payment-required`` (case-insensitive) whose value is **base64-encoded JSON**.
This module turns that wire payload into the firewall's internal
:class:`~x402_firewall.models.PaymentRequest` model and (optionally) evaluates
it, without ever performing on-chain signing.

The decoded v2 JSON shape is::

    {
      "x402Version": 2,
      "error": "Payment required",
      "resource": { "url": ..., "description": ..., "mimeType": ...,
                    "serviceName": ..., "tags": [...], "iconUrl": ... },
      "accepts": [
        { "scheme": "exact", "network": "eip155:8453",
          "asset": "0x...token contract...", "amount": "10000",
          "payTo": "0x...", "maxTimeoutSeconds": 60, "extra": {...} }
      ],
      "extensions": { ... }
    }

Key differences from the internal model that this module normalizes away:

* ``amount`` is a **string of atomic integer units**; the human amount is
  ``amount_raw / 10**decimals`` (USDC has 6 decimals).
* ``asset`` is a **token contract address**, not a symbol; a small built-in
  table maps known Base USDC contracts to ``USDC``/6 decimals.
* ``network`` is a CAIP-2 chain id (``eip155:8453`` = Base mainnet,
  ``eip155:84532`` = Base Sepolia).
* There is no nonce at this stage; the normalized request carries ``nonce=None``
  (replay protection happens later on the signed authorization).

Standard library only — no third-party runtime dependencies.
"""

from __future__ import annotations

import base64
import binascii
import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .models import MalformedRequestError, PaymentRequest, Result, Verdict
from .policy import PolicyConfig, evaluate_payment_request

# The only x402 version this firewall understands.
X402_VERSION = 2

# CAIP-2 network identifiers and their human-readable names.
CAIP2_BASE_MAINNET = "eip155:8453"
CAIP2_BASE_SEPOLIA = "eip155:84532"

NETWORK_BY_CAIP2: Dict[str, str] = {
    CAIP2_BASE_MAINNET: "Base",
    CAIP2_BASE_SEPOLIA: "Base Sepolia",
}

# Known USDC token contracts. Keyed by ``(caip2_network, contract_address)``
# both lowercased, mapped to ``(symbol, decimals)``. USDC has 6 decimals.
BASE_USDC_MAINNET = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
BASE_USDC_SEPOLIA = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"

KNOWN_ASSETS: Dict[Tuple[str, str], Tuple[str, int]] = {
    (CAIP2_BASE_MAINNET, BASE_USDC_MAINNET.lower()): ("USDC", 6),
    (CAIP2_BASE_SEPOLIA, BASE_USDC_SEPOLIA.lower()): ("USDC", 6),
}


class WireError(ValueError):
    """Base class for v2 wire-parsing errors."""


class UnknownVersionError(WireError):
    """Raised when the payload's ``x402Version`` is not the supported version."""


class UnknownAssetError(WireError):
    """Raised when an option's asset contract / network is not known."""


class UnsupportedSchemeError(WireError):
    """Raised when no option uses the supported ``exact`` payment scheme."""


class NoMatchingOptionError(WireError):
    """Raised when no option matches the requested network."""


class WireFetchError(WireError):
    """Raised when a live 402 fetch fails or lacks the payment-required header."""


@dataclass(frozen=True)
class Resource:
    """The ``resource`` object describing what the agent is trying to access."""

    url: str
    description: str
    mime_type: Optional[str] = None
    service_name: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    icon_url: Optional[str] = None


@dataclass(frozen=True)
class PaymentOption:
    """A single ``accepts`` entry (one way to pay)."""

    scheme: str
    network: str  # CAIP-2 chain id, e.g. eip155:8453
    asset: str  # token contract address
    amount_raw: int  # atomic integer units
    pay_to: str
    max_timeout_seconds: Optional[int] = None
    extra: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class PaymentRequired:
    """The decoded x402 v2 ``payment-required`` payload."""

    version: int
    resource: Resource
    accepts: List[PaymentOption]
    error: Optional[str] = None
    extensions: Dict[str, Any] = field(default_factory=dict)


def _parse_atomic_amount(value: Any) -> Optional[int]:
    """Parse an on-chain atomic amount (int or digit-only string).

    Returns ``None`` on anything else (bool, floats, negatives, non-numeric).
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


def _require_str(data: dict, key: str, context: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value.strip():
        raise MalformedRequestError(f"{context} '{key}' must be a non-empty string")
    return value


def _parse_resource(data: Any) -> Resource:
    if not isinstance(data, dict):
        raise MalformedRequestError("'resource' must be a JSON object")

    url = _require_str(data, "url", "resource")
    description = data.get("description", "")
    if not isinstance(description, str):
        raise MalformedRequestError("resource 'description' must be a string")

    mime_type = data.get("mimeType")
    if mime_type is not None and not isinstance(mime_type, str):
        raise MalformedRequestError("resource 'mimeType' must be a string")

    service_name = data.get("serviceName")
    if service_name is not None and not isinstance(service_name, str):
        raise MalformedRequestError("resource 'serviceName' must be a string")

    tags = data.get("tags", [])
    if not isinstance(tags, list):
        raise MalformedRequestError("resource 'tags' must be a list")
    if not all(isinstance(t, str) for t in tags):
        raise MalformedRequestError("resource 'tags' entries must be strings")

    icon_url = data.get("iconUrl")
    if icon_url is not None and not isinstance(icon_url, str):
        raise MalformedRequestError("resource 'iconUrl' must be a string")

    return Resource(
        url=url,
        description=description,
        mime_type=mime_type,
        service_name=service_name,
        tags=list(tags),
        icon_url=icon_url,
    )


def _parse_option(data: Any) -> PaymentOption:
    if not isinstance(data, dict):
        raise MalformedRequestError("each 'accepts' entry must be a JSON object")

    scheme = _require_str(data, "scheme", "accepts")
    network = _require_str(data, "network", "accepts")
    asset = _require_str(data, "asset", "accepts")

    if "amount" not in data:
        raise MalformedRequestError("accepts entry missing 'amount'")
    amount_raw = _parse_atomic_amount(data["amount"])
    if amount_raw is None:
        raise MalformedRequestError(
            "accepts 'amount' must be a non-negative integer "
            "(digit-only string or int)"
        )

    pay_to = _require_str(data, "payTo", "accepts")

    max_timeout = data.get("maxTimeoutSeconds")
    if max_timeout is not None:
        if isinstance(max_timeout, bool) or not isinstance(max_timeout, int) or max_timeout < 0:
            raise MalformedRequestError(
                "accepts 'maxTimeoutSeconds' must be a non-negative integer"
            )

    extra = data.get("extra", {})
    if not isinstance(extra, dict):
        raise MalformedRequestError("accepts 'extra' must be a JSON object")

    return PaymentOption(
        scheme=scheme,
        network=network,
        asset=asset,
        amount_raw=amount_raw,
        pay_to=pay_to,
        max_timeout_seconds=max_timeout,
        extra=dict(extra),
    )


def parse_payment_required_json(data: Any) -> PaymentRequired:
    """Parse an already-decoded v2 payload (a ``dict``) into ``PaymentRequired``.

    Raises :class:`MalformedRequestError` on any structural problem.
    """
    if not isinstance(data, dict):
        raise MalformedRequestError("payment-required payload must be a JSON object")

    version = data.get("x402Version")
    if isinstance(version, bool) or not isinstance(version, int):
        raise MalformedRequestError("'x402Version' must be an integer")
    if version != X402_VERSION:
        raise UnknownVersionError(
            f"unsupported x402 version {version} (expected {X402_VERSION})"
        )

    resource = _parse_resource(data.get("resource"))

    accepts = data.get("accepts")
    if not isinstance(accepts, list) or len(accepts) == 0:
        raise MalformedRequestError("missing or empty 'accepts' array")

    error = data.get("error")
    if error is not None and not isinstance(error, str):
        raise MalformedRequestError("'error' must be a string")

    extensions = data.get("extensions", {})
    if not isinstance(extensions, dict):
        raise MalformedRequestError("'extensions' must be a JSON object")

    return PaymentRequired(
        version=version,
        resource=resource,
        accepts=[_parse_option(o) for o in accepts],
        error=error,
        extensions=dict(extensions),
    )


def parse_payment_required_header(header_value: str) -> PaymentRequired:
    """Base64-decode and JSON-parse a ``payment-required`` header value."""
    if not isinstance(header_value, str):
        raise MalformedRequestError("payment-required header value must be a string")

    stripped = header_value.strip()
    try:
        decoded = base64.b64decode(stripped, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise MalformedRequestError(
            f"payment-required header is not valid base64: {exc}"
        ) from exc

    try:
        text = decoded.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise MalformedRequestError(
            f"payment-required header is not valid UTF-8: {exc}"
        ) from exc

    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise MalformedRequestError(
            f"payment-required header is not valid JSON: {exc}"
        ) from exc

    return parse_payment_required_json(data)


def _coerce_payment_required(payload: Any) -> PaymentRequired:
    if isinstance(payload, PaymentRequired):
        return payload
    if isinstance(payload, dict):
        return parse_payment_required_json(payload)
    raise MalformedRequestError("payment-required payload must be an object")


def resolve_asset(network: str, asset: str) -> Tuple[str, int, str]:
    """Resolve a CAIP-2 network + token contract into ``(symbol, decimals, name)``.

    Raises :class:`UnknownAssetError` when the network or contract is unknown.
    """
    net_key = network.strip().lower()
    network_name = NETWORK_BY_CAIP2.get(net_key)
    if network_name is None:
        raise UnknownAssetError(f"unknown network '{network}' (CAIP-2 id not supported)")
    entry = KNOWN_ASSETS.get((net_key, asset.strip().lower()))
    if entry is None:
        raise UnknownAssetError(
            f"unknown asset contract '{asset}' on network '{network}'"
        )
    symbol, decimals = entry
    return symbol, decimals, network_name


def select_option(
    payment_required: PaymentRequired,
    desired_network: Optional[str] = None,
) -> PaymentOption:
    """Choose the first usable payment option.

    An option is usable when its ``scheme`` is ``exact`` and its network + asset
    contract are known. Raises:

    * :class:`UnsupportedSchemeError` — no option uses the ``exact`` scheme.
    * :class:`NoMatchingOptionError` — ``desired_network`` filters everything out.
    * :class:`UnknownAssetError` — the exact options reference unknown assets.
    """
    exact = [o for o in payment_required.accepts if o.scheme.strip().lower() == "exact"]
    if not exact:
        schemes = ", ".join(sorted({o.scheme for o in payment_required.accepts}))
        raise UnsupportedSchemeError(
            f"no 'exact' payment scheme available (found: {schemes or 'none'})"
        )

    candidates = exact
    if desired_network is not None:
        wanted = desired_network.strip().lower()
        candidates = [o for o in candidates if o.network.strip().lower() == wanted]
        if not candidates:
            raise NoMatchingOptionError(
                f"no 'exact' option for desired network '{desired_network}'"
            )

    for option in candidates:
        net_key = option.network.strip().lower()
        if net_key in NETWORK_BY_CAIP2 and (net_key, option.asset.strip().lower()) in KNOWN_ASSETS:
            return option

    first = candidates[0]
    if first.network.strip().lower() not in NETWORK_BY_CAIP2:
        raise UnknownAssetError(f"unknown network '{first.network}' (CAIP-2 id not supported)")
    raise UnknownAssetError(
        f"unknown asset contract '{first.asset}' on network '{first.network}'"
    )


def option_to_request(option: PaymentOption, resource: Resource) -> PaymentRequest:
    """Convert one resolved payment option into the internal request model.

    Raises :class:`UnknownAssetError` if the option's asset is unknown (never
    silently assumes a decimals value).
    """
    symbol, decimals, network_name = resolve_asset(option.network, option.asset)
    human_amount = option.amount_raw / (10 ** decimals)
    return PaymentRequest(
        pay_to=option.pay_to,
        amount=human_amount,
        asset=symbol,
        network=network_name,
        payee=resource.service_name or "",
        description=resource.description,
        source_url=resource.url,
        nonce=None,
    )


def normalize_v2(payload: Any, desired_network: Optional[str] = None) -> PaymentRequest:
    """Parse + select + normalize a v2 payload into a ``PaymentRequest``.

    Raises the typed errors above on failure. ``nonce`` is ``None`` at this
    stage (no fabricated nonce — real replay protection happens later).
    """
    payment_required = _coerce_payment_required(payload)
    option = select_option(payment_required, desired_network=desired_network)
    return option_to_request(option, payment_required.resource)


def evaluate_v2_payment_required(
    payload: Any,
    policy: Any,
    expected_amount: Optional[float] = None,
    desired_network: Optional[str] = None,
) -> Result:
    """Normalize a v2 payload and evaluate it against the policy.

    Malformed/unsupported v2 payloads map to clean ``DENY`` results instead of
    raising: ``malformed``, ``unsupported_scheme``, ``unsupported_asset``,
    ``no_matching_option``. A successfully normalized request is evaluated by
    :func:`x402_firewall.policy.evaluate_payment_request` (in-memory only; there
    is no nonce at this stage).
    """
    try:
        request = normalize_v2(payload, desired_network=desired_network)
    except UnsupportedSchemeError as exc:
        return Result(Verdict.DENY, str(exc), "unsupported_scheme")
    except UnknownAssetError as exc:
        return Result(Verdict.DENY, str(exc), "unsupported_asset")
    except NoMatchingOptionError as exc:
        return Result(Verdict.DENY, str(exc), "no_matching_option")
    except (WireError, MalformedRequestError) as exc:
        return Result(Verdict.DENY, str(exc), "malformed")

    return evaluate_payment_request(request, policy, expected_amount)


def fetch_payment_required(url: str, timeout: float = 10.0) -> PaymentRequired:
    """Fetch a URL and parse its ``payment-required`` header (live, once).

    Used only for the one-off verification of a fresh live response. On a
    network error or a missing header a :class:`WireFetchError` is raised.
    """
    request = urllib.request.Request(url, method="GET", headers={"Accept": "application/json"})
    try:
        response = urllib.request.urlopen(request, timeout=timeout)
    except urllib.error.HTTPError as exc:
        response = exc
    except urllib.error.URLError as exc:
        raise WireFetchError(f"failed to fetch {url}: {exc.reason}") from exc

    header_value: Optional[str] = None
    try:
        for key, value in response.headers.items():
            if key.lower() == "payment-required":
                header_value = value
    finally:
        try:
            response.read()
        except Exception:
            pass

    if header_value is None:
        raise WireFetchError(
            f"no 'payment-required' header in the response from {url}"
        )

    return parse_payment_required_header(header_value)
