"""x402 payment-request firewall.

A minimal, pure-Python validator that inspects an x402 HTTP-402 payment
request against a local policy and returns PAY / ASK / DENY.
"""

from .models import (
    PaymentRequest,
    Verdict,
    Result,
    MalformedRequestError,
    SignedPayload,
    is_valid_evm_address,
)
from .policy import (
    PolicyConfig,
    evaluate_payment_request,
    scan_description,
    cross_check_signed_payload,
    is_valid_source_url,
    has_excess_precision,
    PROMPT_INJECTION_PATTERNS,
)
from .store import Store
from .gate import (
    GateResult,
    PaymentBlockedError,
    guard_payment,
    approve,
)
from .interactive import interactive_approve, format_summary, MAX_PROMPTS
from .client import (
    Client,
    InMemoryServer,
    FakeSettler,
    Transport,
    Settler,
    TransportResponse,
    ClientOutcome,
    ApprovalHandler,
    STATUS_NOT_REQUIRED,
    STATUS_PAID,
    STATUS_BLOCKED,
    STATUS_REJECTED,
    STATUS_AWAITING,
)
from .demo import run_demo, build_client, SCENARIOS

__all__ = [
    "PaymentRequest",
    "Verdict",
    "Result",
    "MalformedRequestError",
    "SignedPayload",
    "is_valid_evm_address",
    "PolicyConfig",
    "evaluate_payment_request",
    "scan_description",
    "cross_check_signed_payload",
    "is_valid_source_url",
    "has_excess_precision",
    "PROMPT_INJECTION_PATTERNS",
    "Store",
    "GateResult",
    "PaymentBlockedError",
    "guard_payment",
    "approve",
    "interactive_approve",
    "format_summary",
    "MAX_PROMPTS",
    "Client",
    "InMemoryServer",
    "FakeSettler",
    "Transport",
    "Settler",
    "TransportResponse",
    "ClientOutcome",
    "ApprovalHandler",
    "STATUS_NOT_REQUIRED",
    "STATUS_PAID",
    "STATUS_BLOCKED",
    "STATUS_REJECTED",
    "STATUS_AWAITING",
    "run_demo",
    "build_client",
    "SCENARIOS",
]

__version__ = "0.4.0"
