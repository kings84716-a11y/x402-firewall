"""x402 payment-request firewall.

A minimal, pure-Python validator that inspects an x402 HTTP-402 payment
request against a local policy and returns PAY / ASK / DENY.
"""

from .models import (
    PaymentRequest,
    Verdict,
    Result,
    MalformedRequestError,
)
from .policy import (
    PolicyConfig,
    evaluate_payment_request,
    scan_description,
    PROMPT_INJECTION_PATTERNS,
)

__all__ = [
    "PaymentRequest",
    "Verdict",
    "Result",
    "MalformedRequestError",
    "PolicyConfig",
    "evaluate_payment_request",
    "scan_description",
    "PROMPT_INJECTION_PATTERNS",
]

__version__ = "0.1.0"
