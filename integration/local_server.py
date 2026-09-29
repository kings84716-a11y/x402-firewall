"""A minimal local Base-Sepolia x402 resource server for the live testnet run.

Serves one resource behind a real ``402 Payment Required`` whose
``payment-required`` header carries a base64-encoded x402 v2 payload (Base
Sepolia USDC, ``exact`` scheme). After the orchestrator settles through the free
facilitator, ``mark_paid()`` flips the route to ``200`` so the full
``request -> 402 -> firewall -> sign -> settle -> resource`` loop can complete.

This is the "run the SDK example server locally" fallback from the task: the
verification/settlement still genuinely hit the public facilitator and produce a
real Base Sepolia transaction. Stdlib only.
"""

from __future__ import annotations

import base64
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from x402_firewall import BASE_USDC_SEPOLIA, CAIP2_BASE_SEPOLIA


def build_payment_required_payload(
    resource_url: str,
    pay_to: str,
    amount_raw: str = "10000",  # 0.01 USDC at 6 decimals
    max_timeout_seconds: int = 60,
) -> dict:
    return {
        "x402Version": 2,
        "error": "Payment required",
        "resource": {
            "url": resource_url,
            "description": "One testnet API call (Base Sepolia x402 demo)",
            "mimeType": "application/json",
            "serviceName": "Firewall Testnet Resource",
            "tags": ["testnet", "x402", "base-sepolia"],
        },
        "accepts": [
            {
                "scheme": "exact",
                "network": CAIP2_BASE_SEPOLIA,
                "asset": BASE_USDC_SEPOLIA,
                "amount": amount_raw,
                "payTo": pay_to,
                "maxTimeoutSeconds": max_timeout_seconds,
                "extra": {"name": "USDC", "version": "2"},
            }
        ],
        "extensions": {},
    }


class _Handler(BaseHTTPRequestHandler):
    server: "Local402Server"

    def do_GET(self):  # noqa: N802
        resource = {"ok": True, "data": "paid testnet resource payload", "path": self.path}
        if self.server.paid:
            body = json.dumps(resource).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        header = base64.b64encode(
            json.dumps(self.server.payload).encode("utf-8")
        ).decode("ascii")
        body = json.dumps({"error": "Payment required"}).encode("utf-8")
        self.send_response(402)
        self.send_header("payment-required", header)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # silence noisy request logs
        pass


class Local402Server:
    """A thread-hosted HTTP server that 402s until ``mark_paid()`` is called."""

    def __init__(self, pay_to: str, resource_path: str = "/resource") -> None:
        self.resource_path = resource_path
        self.paid = False
        self.payload = build_payment_required_payload(
            f"http://127.0.0.1:0{resource_path}", pay_to
        )
        self._httpd: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def url(self) -> str:
        host, port = self._httpd.server_address[:2]
        return f"http://127.0.0.1:{port}{self.resource_path}"

    def start(self) -> "Local402Server":
        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self._httpd.paid = False
        self._httpd.payload = self.payload
        self._httpd.server = self
        # fix the resource url now that the port is known
        self.payload["resource"]["url"] = self.url
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        return self

    def mark_paid(self) -> None:
        self.paid = True

    def stop(self) -> None:
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
