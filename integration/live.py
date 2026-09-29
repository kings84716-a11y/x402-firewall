"""Live Base Sepolia end-to-end run (requires a funded throwaway EOA).

Steps (all real, testnet only):

1. Load the throwaway EOA from ``integration/.env.testnet`` (gitignored).
2. Print the address and its on-chain Base Sepolia test-USDC / ETH balances.
3. Start a local x402 resource server that 402s with a real Base-Sepolia USDC
   payment request.
4. Fetch the resource, parse the ``payment-required`` header with OUR wire
   parser, and gate it with OUR ``guard_payment``.
5. Only when the gate allows, sign EIP-3009 via the SDK and call the free
   facilitator ``/verify`` then ``/settle``.
6. Print the whole result (gate decision, verify/settle responses, tx hash and
   explorer URL) as JSON.

Run from the repo root with the venv:
    .venv/bin/python -m integration.live --policy integration/policy.testnet.json
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

import httpx
from web3 import Web3

from x402_firewall import (
    BASE_USDC_SEPOLIA,
    CAIP2_BASE_SEPOLIA,
    PolicyConfig,
    Store,
    option_to_request,
    parse_payment_required_header,
    select_option,
)

from . import local_server, sdk_adapter, testnet_runner

RPC_URL = "https://sepolia.base.org"
EXPLORER_TX = "https://sepolia.basescan.org/tx"

# The local demo resource's merchant address (recipient only; no key is held).
# This is whitelisted in integration/policy.testnet.json so the gate returns PAY.
MERCHANT_ADDRESS = "0x84f7fFF002D2b7817a7f20FDDA0779928c38C2E1"
_ERC20_BALANCE_ABI = [
    {
        "inputs": [{"name": "account", "type": "address"}],
        "name": "balanceOf",
        "outputs": [{"name": "", "type": "uint256"}],
        "stateMutability": "view",
        "type": "function",
    }
]


def usdc_balance(w3: Web3, address: str) -> int:
    contract = w3.eth.contract(
        address=Web3.to_checksum_address(BASE_USDC_SEPOLIA), abi=_ERC20_BALANCE_ABI
    )
    return contract.functions.balanceOf(Web3.to_checksum_address(address)).call()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Live Base Sepolia x402 firewall run")
    parser.add_argument("--policy", default="integration/policy.testnet.json")
    parser.add_argument("--db", default=":memory:")
    parser.add_argument("--key-file", default="integration/.env.testnet")
    parser.add_argument("--expected-amount", type=float, default=None)
    args = parser.parse_args(argv)

    try:
        signer = sdk_adapter.make_signer(args.key_file)
    except (FileNotFoundError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    policy = PolicyConfig.from_dict(json.load(open(args.policy, "r", encoding="utf-8")))
    facilitator = sdk_adapter.FacilitatorClient()

    # The 402 pay_to is a fixed, documented merchant address (recipient only;
    # its key is not held or stored). Whitelisted in the testnet policy.
    merchant = MERCHANT_ADDRESS

    w3 = Web3(Web3.HTTPProvider(RPC_URL))
    payer = signer.address

    report: dict[str, Any] = {
        "payer": payer,
        "rpc": RPC_URL,
        "merchant_pay_to": merchant,
        "usdc_contract": BASE_USDC_SEPOLIA,
        "usdc_balance_atomic": usdc_balance(w3, payer),
        "usdc_balance_human": usdc_balance(w3, payer) / 1e6,
        "eth_balance_wei": w3.eth.get_balance(Web3.to_checksum_address(payer)),
        "facilitator": facilitator.url,
    }

    server = local_server.Local402Server(pay_to=merchant).start()
    try:
        response = httpx.get(server.url, timeout=15.0)
        header_value = response.headers.get("payment-required")
        report["http_status"] = response.status_code

        if response.status_code != 402 or not header_value:
            report["error"] = "expected a 402 with a payment-required header"
            print(json.dumps(report, indent=2, sort_keys=True))
            return 2

        payment_required = parse_payment_required_header(header_value)
        option = select_option(payment_required, desired_network=CAIP2_BASE_SEPOLIA)
        request = option_to_request(option, payment_required.resource)
        report["parsed_402"] = {
            "version": payment_required.version,
            "resource_url": payment_required.resource.url,
            "service_name": payment_required.resource.service_name,
            "selected_option": {
                "scheme": option.scheme,
                "network": option.network,
                "asset": option.asset,
                "amount_raw": option.amount_raw,
                "pay_to": option.pay_to,
                "max_timeout_seconds": option.max_timeout_seconds,
            },
            "normalized_request": {
                "pay_to": request.pay_to,
                "amount": request.amount,
                "asset": request.asset,
                "network": request.network,
                "payee": request.payee,
                "nonce": request.nonce,
            },
        }

        runner = testnet_runner.TestnetRunner(
            signer=signer,
            facilitator=facilitator,
            policy=policy,
            store=Store(args.db),
            desired_network=CAIP2_BASE_SEPOLIA,
        )
        outcome = runner.process(payment_required, expected_amount=args.expected_amount)
        report["outcome"] = outcome.to_dict()

        if outcome.tx_hash:
            report["explorer_url"] = f"{EXPLORER_TX}/{outcome.tx_hash}"

        if outcome.settle and outcome.settle.get("success"):
            server.mark_paid()
            paid = httpx.get(server.url, timeout=15.0)
            report["resource_after_payment"] = {
                "status": paid.status_code,
                "body": paid.json() if paid.headers.get("content-type", "").startswith(
                    "application/json"
                ) else paid.text,
            }

        print(json.dumps(report, indent=2, sort_keys=True))
        return 0 if outcome.allowed else 1
    finally:
        server.stop()


if __name__ == "__main__":
    raise SystemExit(main())
