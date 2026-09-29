"""Check the throwaway EOA's Base Sepolia balances and print a funding command.

The Circle faucet (https://faucet.circle.com) is a browser app that requires a
wallet connection and a Google reCAPTCHA, so it cannot be driven
non-interactively from this machine. This script verifies the on-chain balance
and, when the account is unfunded, prints the exact single step a human must
run to fund it.

Usage:
    .venv/bin/python -m integration.fund_account
"""

from __future__ import annotations

import json
import os
import sys

from web3 import Web3

from x402_firewall import BASE_USDC_SEPOLIA

from . import sdk_adapter

RPC_URL = "https://sepolia.base.org"
FAUCET_URL = "https://faucet.circle.com"

_ERC20_BALANCE_ABI = [
    {
        "inputs": [{"name": "account", "type": "address"}],
        "name": "balanceOf",
        "outputs": [{"name": "", "type": "uint256"}],
        "stateMutability": "view",
        "type": "function",
    }
]


def main() -> int:
    key_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env.testnet")
    try:
        signer = sdk_adapter.make_signer(key_file)
    except (FileNotFoundError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        print("first run:  .venv/bin/python -m integration.create_eoa", file=sys.stderr)
        return 2

    w3 = Web3(Web3.HTTPProvider(RPC_URL))
    address = signer.address
    contract = w3.eth.contract(
        address=Web3.to_checksum_address(BASE_USDC_SEPOLIA), abi=_ERC20_BALANCE_ABI
    )
    usdc_atomic = contract.functions.balanceOf(Web3.to_checksum_address(address)).call()
    eth_wei = w3.eth.get_balance(Web3.to_checksum_address(address))

    print(
        json.dumps(
            {
                "address": address,
                "network": "eip155:84532 (Base Sepolia)",
                "usdc_contract": BASE_USDC_SEPOLIA,
                "usdc_balance_atomic": usdc_atomic,
                "usdc_balance_human": usdc_atomic / 1e6,
                "eth_balance_wei": eth_wei,
                "eth_balance_eth": eth_wei / 1e18,
            },
            indent=2,
            sort_keys=True,
        )
    )

    if usdc_atomic <= 0:
        print()
        print("=" * 72)
        print("ACCOUNT IS NOT FUNDED WITH TEST USDC.")
        print("The Circle faucet requires a human (wallet connect + Google reCAPTCHA)")
        print("and cannot be automated from a headless machine.")
        print()
        print("To fund it, open a browser and run this ONE step:")
        print(f"  1. go to {FAUCET_URL}")
        print(f"  2. connect a wallet, paste this address, claim test USDC:")
        print(f"     {address}")
        print()
        print("Then re-run:  .venv/bin/python -m integration.fund_account")
        print("=" * 72)
        return 3

    print("funded — ready for the live run:")
    print("  .venv/bin/python -m integration.live")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
