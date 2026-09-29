"""Create a fresh throwaway Base Sepolia test EOA (never reuse real funds).

Writes the private key to ``integration/.env.testnet`` (gitignored) and prints
only the address — never the key. The key is for testnet only.

Usage:
    .venv/bin/python -m integration.create_eoa
"""

from __future__ import annotations

import os
import sys

from eth_account import Account


def main() -> int:
    out_dir = os.path.dirname(os.path.abspath(__file__))
    env_path = os.path.join(out_dir, ".env.testnet")

    if os.path.exists(env_path):
        print(f"refusing to overwrite existing key file: {env_path}", file=sys.stderr)
        return 2

    account = Account.create()
    with open(env_path, "w", encoding="utf-8") as handle:
        handle.write(f"PRIVATE_KEY={account.key.hex()}\n")
    os.chmod(env_path, 0o600)

    print(f"address: {account.address}")
    print(f"key written to: {env_path}  (gitignored, chmod 600)")
    print("Fund this address with Base Sepolia test USDC at https://faucet.circle.com")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
