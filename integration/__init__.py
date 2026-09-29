"""x402 firewall -> Base Sepolia testnet integration.

This package is the *only* place third-party dependencies (the official
``x402`` SDK + ``web3``/``eth_account``/``httpx``) are allowed. It imports both
the SDK and the dependency-free :mod:`x402_firewall` package, and wires them
together for a live testnet run.

The core firewall package must remain importable with **no** third-party deps;
nothing in :mod:`x402_firewall` imports anything from this package.
"""
