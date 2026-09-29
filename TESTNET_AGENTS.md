# Task: x402 Firewall — Base Sepolia Testnet End-to-End with Real Signing

## Goal
Run the FULL closed loop on **Base Sepolia testnet with real (testnet-only) signing**,
wired through our firewall, so the path "request -> 402 -> firewall -> EIP-3009 sign ->
facilitator verify -> resource" genuinely works. **No real money — test USDC only.**
Keep all existing firewall stdlib tests passing (142). The official `x402` Python SDK
is allowed for the signing/transport part (it is the one permitted third-party dep for
this integration), isolated in a project virtualenv so the stdlib firewall package is
untouched.

## Verified environment (T2, checked 2026-09-29)
- Python 3.12.3; `uv` at `/home/kings/.local/bin/uv` (use it; do not use system pip
  globally). x402 SDK latest available 2.23.0.
- Free facilitator `https://x402.org/facilitator` is live; GET `/supported` confirms
  `{x402Version:2, scheme:"exact", network:"eip155:84532"}` (Base Sepolia) plus upto /
  batch. Endpoints are `/supported`, `/verify`, `/settle`.
- Faucet reachable: `https://faucet.circle.com` (Base Sepolia test USDC contract
  `0x036CbD53842c5426634e7929541eC2318f3dCF7e`). Base Sepolia test ETH from the Base
  faucet if gas is needed (EIP-3009 via facilitator should not need client gas).
- Base Sepolia RPC e.g. `https://sepolia.base.org`, chain CAIP-2 `eip155:84532`.

## What to build

### 1. Integration virtualenv (isolated, not system-wide)
- Create `.venv` inside the project via uv and install `x402[evm,httpx]` (pin a working
  version; 2.23.0 is current). Also `web3` if the SDK needs it. Keep this venv out of
  git (extend `.gitignore`). The core `x402_firewall/` package stays dependency-free;
  the testnet glue lives in a separate integration module/scripts that import both the
  SDK and our firewall.

### 2. Testnet account + funds
- Generate (or import) a fresh throwaway EOA **dedicated to testnet**, never reuse a key
  that holds real funds. Provide a script to create it and print the address; store the
  test key ONLY in a local untracked env/file (e.g. `.env.testnet` gitignored) and never
  commit it. Do not ask for or echo any secret in chat.
- Fund it with Base Sepolia test USDC from faucet.circle.com. NOTE: faucet may require a
  human/Captcha or wallet interaction. If automated funding is not possible, STOP at that
  point and report exactly what is needed (do not fabricate a balance). Verify balance
  on-chain via RPC before proceeding and paste the real balance output.

### 3. Wire firewall -> real SDK signing (testnet orchestrator)
- Add an integration module (e.g. `integration/testnet_runner.py`) that:
  1. Performs the initial request against a chosen Base-Sepolia x402 resource and reads
     the real 402 `payment-required` header.
  2. Parses it with OUR `x402_firewall.wire` parser and runs OUR gate
     (`guard_payment`) using a testnet policy.
  3. ONLY when the gate allows (PAY, or ASK explicitly approved), constructs the real
     payment via the x402 SDK: select the exact/EVM option, build the EIP-3009
     `transferWithAuthorization` EIP-712 signature with the funded EOA (the SDK handles
     domain/nonce/validAfter/Before), submit via the free facilitator `/verify` then
     `/settle`, and obtain the paid resource.
  4. Returns a structured result: firewall decision/rule, whether signing happened,
     facilitator verify/settle responses (including tx hash and network), and resource.
- Hard requirement: the SDK signing/settle call must be unreachable unless our gate
  returned allowed. Reuse the same gate contract; do not add a bypass.
- Choose the test resource:
  - Prefer a documented Base-Sepolia x402 example server/resource that works with the
    free facilitator. The x402 repo examples or any public Base-Sepolia x402 endpoint
    are acceptable. If no third-party test resource is reliably reachable, run the
    official SDK example server locally (in the venv) on Base Sepolia and drive the
    client against it through the free facilitator — that is a valid end-to-end test as
    long as verify/settle genuinely hit the facilitator and a real testnet tx is
    produced.
- Reuse our Store for the decision/audit record (a testnet DB file or `:memory:`), so
  the run shows in the same audit trail; clean up committed temp files afterward.

### 4. Tests / verification
Because real signing needs funds/network, provide BOTH:
- Offline unit tests (stdlib unittest, run in CI without funds) that assert the wiring:
  (a) when gate says DENY, the SDK signer is never invoked (use a fake signer that
  records calls); (b) when gate says PAY, the real-or-fake signer is invoked exactly
  once with the selected v2 option; (c) ASK unapproved -> no sign; approved -> sign.
- A live testnet run script that executes the real flow and PASTES REAL OUTPUT:
  account address, real test-USDC balance, parsed 402, gate PAY, facilitator `/verify`
  valid, `/settle` success with a real Base Sepolia tx hash, and the resource.

## Success criteria — run yourself, paste REAL output
1. Offline: `python3 -m unittest discover -s tests` -> all existing 142 tests still pass
   PLUS new wiring tests (paste counts).
2. The firewall core still imports/works with no third-party deps (confirm py_compile and
   that nothing in x402_firewall/ imports the SDK).
3. Live Base Sepolia run: paste real commands and outputs — funded balance, 402 parse,
   gate allowed, facilitator verify/settle, and a verifiable testnet tx hash (the hash
   must be queryable on Base Sepolia; print the explorer URL).
4. If the faucet cannot be funded non-interactively, report that exact blocker instead
   of fabricating; leave a clear single command for Eric to fund the address.
5. README updated with the testnet setup (venv, faucet, env vars), how to run the live
   flow, and the example tx. Then git commit (no secrets, no venv, no temp db committed).

## Constraints / FORBIDDEN
- Work only inside `/home/kings/projects/x402-firewall`.
- Testnet only. Never spend real funds or touch mainnet in this task. Never commit a
  private key; never print secrets in chat; do not reuse a key with real value.
- Do not modify the stdlib firewall package to depend on the SDK; integration code only.
- Do not break existing tests/flags/exit-codes/DB compatibility.
- No real HTTP signing without an allowed gate result. No fabricated balances or tx
  hashes — if a step cannot complete, report the blocker truthfully.
