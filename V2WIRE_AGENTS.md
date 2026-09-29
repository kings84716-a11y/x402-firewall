# Task: Adapt x402 Firewall to Real x402 v2 + Massive Live 402 (parsing only)

## Goal
Make the firewall understand the REAL x402 protocol v2 payload that live servers
actually return, using a captured response from Massive (`agent.massive.com`). This
step is **parsing/normalization + policy evaluation only**: add a real v2 parser that
turns the wire payload into the firewall's internal request model, validate it, and
prove it against the genuine captured header. **No signing, no settler, no facilitator,
no transaction.** Keep stdlib-only; all 117 existing tests must still pass.

## Ground truth — the REAL 402 from Massive (captured 2026-09-29)
`GET https://agent.massive.com/v1/open-close/AAPL/2026-08-14` returns
`402 Payment Required` with an HTTP header `payment-required` whose value is **base64
(JSON)**. Decoded JSON shape (exact):

```json
{
  "x402Version": 2,
  "error": "Payment required",
  "resource": {
    "url": "https://agent.massive.com/v1/open-close/AAPL/2026-08-14",
    "description": "Get the open, close and afterhours prices ...",
    "mimeType": "application/json",
    "serviceName": "Massive",
    "tags": ["open-close", "daily", "ohlc", "stocks"],
    "iconUrl": "https://agent.massive.com/icon.png"
  },
  "accepts": [
    {
      "scheme": "exact",
      "network": "eip155:8453",
      "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
      "amount": "10000",
      "payTo": "0x525f6dDcE9aF7179D7696aaBfCd5FCd15a21e6",
      "maxTimeoutSeconds": 60,
      "extra": {"name": "USD Coin", "version": "2"}
    }
  ],
  "extensions": { "bazaar": { "...schema/info...": true } }
}
```

Key facts the code must reflect (these differ from the current internal model):
- Header name is `payment-required` (case-insensitive); value is base64-encoded JSON.
- `x402Version` must be `2`. Reject unknown versions with a clear error.
- Payment options live in an **`accepts` array**; a server may list several. Each entry
  has `scheme`, `network` (CAIP-2 like `eip155:8453`), `asset` (**token contract
  address**, not a symbol), `amount` (**string of atomic integer units**), `payTo`
  (destination address), `maxTimeoutSeconds`, optional `extra`.
- There is **no decimals field** in the payload. USDC uses 6 decimals. Map the known
  Base USDC contract `0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913` -> USDC/6 decimals.
  `amount "10000"` with 6 decimals = `0.01` USDC.
- `network "eip155:8453"` = Base mainnet. (`eip155:84532` = Base Sepolia testnet.)
- There is no top-level human payee/nonce; `resource.serviceName` is the merchant name.
  Do not invent fields.

## Required work

### 1. v2 wire parser (new module, e.g. `x402_firewall/wire.py`)
- `parse_payment_required_header(header_value: str) -> PaymentRequired` : base64-decode
  and JSON-parse; validate structure.
- `parse_payment_required_json(data: dict) -> PaymentRequired` : typed parse.
- Model the v2 payload with small containers: `PaymentRequired` (version, resource,
  accepts list, extensions) and `PaymentOption` (scheme, network, asset, amount_raw:int,
  pay_to, max_timeout_seconds, extra). Convert `amount` string to int (reject non-numeric
  / negative / non-finite).
- Selector: a function to choose a usable option (e.g. filter to scheme `exact`, a
  desired network, and a known/accepted asset). Return a clear error if none match.
- Conversion into the firewall's internal `PaymentRequest`:
  - resolve asset contract -> symbol + decimals via a small built-in asset table
    (Base USDC mainnet + Base Sepolia test USDC at minimum); unknown asset -> a typed
    `UnknownAssetError` or option marked unsupported (do not silently assume decimals).
  - human amount = amount_raw / 10**decimals.
  - map pay_to, asset symbol, network name (Base), payee=resource.serviceName,
    description=resource.description, source_url=resource.url. Reuse a synthetic/derived
    internal nonce ONLY if the existing model requires one — prefer extending the
    internal model so a nonce is not mandatory at the v2-request stage (real replay
    protection happens on the signed authorization later). Do not fabricate a fake nonce
    that could be mistaken for a real one.

### 2. Adapt policy evaluation to v2 semantics
- The existing evaluator compares asset=="USDC"/network=="Base". Keep that behavior for
  direct internal requests, but ensure v2-derived requests evaluate correctly:
  network CAIP-2 `eip155:8453` -> Base; asset resolved from contract -> USDC.
- Validate `scheme == "exact"` for now; other schemes -> a clean unsupported result
  (DENY rule `unsupported_scheme`) rather than crashing. `upto`/batch/auth-capture are
  future work; just reject safely.
- Keep address whitelist, per-request budget, total budget, injection scan (now applied
  to `resource.description`), and signed-payload cross-check working unchanged on the
  normalized request.
- Malformed v2 payloads must map to DENY `malformed` / typed errors, never a raw
  traceback through the CLI.

### 3. CLI
- Add a way to parse a real captured 402: e.g. `--payment-required-header PATH` (read
  raw header value from file or `-` stdin) OR `--payment-required-json PATH` (already
  decoded JSON), plus optionally fetch a URL with `--fetch-url URL` ONLY if you keep it
  offline-safe — prefer NOT doing live HTTP inside the CLI for tests; make the parser
  accept the captured header value. Keep it stdlib and deterministic.
- Print the normalized internal request and the gate decision as JSON. Exit codes
  unchanged (PAY 0, DENY 1, ASK 3, error 2).
- Do not break any current flags/invocations.

### 4. Captured fixture (committed)
- Save the real captured header value and decoded JSON under `examples/` (e.g.
  `massive_payment_required.header.txt` and `massive_payment_required.json`) so tests run
  fully offline. Values must be the genuine captured ones from above.

## Tests — real stdlib unittest, must cover
1. parse the committed real base64 header -> version 2, exactly 1 accept, scheme exact,
   network eip155:8453, asset contract matches Base USDC, amount_raw 10000.
2. conversion -> human amount 0.01, asset USDC, network Base, payee "Massive",
   source_url and description populated.
3. full evaluation of the normalized Massive request against a permissive policy -> PAY;
   against a policy that whitelists a different payTo -> DENY unknown_address; with
   max_amount 0.005 -> DENY over_budget.
4. bad base64 / not-an-object / missing accepts / bad version -> clean error (malformed).
5. amount string non-numeric/negative -> error; unknown asset contract ->
   UnknownAssetError/unsupported; non-exact scheme -> unsupported_scheme.
6. testnet mapping `eip155:84532` recognized as Base Sepolia with the test USDC
   contract when present in your asset table (add it).
7. Existing FULL suite (117) still passes.

## Success criteria — run yourself, paste REAL output
1. `python3 -m unittest discover -s tests -v` -> all tests pass, zero skips; paste full
   output with new total.
2. `python3 -m py_compile` over all modules -> OK.
3. Real CLI demo (offline, using committed fixture): feed the captured header value and
   show (a) normalized JSON, (b) PAY with a permissive policy, (c) DENY when the Massive
   payTo is not whitelisted. Paste exact commands and output.
4. Also verify the parser against a FRESH live header by fetching Massive once over the
   network just for this verification (curl to a temp file; parse it) — proving it works
   on today's live response, not only the frozen fixture. Do not commit extra temp files.
5. README updated: real v2 wire format, CAIP-2/asset-contract/decimals mapping, the new
   parser and CLI usage. Then git commit (tests green).

## Constraints / FORBIDDEN
- Work only inside `/home/kings/projects/x402-firewall`.
- Python stdlib only. No pip installs, no signing, no facilitator, no settler, no keys,
  no GPU. Live network use only for the single fetch-and-verify step (#4).
- Do not break existing tests/flags/exit-codes/DB compatibility.
- Do not fabricate a nonce or assume fields the v2 payload does not contain.
- Do not stub/fabricate test or CLI output — run and paste real results.
