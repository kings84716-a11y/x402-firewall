# x402 Payment Firewall

A minimal, dependency-free Python firewall that inspects an **x402 payment
request** (the payload behind an HTTP `402 Payment Required`) before an agent
signs it. It compares the request against a local policy and returns one of
`PAY` / `ASK` / `DENY` with a concrete, human-readable reason.

Pure software, CPU-only, standard-library only (incl. `sqlite3`): **no on-chain
signing, no HTTP server, no network calls, no wallet keys.**

## Purpose

An agent sends an HTTP request; the server replies `402 Payment Required`
carrying a payment request (destination address, amount, asset/network, payee,
nonce, description, source URL). This firewall validates that request *before*
signing, catching:

1. Amount tampering — amount differs from what the agent expected.
2. Address substitution — `pay_to` swapped to an attacker address.
3. Nonce replay — the same nonce was already approved (now **persistent**).
4. Over budget — amount exceeds the per-request / cumulative budget.
5. Description prompt injection — the untrusted `description` field carries an
   LLM prompt-injection payload.
6. Asset/network mismatch — anything other than USDC on Base.
7. JSON↔signature inconsistency — the outer request JSON can differ from the
   structured payload that actually gets signed (a whitelisted address shown in
   JSON but an attacker address in the signed object). The **signed-payload
   cross-check** compares them.
8. Input edge cases — NaN/Infinity/bool amounts, sub-cent dust, invalid
   addresses, bad URLs, and oversized fields.

## Data structure

A payment request object:

| Field         | Type     | Meaning                                      |
|---------------|----------|----------------------------------------------|
| `pay_to`      | str      | destination address                          |
| `amount`      | number>0 | amount in human units (USDC, e.g. `0.50`)    |
| `asset`       | str      | asset id, canonical `"USDC"`                 |
| `network`     | str      | network id, canonical `"Base"`               |
| `payee`       | str      | payee identity/name                          |
| `nonce`       | str      | one-time nonce                               |
| `description` | str      | merchant description (untrusted text)        |
| `source_url`  | str      | URL that issued the 402                      |

## Real x402 v2 wire format (live `payment-required` parsing)

Real x402 v2 servers (e.g. `agent.massive.com`) return `402 Payment Required`
with an HTTP header named **`payment-required`** (case-insensitive) whose value
is **base64-encoded JSON**. The firewall (`x402_firewall.wire`) decodes that
payload and normalizes it into the internal `PaymentRequest` above. This is
**parsing + normalization + policy evaluation only** — no signing, no settler,
no facilitator.

Decoded shape (the genuine Massive capture committed under `examples/`):

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
      "payTo": "0x525f6dDcE9aF7a7179D7696aaBfCd5FCd15a21e6",
      "maxTimeoutSeconds": 60,
      "extra": {"name": "USD Coin", "version": "2"}
    }
  ],
  "extensions": { "bazaar": { "...": true } }
}
```

Key differences from the internal model, normalized by the parser:

- **Header** — `payment-required` (case-insensitive), base64(JSON).
- **Version** — `x402Version` must be `2`; any other value is rejected with a
  clear error.
- **Payment options** — an `accepts` array (a server may list several). Each
  entry has `scheme`, `network`, `asset`, `amount`, `payTo`,
  `maxTimeoutSeconds`, optional `extra`.
- **Network** — a CAIP-2 chain id. `eip155:8453` = Base mainnet,
  `eip155:84532` = Base Sepolia testnet.
- **Asset** — a **token contract address**, not a symbol. A built-in table maps
  the known Base USDC contract to `USDC`/6 decimals:

  | Network (CAIP-2) | USDC contract                              | Symbol | Decimals |
  |------------------|--------------------------------------------|--------|----------|
  | `eip155:8453`    | `0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913` | `USDC` | 6        |
  | `eip155:84532`   | `0x036CbD53842c5426634e7929541eC2318f3dCF7e` | `USDC` | 6        |

- **Amount** — a **string of atomic integer units** (no `decimals` field in the
  payload). `"10000"` at 6 decimals = `0.01` USDC (human amount
  = `amount_raw / 10**decimals`).
- **No nonce / payee** — there is no top-level nonce or human payee.
  `resource.serviceName` becomes `payee`; `resource.description` →
  `description`; `resource.url` → `source_url`. The normalized request carries
  `nonce = None` (the firewall does **not** fabricate a nonce — real replay
  protection happens on the signed authorization later).

The parser exposes:

- `parse_payment_required_header(value)` — base64-decode + JSON-parse a header
  value.
- `parse_payment_required_json(data)` — typed parse of an already-decoded object.
- `select_option(payment_required, desired_network=None)` — pick the first
  usable `accepts` entry (`scheme == "exact"`, known network + asset).
- `option_to_request(option, resource)` — convert one option into a
  `PaymentRequest` (resolving contract → symbol/decimals, computing the human
  amount).
- `normalize_v2(payload)` — parse + select + convert in one call.
- `evaluate_v2_payment_required(payload, policy, expected_amount=None)` —
  normalize and evaluate against the policy, mapping v2-specific failures to
  clean `DENY` results:
  `malformed`, `unsupported_scheme`, `unsupported_asset`, `no_matching_option`.

Only the `exact` scheme is supported today; other schemes (`upto`, batch,
auth-capture) are future work and are rejected safely with `unsupported_scheme`.
Unknown asset contracts raise a typed `UnknownAssetError` (never a silent
assumption about decimals).

## Policy rules

Rules are evaluated in order; the first hit decides:

| #  | Rule                                        | Verdict          | `rule` id                  |
|----|---------------------------------------------|------------------|----------------------------|
| 1  | Malformed request (missing/invalid/finite)  | DENY             | `malformed`                |
| 2  | `pay_to` not a valid EVM address            | DENY             | `bad_address_format`       |
| 3  | nonce missing/oversized (>1024 chars)       | DENY             | `bad_nonce`                |
| 4  | `source_url` not http(s) with a host        | DENY             | `bad_source_url`           |
| 5  | description too long (>4096 chars)          | DENY             | `description_too_long`     |
| 6  | amount has >6 decimals (sub-cent dust)      | DENY             | `amount_precision`         |
| 7  | asset/network not USDC on Base/Base Sepolia  | DENY             | `asset_network`            |
| 8  | `pay_to` not in `allowed_addresses`         | DENY (or ASK*)   | `unknown_address`          |
| 9  | `amount > max_amount`                       | DENY             | `over_budget`              |
| 10 | nonce already seen                          | DENY             | `nonce_replay`             |
| 11 | description triggers injection scan         | ASK              | `prompt_injection`         |
| 12 | `expected_amount` supplied and differs      | DENY             | `amount_tampering`         |
| 13 | cumulative spend exceeds `total_budget`     | DENY             | `total_budget`             |
| 14 | signed payload required but absent          | DENY             | `signed_payload_required`  |
| 15 | signed payload inconsistent with request    | DENY             | `signed_address_mismatch` / `signed_amount_mismatch` / `signed_asset_mismatch` / `signed_payload_malformed` |
| 16 | all checks pass                             | PAY              | `valid`                    |

\* Rule 8 returns `ASK` when the policy option `ask_on_unknown_address` is
`true`, otherwise `DENY` (safe default).

On a `PAY` or `ASK` verdict the nonce is recorded, so replaying the exact same
request afterwards yields `DENY` (replay). Only `PAY` records spend against the
cumulative budget.

### Signed-payload cross-check

The outer request JSON is not what gets signed — a structured, EIP-712-style
object is. The firewall cross-checks the authoritative **signed payload**
against the validated request fields so an attacker cannot show a whitelisted
address in the JSON while placing a different one in the signed object. This is
a field-level consistency check only (no crypto, no signatures).

The signed payload is a small dict (see
`x402_firewall.models.SignedPayload`):

```json
{
  "recipient": "0x1234567890abcdef1234567890abcdef12345678",
  "amount_raw": "500000",
  "decimals": 6,
  "asset": "USDC",
  "network": "Base",
  "nonce": "nonce-0001"
}
```

- `recipient` — must equal `request.pay_to` (whitespace/lowercase-insensitive).
- `amount_raw` / `decimals` — integer on-chain amount; converted as
  `amount_raw * 10^-decimals` (USDC uses 6 decimals) and compared to
  `request.amount` within epsilon.
- `asset` / `network` — when present, must equal `request.asset` / `request.network`.

Mismatches return `DENY` with rules `signed_address_mismatch`,
`signed_amount_mismatch`, or `signed_asset_mismatch`; a missing/malformed
payload returns `signed_payload_malformed`. When the policy option
`require_signed_payload` is `true` and no payload is supplied, the verdict is
`DENY` with rule `signed_payload_required`. The default is `false` (no payload
required, backward compatible).

### EVM address format

`pay_to` must look like `0x` followed by 40 hex characters; EIP-55 mixed-case,
all-lower, and all-upper are all accepted (the checksum is not verified). An
invalid address is denied early with `bad_address_format`.

### Amount precision / decimals

USDC has 6 decimals on-chain. An amount whose fractional part has more than 6
significant decimals (sub-cent dust that cannot be represented on-chain) is
denied with `amount_precision`. Negligible float noise below the comparison
epsilon is tolerated, so `0.50000000001` still matches an expected `0.5`.

### Policy config

Loadable from JSON:

```json
{
  "allowed_addresses": ["0x1234567890abcdef1234567890abcdef12345678"],
  "max_amount": 1.0,
  "total_budget": 10.0,
  "ask_on_unknown_address": false,
  "require_signed_payload": false
}
```

- `max_amount` — per-request cap.
- `total_budget` — maximum cumulative approved spend across the persistent
  ledger; `null` (the default) means unlimited.
- `ask_on_unknown_address` — `true` turns an unknown `pay_to` into `ASK`.
- `require_signed_payload` — `true` forces a `DENY` (`signed_payload_required`)
  when no signed payload is supplied; default `false`.

The prompt-injection heuristic pattern list lives in one constant,
`x402_firewall.policy.PROMPT_INJECTION_PATTERNS`, so it is easy to extend.

## Persistence (SQLite store)

Nonces and spend are persisted in a SQLite database so replay protection and the
cumulative budget survive process restarts. The store (`x402_firewall.store.Store`)
keeps three tables: `nonces`, `spend` (the ledger), and `decisions` (the audit
trail). The schema is created idempotently on open. The path comes from config;
the sentinel `":memory:"` opens an in-memory database (handy for tests).

The `decisions` audit table carries enriched columns — `asset`, `network`,
`source_url`, `signed_payload_present`, and `decision_duration_ms` — added
idempotently via an additive migration (`ALTER TABLE ... ADD COLUMN` guarded by
a `PRAGMA table_info` check), so **existing databases keep opening** after an
upgrade.

The store is injected into the evaluator/gate. When omitted, the firewall falls
back to in-memory nonce tracking (`PolicyConfig.seen_nonces`).

```python
from x402_firewall import Store, evaluate_payment_request

with Store("x402_firewall.db") as store:
    result = evaluate_payment_request(request, policy, store=store)
```

Recording a nonce is atomic via the `PRIMARY KEY` constraint (duplicate inserts
raise `sqlite3.IntegrityError`, handled internally). The PAY commit path
(`store.record_pay`) wraps nonce-insert + budget-check + spend-insert in a
`BEGIN IMMEDIATE` transaction, so two simultaneous evaluations of the same nonce
or a double-spend near the cap cannot both succeed. All values are bound as SQL
parameters (no string interpolation of nonces/amounts).

### Audit trail export

`Store.list_decisions(limit=None, verdict=None, since=None)` returns audit rows
newest-first, optionally filtered. Use the CLI's `--audit` flag to dump them as
JSON (see below). A separate append-only JSONL event log is available via
`--log PATH` (one machine-readable JSON line per decision). No key material or
secrets are ever written.

## Signing gate

`x402_firewall.gate.guard_payment(...)` is the single choke point an agent calls
immediately before signing. It enforces the authorization contract:

- `PAY`  → allowed.
- `ASK`  → blocked unless human approval is granted
  (`auto_approve_ask=True` or an explicit `approve(gate_result)` call).
- `DENY` → always blocked.

Every gate decision (PAY/ASK/DENY) is written to the store's `decisions` audit
table with a request fingerprint and timestamp.

```python
from x402_firewall import guard_payment, approve, PaymentBlockedError

gr = guard_payment(request, policy, store=store)   # GateResult
if not gr.allowed and gr.result.decision is Verdict.ASK:
    gr = approve(gr)                                # record human approval

try:
    signing_args = gr.signing_authorization()       # raises PaymentBlockedError
except PaymentBlockedError:
    ...                                             # do NOT sign
```

`GateResult.allowed` is the unambiguous boolean; `signing_authorization()`
returns the exact arguments needed to proceed and raises `PaymentBlockedError`
otherwise, so calling code cannot accidentally sign on `DENY`/`ASK`. This is
pure data — no blockchain signing or private keys live here.

## Interactive ASK approval

An `ASK` verdict needs a human decision before the payment can be settled.
`x402_firewall.interactive.interactive_approve(gate_result, input_stream=None,
output_stream=None, max_attempts=3)` presents a clear summary — payee, amount +
asset/network, destination address, nonce, `source_url`, the **untrusted
description clearly labeled**, and the reason it was flagged — then prompts for a
decision.

- `y` / `yes` → approve (goes through `approve(...)`, which records the human
  approval in the audit trail **and** commits spend to the ledger).
- `n` / `no` → reject (no spend, no settlement).
- Anything else re-prompts up to `max_attempts` times, then rejects (safe default).
- EOF / a closed input stream → reject.

The streams are injectable (no hard-wired `input()`), so it is fully testable
without a TTY:

```python
import io
from x402_firewall import guard_payment, interactive_approve, Store, PolicyConfig

gr = guard_payment(request, policy, store=store)   # verdict ASK
approved = interactive_approve(
    gr,
    input_stream=io.StringIO("y\n"),
    output_stream=io.StringIO(),
)
assert approved.allowed
```

### CLI interactive approval

`--interactive` / `-i` runs the prompt when the verdict is `ASK`. Supply the
request via `--request FILE` so stdin is free for the answer (the prompt is
written to stderr, stdout stays machine-readable JSON):

```bash
printf 'y\n' | python3 -m x402_firewall --request examples/request_injection.json \
  --policy examples/policy.json --db :memory: --interactive
# -> {"allowed": true, "approved": true, "decision": "ASK", ...}   (exit 0)

printf 'n\n' | python3 -m x402_firewall --request examples/request_injection.json \
  --policy examples/policy.json --db :memory: --interactive
# -> {"allowed": false, "approved": false, "decision": "ASK", ...}  (exit 4)
```

- approved → exit `0`; rejected (or EOF/invalid input) → exit `4`.
- without `--interactive`, a non-interactive `ASK` still exits `3`.

`--approve` approves an `ASK` deterministically (equivalent to answering yes),
for scripting/automation that has already reviewed the request:

```bash
python3 -m x402_firewall --request examples/request_injection.json \
  --policy examples/policy.json --db :memory: --approve
# -> {"allowed": true, "approved": true, "decision": "ASK", ...}   (exit 0)
```

## End-to-end x402 client flow (simulated transport)

`x402_firewall.client` drives the full purchase loop with the firewall as the
mandatory decision point, using an injectable transport and settler (both are
small ABCs) so tests and demos never touch the network or a chain.

```
agent request ──► Transport ──► 200 (resource)          → status not_required
                          └────► 402 (payment request)   → guard_payment(...)
                                       │
                          PAY ──► settle ──► re-request ──► status paid
                          ASK ──► no handler            → status awaiting
                                  ├─ approval handler (approve/interactive)
                                  │    ├─ allowed ──► settle ──► status paid
                                  │    └─ rejected ─────────────► status rejected
                          DENY ───────────────────────────────► status blocked
```

Settlement is centralized behind `Client._settle`, which checks `allowed` and
obtains `signing_authorization()` (raising `PaymentBlockedError` unless allowed),
so **the settler is unreachable on a DENY or un-approved ASK**.

```python
from x402_firewall import (
    Client, InMemoryServer, FakeSettler, PolicyConfig, Store, approve,
)

policy = PolicyConfig.from_dict({
    "allowed_addresses": ["0x1234567890abcdef1234567890abcdef12345678"],
    "max_amount": 1.0,
})

server = InMemoryServer()
server.add_paid_resource(
    "https://api.example.com/v1/data",
    payment_request={... "pay_to": "0x1234...", "amount": 0.5, ...},
    resource={"data": "the paid resource payload"},
)
settler = FakeSettler(on_settle=server.mark_paid)

with Store(":memory:") as store:
    client = Client(server, settler, policy, store=store)
    outcome = client.run("https://api.example.com/v1/data",
                         expected_amount=0.5,
                         approval_handler=approve)   # or interactive_approve(...)
    print(outcome.to_dict())
```

`ClientOutcome` carries `status` (`not_required` / `paid` / `blocked` /
`rejected` / `awaiting`), the firewall `decision`/`rule`/`reason`, the
`settlement_reference` (if any), and the `resource` (if any). Nonces, spend, and
audit all flow through the same `Store` as direct `guard_payment` calls, so a
full purchase is reflected in one persistent ledger.

### Demo scenarios

Run the whole closed loop from the CLI with `--demo SCENARIO` (in-memory
transport + fake settler; use `--db :memory:` to avoid a file):

```bash
python3 -m x402_firewall --demo clean --db :memory:       # PAY   -> paid (exit 0)
python3 -m x402_firewall --demo injected --db :memory:    # ASK   -> awaiting (exit 3)
python3 -m x402_firewall --demo injected --approve --db :memory:   # ASK approved -> paid (exit 0)
printf 'n\n' | python3 -m x402_firewall --demo injected --interactive --db :memory:  # rejected (exit 4)
python3 -m x402_firewall --demo malicious --db :memory:   # DENY  -> blocked (exit 1)
```

Sample output (clean scenario):

```json
{"outcome": {"decision": "PAY", "reason": "approved payment of 0.5 USDC on Base to 'Example API Merchant'",
             "resource": {"data": "the paid resource payload", "ok": true}, "rule": "valid",
             "settlement_reference": "tx-0001", "status": "paid"},
 "scenario": "clean", "settlement_references": ["tx-0001"], "settler_calls": 1, "total_spent": 0.5}
```

The `settler_calls` count shows settlement only happens on allowed paths.

### Plugging in real transport / settler

`Transport` and `Settler` are ABCs with a single method each. A real HTTP
transport implements `request(url) -> TransportResponse` (returning `200` +
resource or `402` + payment-request payload); a real settler implements
`settle(authorization) -> str` (sign + broadcast, returning a transaction id).
Drop either into `Client(transport, settler, policy, store)` without touching the
orchestrator or the gate. `examples/e2e_demo.py` shows the full loop with the
in-memory implementations and both the interactive and scripted approval
handlers.

## Library usage

```python
from x402_firewall import evaluate_payment_request, PolicyConfig, Verdict

policy = PolicyConfig.from_dict({
    "allowed_addresses": ["0x1234567890abcdef1234567890abcdef12345678"],
    "max_amount": 1.0,
})

result = evaluate_payment_request(
    {"pay_to": "0x1234567890abcdef1234567890abcdef12345678",
     "amount": 0.5, "asset": "USDC", "network": "Base",
     "payee": "Example", "nonce": "n-1",
     "description": "Pay 0.50 USDC for one API call",
     "source_url": "https://api.example.com"},
    policy,
    expected_amount=0.5,
)
assert result.decision is Verdict.PAY
```

`evaluate_payment_request(request, policy, expected_amount=None, store=None,
signed_payload=None)` returns a `Result` with `decision` (a `Verdict` enum),
`reason` (str) and `rule` (str). Pass a structured signed payload as
`signed_payload` to enable the cross-check (see above).

## Running the tests

```bash
python3 -m unittest discover -s tests -v
```

## CLI usage

Read a request from a file or stdin, guard it against a policy, print the gate
result as JSON on stdout, and exit with a code scripts can branch on:

| Exit code | Meaning                            |
|-----------|------------------------------------|
| `0`       | allowed (PAY, ASK auto-approved, or ASK human/scripted-approved) |
| `1`       | DENY (hard denial)                 |
| `2`       | usage / config / IO error          |
| `3`       | ASK (needs human approval)         |
| `4`       | ASK rejected by a human (or EOF/invalid input) — `--interactive` only |

```bash
# clean request -> PAY (exit 0)
python3 -m x402_firewall --request examples/request_ok.json --policy examples/policy.json --db /tmp/firewall.db
# {"allowed": true, "approved": false, "decision": "PAY", "reason": "approved payment of 0.5 USDC on Base to 'Example API Merchant'", "rule": "valid"}

# replay the same request -> DENY (exit 1), persisted across processes
python3 -m x402_firewall --request examples/request_ok.json --policy examples/policy.json --db /tmp/firewall.db
# {"allowed": false, "approved": false, "decision": "DENY", "reason": "nonce 'nonce-0001' was already seen (replay)", "rule": "nonce_replay"}

# injection description -> ASK (exit 3)
python3 -m x402_firewall --request examples/request_injection.json --policy examples/policy.json --db /tmp/firewall.db
# {"allowed": false, "approved": false, "decision": "ASK", "reason": "description triggers prompt-injection heuristic 'ignore_instructions'", "rule": "prompt_injection"}

# query cumulative spend
python3 -m x402_firewall --report --db /tmp/firewall.db
# {"total_spent": 0.5}

# from stdin, in-memory store (no file created)
echo '<request json>' | python3 -m x402_firewall --policy examples/policy.json --db :memory:

# cross-check a signed payload before PAY (exit 0)
python3 -m x402_firewall --request examples/request_ok.json --signed examples/signed_payload_ok.json --policy examples/policy.json --db /tmp/firewall.db
# {"allowed": true, "approved": false, "decision": "PAY", "reason": "approved payment of 0.5 USDC on Base to 'Example API Merchant'", "rule": "valid"}

# tampered signed address -> DENY signed_address_mismatch (exit 1)
python3 -m x402_firewall --request examples/request_ok.json --signed examples/signed_payload_mismatch.json --policy examples/policy.json --db /tmp/firewall.db
# {"allowed": false, "approved": false, "decision": "DENY", "reason": "signed recipient '0x000000000000000000000000000000000000dead' does not match pay_to '0x1234567890abcdef1234567890abcdef12345678'", "rule": "signed_address_mismatch"}

# bad address -> DENY bad_address_format (exit 1)
python3 -m x402_firewall --request examples/request_bad_address.json --policy examples/policy.json --db /tmp/firewall.db
# {"allowed": false, "approved": false, "decision": "DENY", "reason": "pay_to '0x1234' is not a valid EVM address (expected 0x + 40 hex chars)", "rule": "bad_address_format"}

# dump the audit trail as JSON (newest first)
python3 -m x402_firewall --audit --db /tmp/firewall.db
# [{"id": 2, "request_fingerprint": "...", "verdict": "DENY", "rule": "bad_address_format", ...}, ...]

# filtered audit + append-only JSONL event log
python3 -m x402_firewall --audit --verdict DENY --limit 5 --db /tmp/firewall.db
python3 -m x402_firewall --request examples/request_ok.json --policy examples/policy.json --db /tmp/firewall.db --log /tmp/audit.jsonl
```

### Parsing a real x402 v2 `payment-required` header

Feed a captured header value (base64) or an already-decoded JSON object; the CLI
prints the **normalized internal request** plus the gate decision and exits with
the same codes (`PAY` 0 / `DENY` 1 / `ASK` 3 / error 2):

```bash
# (a) base64 header from a file -> normalized request + PAY
python3 -m x402_firewall --payment-required-header examples/massive_payment_required.header.txt \
  --policy examples/massive_policy.json --db :memory:
# {"decision": "PAY", "normalized_request": {"amount": 0.01, "asset": "USDC",
#  "network": "Base", "nonce": null, "payee": "Massive", "pay_to": "0x525f...",
#  "source_url": "https://agent.massive.com/v1/open-close/AAPL/2026-08-14", ...},
#  "reason": "approved payment of 0.01 USDC on Base to 'Massive'", "rule": "valid"}

# (b) decoded JSON -> same result
python3 -m x402_firewall --payment-required-json examples/massive_payment_required.json \
  --policy examples/massive_policy.json --db :memory:

# (c) Massive payTo not whitelisted -> DENY unknown_address (exit 1)
python3 -m x402_firewall --payment-required-json examples/massive_payment_required.json \
  --policy examples/policy.json --db :memory:

# (d) over budget (max_amount < 0.01) -> DENY over_budget (exit 1)

# (e) live fetch (one-off verification only) -> parses the real response header
python3 -m x402_firewall --fetch-url "https://agent.massive.com/v1/open-close/AAPL/2026-08-14" \
  --policy examples/massive_policy.json --db :memory:
```

Malformed v2 payloads map to a clean `DENY` (`malformed`) instead of a
traceback: bad base64, non-object JSON, missing/empty `accepts`, an unsupported
`x402Version`, a non-numeric/negative `amount`, an unknown asset contract
(`unsupported_asset`), or a non-`exact` scheme (`unsupported_scheme`).

Options:

- `--request/-r PATH` — request JSON file (default: stdin).
- `--policy/-p PATH` — policy JSON file (default: `examples/policy.json`).
- `--db PATH` — SQLite store path (default: `x402_firewall.db`; `:memory:` for
  no file).
- `--expected-amount AMOUNT` — enable the amount-tampering check.
- `--total-budget AMOUNT` — override the policy's cumulative spend cap.
- `--auto-approve-ask` — auto-approve `ASK` verdicts.
- `--interactive/-i` — on an `ASK` verdict, prompt a human to approve/reject
  (approved → exit `0`, rejected → exit `4`). Mutually exclusive with `--approve`.
- `--approve` — deterministically approve an `ASK` verdict (equivalent to
  answering yes). Mutually exclusive with `--interactive`.
- `--demo SCENARIO` — run a simulated end-to-end demo (`clean` / `injected` /
  `malicious`) instead of guarding a single request; combine with `--approve` or
  `--interactive` to approve the `injected` scenario.
- `--signed PATH` — structured signed-payload JSON file (`-` for stdin) to
  cross-check against the request before PAY.
- `--require-signed` — force `DENY` (`signed_payload_required`) when no signed
  payload is supplied.
- `--report` — print the cumulative spend total and exit.
- `--audit` — dump the decision audit trail as JSON and exit (use `--limit N`
  and `--verdict PAY|ASK|DENY` to filter).
- `--log PATH` — append one JSON line per decision to this file (JSONL).
- `--payment-required-header PATH` — parse a real x402 v2 `payment-required`
  header value (base64) from a file (`-` for stdin).
- `--payment-required-json PATH` — parse an already-decoded v2 payment-required
  JSON object from a file (`-` for stdin).
- `--fetch-url URL` — fetch a URL live and parse its `payment-required` header
  (one-off verification only; not for routine use).

## Base Sepolia testnet integration (real EIP-3009 signing)

The firewall core stays dependency-free; a separate `integration/` package is
the only place the official `x402` SDK is imported, to run the full closed loop
on **Base Sepolia testnet** with a real EIP-3009 `transferWithAuthorization`
signature and real facilitator `/verify` + `/settle`:

```
request ─► 402 payment-required ─► OUR wire parser ─► OUR guard_payment
        ─► (allowed only) x402 SDK EIP-3009 sign ─► free facilitator verify/settle
        ─► paid resource
```

The orchestrator (`integration/testnet_runner.py`) is stdlib-only and injectable,
so the signer/facilitator are **unreachable unless the gate returns allowed** (it
obtains authorization via `GateResult.signing_authorization()`, which raises
`PaymentBlockedError` on any blocked verdict).

### Network support

`x402_firewall.policy` now accepts **`Base` and `Base Sepolia`** (case-insensitive)
as canonical networks (`CANONICAL_NETWORKS`), so a Sepolia-derived request
(`eip155:84532` → `"Base Sepolia"`) gates cleanly to `PAY`. The store also records
spend for v2 requests that carry no nonce (empty-string ledger entry; no fabricated
nonce — replay protection stays on the signed authorization).

### Setup (isolated venv)

```bash
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python "x402[evm,httpx]==2.23.0" web3
```

### Test account + funding (⚠️ needs a human)

```bash
.venv/bin/python -m integration.create_eoa   # -> address, key in integration/.env.testnet (gitignored)
.venv/bin/python -m integration.fund_account # -> on-chain balances
```

The Circle faucet (`https://faucet.circle.com`) requires a browser wallet connect
and a Google reCAPTCHA, so it **cannot be automated**. Fund the printed address
with Base Sepolia test USDC there, then re-run `fund_account` to verify the balance
before the live run. (Base Sepolia test ETH is not required — the facilitator's
EIP-3009 settlement is gasless for the payer.)

### Live run

```bash
.venv/bin/python -m integration.live --policy integration/policy.testnet.json
```

`integration/live.py` starts a local x402 resource server (Base Sepolia USDC,
`exact` scheme), fetches the real `402`, parses it with `x402_firewall.wire`,
gates it with `guard_payment`, then (only when allowed) signs EIP-3009 via the
SDK and calls the free facilitator at `https://x402.org/facilitator`. On a
successful `/settle` it calls `Local402Server.mark_paid()`, which flips the local
server's paid flag (synced to the handler's HTTP server) so the same URL then
serves `200` with the resource JSON; this is reported as
`resource_after_payment.status`. It also prints the account + balances, the
parsed 402, the gate decision, the facilitator verify/settle responses, the tx
hash, and the explorer URL.

### Offline wiring tests

`tests/test_testnet_wiring.py` (stdlib-only, no SDK, no funds) asserts the
wiring with a fake signer/facilitator: DENY → signer never invoked; PAY → signer
invoked exactly once with the selected v2 option; ASK → no sign until approved.
`tests/test_local_server.py` (stdlib-only) asserts the offline `402 → mark_paid →
200` contract: `Local402Server` returns `402` until `mark_paid()`, then `200`
with the resource JSON.

```bash
python3 -m unittest discover -s tests   # 150 tests
```

### Status (2026-09-30)

The full loop is verified live end-to-end on Base Sepolia: a real `402` was
parsed, gated to `PAY`, a real EIP-3009 signature was produced and accepted by
the free facilitator's `/verify`, `/settle` succeeded with a real testnet tx
hash, and the resource re-fetch after settlement returned `200`
(`resource_after_payment.status = 200`).
