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
| 7  | asset/network not USDC/Base                 | DENY             | `asset_network`            |
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
| `0`       | allowed (PAY, or ASK auto-approved)|
| `1`       | DENY (hard denial)                 |
| `3`       | ASK (needs human approval)         |

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

Options:

- `--request/-r PATH` — request JSON file (default: stdin).
- `--policy/-p PATH` — policy JSON file (default: `examples/policy.json`).
- `--db PATH` — SQLite store path (default: `x402_firewall.db`; `:memory:` for
  no file).
- `--expected-amount AMOUNT` — enable the amount-tampering check.
- `--total-budget AMOUNT` — override the policy's cumulative spend cap.
- `--auto-approve-ask` — auto-approve `ASK` verdicts.
- `--signed PATH` — structured signed-payload JSON file (`-` for stdin) to
  cross-check against the request before PAY.
- `--require-signed` — force `DENY` (`signed_payload_required`) when no signed
  payload is supplied.
- `--report` — print the cumulative spend total and exit.
- `--audit` — dump the decision audit trail as JSON and exit (use `--limit N`
  and `--verdict PAY|ASK|DENY` to filter).
- `--log PATH` — append one JSON line per decision to this file (JSONL).
