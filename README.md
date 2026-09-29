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

| # | Rule                                     | Verdict          | `rule` id            |
|---|------------------------------------------|------------------|----------------------|
| 1 | Malformed request (missing/invalid)      | DENY             | `malformed`          |
| 2 | asset/network not USDC/Base              | DENY             | `asset_network`      |
| 3 | `pay_to` not in `allowed_addresses`      | DENY (or ASK*)   | `unknown_address`    |
| 4 | `amount > max_amount`                    | DENY             | `over_budget`        |
| 5 | nonce already seen                       | DENY             | `nonce_replay`       |
| 6 | description triggers injection scan      | ASK              | `prompt_injection`   |
| 7 | `expected_amount` supplied and differs   | DENY             | `amount_tampering`   |
| 8 | cumulative spend exceeds `total_budget`  | DENY             | `total_budget`       |
| 9 | all checks pass                          | PAY              | `valid`              |

\* Rule 3 returns `ASK` when the policy option `ask_on_unknown_address` is
`true`, otherwise `DENY` (safe default).

On a `PAY` or `ASK` verdict the nonce is recorded, so replaying the exact same
request afterwards yields `DENY` (replay). Only `PAY` records spend against the
cumulative budget.

### Policy config

Loadable from JSON:

```json
{
  "allowed_addresses": ["0x1234567890abcdef1234567890abcdef12345678"],
  "max_amount": 1.0,
  "total_budget": 10.0,
  "ask_on_unknown_address": false
}
```

- `max_amount` — per-request cap.
- `total_budget` — maximum cumulative approved spend across the persistent
  ledger; `null` (the default) means unlimited.
- `ask_on_unknown_address` — `true` turns an unknown `pay_to` into `ASK`.

The prompt-injection heuristic pattern list lives in one constant,
`x402_firewall.policy.PROMPT_INJECTION_PATTERNS`, so it is easy to extend.

## Persistence (SQLite store)

Nonces and spend are persisted in a SQLite database so replay protection and the
cumulative budget survive process restarts. The store (`x402_firewall.store.Store`)
keeps three tables: `nonces`, `spend` (the ledger), and `decisions` (the audit
trail). The schema is created idempotently on open. The path comes from config;
the sentinel `":memory:"` opens an in-memory database (handy for tests).

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
or a double-spend near the cap cannot both succeed.

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

`evaluate_payment_request(request, policy, expected_amount=None, store=None)`
returns a `Result` with `decision` (a `Verdict` enum), `reason` (str) and
`rule` (str).

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
```

Options:

- `--request/-r PATH` — request JSON file (default: stdin).
- `--policy/-p PATH` — policy JSON file (default: `examples/policy.json`).
- `--db PATH` — SQLite store path (default: `x402_firewall.db`; `:memory:` for
  no file).
- `--expected-amount AMOUNT` — enable the amount-tampering check.
- `--total-budget AMOUNT` — override the policy's cumulative spend cap.
- `--auto-approve-ask` — auto-approve `ASK` verdicts.
- `--report` — print the cumulative spend total and exit.
