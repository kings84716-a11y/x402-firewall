# x402 Payment Firewall (MVP)

A minimal, dependency-free Python validator that inspects an **x402 payment
request** (the payload behind an HTTP `402 Payment Required`) before an agent
signs it. It compares the request against a local policy and returns one of
`PAY` / `ASK` / `DENY` with a concrete, human-readable reason.

Pure software, CPU-only, standard-library only: **no on-chain signing, no HTTP
server, no network calls.**

## Purpose

An agent sends an HTTP request; the server replies `402 Payment Required`
carrying a payment request (destination address, amount, asset/network, payee,
nonce, description, source URL). This firewall validates that request *before*
signing, catching:

1. Amount tampering — amount differs from what the agent expected.
2. Address substitution — `pay_to` swapped to an attacker address.
3. Nonce replay — the same nonce was already approved.
4. Over budget — amount exceeds the per-request / total budget.
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

| # | Rule                                  | Verdict          | `rule` id            |
|---|---------------------------------------|------------------|----------------------|
| 1 | Malformed request (missing/invalid)   | DENY             | `malformed`          |
| 2 | asset/network not USDC/Base           | DENY             | `asset_network`      |
| 3 | `pay_to` not in `allowed_addresses`   | DENY (or ASK*)   | `unknown_address`    |
| 4 | `amount > max_amount`                 | DENY             | `over_budget`        |
| 5 | nonce already seen                    | DENY             | `nonce_replay`       |
| 6 | description triggers injection scan   | ASK              | `prompt_injection`   |
| 7 | `expected_amount` supplied and differs| DENY             | `amount_tampering`   |
| 8 | all checks pass                       | PAY              | `valid`              |

\* Rule 3 returns `ASK` when the policy option `ask_on_unknown_address` is
`true`, otherwise `DENY` (safe default).

On a `PAY` or `ASK` verdict the nonce is recorded, so replaying the exact same
request afterwards yields `DENY` (replay).

### Policy config

Loadable from JSON:

```json
{
  "allowed_addresses": ["0x1234567890abcdef1234567890abcdef12345678"],
  "max_amount": 1.0,
  "ask_on_unknown_address": false
}
```

The prompt-injection heuristic pattern list lives in one constant,
`x402_firewall.policy.PROMPT_INJECTION_PATTERNS`, so it is easy to extend.

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

`evaluate_payment_request(request, policy, expected_amount=None)` returns a
`Result` with `decision` (a `Verdict` enum), `reason` (str) and `rule` (str).

## Running the tests

```bash
python3 -m unittest discover -s tests -v
```

## CLI usage

Read a request from a file or stdin, print the decision as JSON on stdout, and
exit non-zero on `DENY`:

```bash
# clean request -> PAY (exit 0)
python3 -m x402_firewall --request examples/request_ok.json --policy examples/policy.json
# {"decision": "PAY", "reason": "approved payment of 0.5 USDC on Base to 'Example API Merchant'", "rule": "valid"}

# over-budget request -> DENY (exit 1)
python3 -m x402_firewall --request examples/request_over_budget.json --policy examples/policy.json
# {"decision": "DENY", "reason": "amount 5.0 exceeds budget 1.0", "rule": "over_budget"}

# injection description -> ASK (exit 0)
python3 -m x402_firewall --request examples/request_injection.json --policy examples/policy.json
# {"decision": "ASK", "reason": "description triggers prompt-injection heuristic 'ignore_instructions'", "rule": "prompt_injection"}

# from stdin
echo '<request json>' | python3 -m x402_firewall --policy examples/policy.json
```

Optional `--expected-amount AMOUNT` enables the amount-tampering check.
