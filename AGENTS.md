# Task: x402 Payment Firewall MVP (Python)

## Goal
Build a minimal, runnable **x402 payment-request firewall**: before an agent signs an
x402 HTTP-402 payment, it validates the payment request against a local policy and
returns one of `PAY` / `ASK` / `DENY` with a human-readable reason.

This is a pure-software, CPU-only MVP: validator library + CLI/function entry point +
unit tests. **No on-chain signing, no HTTP server, no network calls.**

## Background
An agent sends an HTTP request and the server replies `402 Payment Required` carrying
a payment request (payTo address, amount, asset + network, payee, nonce, description,
source URL). The agent must validate this *before* signing. Attacks this firewall
must catch:

1. **Amount tampering** — amount differs from what the agent expected.
2. **Address substitution** — pay_to / payee address swapped to an attacker address.
3. **Nonce replay** — the same nonce was already approved.
4. **Over budget** — amount exceeds the per-request / total budget.
5. **Description prompt injection** — the `description` field contains prompt-injection
   payloads aimed at the downstream LLM (e.g. "ignore previous instructions",
   "system:", role-play / exfiltration phrasing).
6. **Asset/network mismatch** — anything other than USDC on Base.

## Required data structure
A payment request object with fields:

- `pay_to` (str): destination address.
- `amount` (number, > 0): payment amount in human units (USDC, e.g. 0.50).
- `asset` (str): asset id, canonical value `"USDC"`.
- `network` (str): network id, canonical value `"Base"`.
- `payee` (str): payee identity/name.
- `nonce` (str): one-time nonce.
- `description` (str): merchant-provided description (untrusted text).
- `source_url` (str): the URL that issued the 402.

You may add a small typed container (dataclass or TypedDict) plus JSON parsing with
basic validation of required fields and types.

## Policy rules (evaluator returns PAY / ASK / DENY + reason)
The validator takes the payment request plus a **policy config**, which should include
at least:

- `allowed_addresses`: whitelist of acceptable `pay_to` addresses.
- `max_amount`: per-request budget.
- `expected_amount`: the amount the agent expected for this action (may be supplied per
  call).
- a **seen-nonce store** (in-memory set is fine) for replay detection.

Rules, in evaluation order (first hit decides):

1. Malformed request (missing/invalid fields) → `DENY`.
2. `asset != "USDC"` or `network != "Base"` (case-insensitive match) → `DENY`.
3. `pay_to` not in `allowed_addresses` → `ASK` if a separate `ask_on_unknown_address`
   option is set, otherwise `DENY`. Pick a safe default (DENY) and make it configurable;
   write a test for both the ASK and DENY paths.
4. `amount > max_amount` (over budget) → `DENY`.
5. nonce already seen → `DENY`. On a `PAY`/`ASK` verdict the nonce is recorded;
   replaying the exact same request afterwards must yield `DENY` (replay).
6. prompt-injection scan of `description` hits → `ASK` (never auto-pay). Implement a
   small, dependency-free heuristic scanner: patterns such as
   "ignore (all|previous|prior|above) instructions", "disregard ...", "you are",
   "new instructions", "system prompt", role markers like "</>", "[system]",
   "reveal/leak/exfiltrate ... (prompt|instructions|secret|api key)",
   base64/data-exfil hints, etc. Case-insensitive, word-boundary tolerant. Keep the
   pattern list in one clearly named constant so it is easy to extend. Do not over-flag:
   a plain benign description ("Pay 0.50 USDC for one API call") must pass.
7. `expected_amount` provided and `amount != expected_amount` (amount tampering) →
   `DENY`. Use a small epsilon for float comparison.
8. All checks pass → `PAY`.

Return a decision object: `decision` (`PAY|ASK|DENY`), `reason` (string), and
optionally the id/name of the matched rule. Every reason must be a concrete,
human-readable explanation (e.g. "amount 5.0 exceeds budget 1.0").

## Entry point
- A CLI that reads a payment request as JSON: from a file path argument or stdin,
  prints the decision + reason as JSON on stdout, and exits non-zero on DENY.
- Also expose a plain Python function entry point (e.g. `evaluate_payment_request(...)`)
  usable as a library.
- Keep policy config loadable from a JSON file with sensible defaults; an example
  policy JSON must be included.

Example invocation shapes (adapt names to your structure):

```bash
echo '<request json>' | python -m x402_firewall --policy examples/policy.json
python -m x402_firewall --request examples/request_ok.json --policy examples/policy.json
```

## Project structure
You choose the layout and test framework, but:
- Keep it tiny and use the **Python standard library only** — no third-party runtime
  deps. Tests may use the stdlib `unittest` (preferred, zero install) or pytest if
  already available on the machine; verify the runner actually exists before choosing.
- Suggested: package dir `x402_firewall/` with `models.py`, `policy.py` (validator +
  injection scanner), `cli.py`, `__main__.py`; `tests/`; `examples/`; `README.md`.

## Tests — must be real and cover EVERY rule
At minimum one test per rule:

1. valid request → PAY
2. asset/network mismatch (each wrong, plus wrong-case inputs) → DENY
3. unknown pay_to address → DENY (default) and ASK (with ask option)
4. amount over budget → DENY
5. nonce replay across two evaluations → DENY; distinct nonces pass
6. injection description (at least 3 different payload styles) → ASK; benign
   description does NOT trigger
7. amount != expected_amount → DENY; equal-within-epsilon passes
8. malformed requests (missing field, negative amount, wrong type) → DENY

Tests must actually assert on the decision enum AND the reason/rule id. No placeholder,
no skipped tests.

## Success criteria (run ALL of these yourself before finishing)
1. `python3 -m unittest discover -s tests -v` (or your chosen runner) — every test
   passes; paste the full real output.
2. Run at least 3 real CLI examples through stdin/file:
   - a clean request → PAY (exit 0)
   - an over-budget or wrong-address request → DENY (exit non-zero)
   - an injection-description request → ASK
   Paste exact commands and their real JSON output.
3. `python3 -m py_compile` across all modules succeeds.
4. README.md exists with: purpose, data structure, policy rules table, how to run
   tests, and the CLI usage examples with sample output.

## Constraints
- Work only inside `/home/kings/projects/x402-firewall`. Do not touch files elsewhere.
- Python 3 standard library only. No pip installs, no network access, no GPU usage.
- No blockchain signing, no wallet keys, no server/daemon.
- Finish with a git commit of the working MVP (all tests green).
- If a chosen tool/runner does not exist or fails, fall back to stdlib `unittest`
  rather than installing anything.

## FORBIDDEN
- Do not fabricate or stub test output — actually run the tests and paste real output.
- Do not write an empty `pass`-bodied implementation; the validator and scanner must
  contain the real logic described above.
- Do not invent CLI flags that the task does not support; use simple argparse flags.
