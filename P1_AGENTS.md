# Task: x402 Firewall P1 — Signed-Payload Cross-Check, Hardening, Audit Enhancements

## Goal
Harden the existing firewall in this repo (MVP + P0 already shipped). Keep the same
hard constraints: **Python standard library only, CPU-only, no third-party packages,
no network calls, no wallet keys or real signing.** All existing tests must keep
passing; every new behavior gets real stdlib-unittest tests.

Current modules: `models.py` (PaymentRequest, Verdict, Result, MalformedRequestError),
`policy.py` (PolicyConfig, evaluate_payment_request, scan_description, rule order),
`store.py` (Store over SQLite: nonces / spend / decisions), `gate.py` (guard_payment,
approve, GateResult, PaymentBlockedError, fingerprint), `cli.py`, examples, tests.

## Item 1 — Signed-payload cross-check (defeat JSON↔signature inconsistency)

Threat: the outer request JSON the validator reads (pay_to/amount) can differ from
the actual structured payload that gets signed (an EIP-719/EIP-712-style typed
object). An attacker could show a whitelisted address in the JSON but place an
attacker address in the signed payload. Add a cross-check that compares the
authoritative **signed payload** against the validated request fields.

Requirements:

- Add an optional representation of the structured/signed payload (pure data, e.g. a
  dict shaped like EIP-712 typed data, or a small typed container). Define the minimal
  shape yourself: it must carry the destination/recipient (address), the amount (and
  its decimals/unit), and ideally the asset + a nonce. Do NOT implement crypto
  signing or ecrecover — this is a field-level consistency check only.
- Add a function (e.g. `cross_check_signed_payload(request, signed_payload)`) that
  verifies, with concrete DENY reasons and stable rule ids:
  1. signed payload recipient address == request.pay_to (normalize
     whitespace/lowercase like the rest) -> mismatch: DENY rule
     `signed_address_mismatch`.
  2. signed amount (after applying declared token decimals, e.g. USDC = 6) ==
     request.amount within the existing epsilon -> mismatch: DENY rule
     `signed_amount_mismatch`. Handle the common on-chain integer form
     (amount_raw * 10^-decimals).
  3. signed asset/symbol (when present) == request.asset and chain/network (when
     present) == request.network -> mismatch: DENY rule `signed_asset_mismatch`.
  4. missing/malformed signed payload when one is required -> DENY rule
     `signed_payload_malformed`.
- Integrate into the gate: `guard_payment(...)` should accept the optional signed
  payload and run the cross-check as part of evaluation BEFORE returning PAY. If no
  signed payload is supplied, preserve backward compatibility (do not break existing
  callers/tests) — but provide a policy option `require_signed_payload` (default
  False) that, when True, forces a DENY if it is absent (rule
  `signed_payload_required`).
- Also validate basic address syntax for the network. For Base/EVM an address must
  look like `0x` + 40 hex chars (EIP-55 mixed-case or all-lower/all-upper accepted);
  invalid `pay_to` -> DENY rule `bad_address_format`, checked early alongside
  malformed. This applies to the request address regardless of signed payload.

## Item 2 — Input & edge-case hardening

Tighten validation and make failure modes deterministic. Add tests for each:

- Numeric: NaN and Infinity amounts must be rejected (DENY). Extremely large /
  scientific-notation / very high precision amounts must not crash and must compare
  safely against budgets (float is acceptable but must not raise). Amounts with more
  than the token's supported precision (e.g. > 6 decimals for USDC) -> DENY rule
  `amount_precision` (sub-cent dust that cannot be represented on-chain).
- Types: reject bool masquerading as number (already partly handled — extend to
  expected_amount and budgets), reject amount as numeric string unless you explicitly
  choose to coerce (pick a strict rule: do NOT silently coerce strings; malformed),
  and ensure nested objects/arrays in string-only fields are rejected.
- URL validation: `source_url` must be http/https with a host; reject
  `javascript:`, `data:`, file paths, or empty host -> DENY rule `bad_source_url`.
  Do not fetch the URL.
- Nonce: enforce a minimum/maximum length sanity range (e.g. non-empty and not
  absurdly long, cap like 1024 chars) -> DENY rule `bad_nonce`.
- Description length cap (e.g. <= 4096 chars) to prevent abuse; oversize -> DENY
  rule `description_too_long` (decide and document; safer as DENY).
- Policy/config errors: loading a policy or store path that is invalid, a policy that
  is not an object, negative/zero budgets, or a non-writable DB path must raise a
  clear, specific exception or produce a clean error — never a raw traceback to the
  user via the CLI (CLI must print `error: ...` and exit 2).
- Ensure DB access is robust: guard with parameterized queries (verify no string
  interpolation of nonce/amount into SQL), and confirm operations still work after a
  reopen.

## Item 3 — Audit enhancements

Make the audit trail genuinely useful and exportable:

- Enrich decision rows: add columns for `asset`, `network`, `source_url`,
  `signed_payload_present`, and `decision_duration_ms` (or timing) where reasonable.
  Use additive, idempotent schema changes (`ALTER TABLE ... ADD COLUMN` guarded so it
  works on existing DBs and does not fail if columns exist; or a small versioned
  migration). Existing DBs must still open.
- Add an export/query API on `Store` (e.g. `list_decisions(limit=..., verdict=...,
  since=...)` returning ordered rows, newest first) and a CLI command/flag to dump
  the audit trail as JSON (e.g. `--audit` with optional `--limit`, `--verdict`).
- Add a structured event/audit log writer to a file **in addition to** SQLite? Keep it
  simple: instead of a second log system, ensure the CLI/guard can emit one
  machine-readable JSON line per decision when a flag like `--log PATH` is given
  (append-only JSONL). Optional and default-off; test that the line is well-formed.
- Redaction: ensure no secrets are written (there are none currently — keep it that
  way; do not log any key material).

## CLI updates
- New flags: `--signed PATH` (read structured signed payload JSON from file/stdin),
  `--require-signed`, `--audit` (with `--limit`, `--verdict`), optional `--log PATH`.
- Keep every existing flag and invocation working; existing exit codes (PAY 0, DENY 1,
  ASK 3, usage/config error 2) unchanged.
- Ensure errors print `error: ...` to stderr and exit 2 (no raw tracebacks).

## Examples / docs
- Add `examples/signed_payload_ok.json` and a mismatch example; a request with a bad
  address / bad URL if helpful.
- Update `examples/policy.json` only if you add `require_signed_payload` (keep it
  explicit; default false).
- Update README: signed-payload cross-check rules + rule ids, EVM address format,
  amount precision/decimals, new validation rules, audit export + JSONL log, all CLI
  flags, and the full rule-order table.

## Tests — real stdlib unittest, must cover
Signed cross-check / address:
1. consistent signed payload -> PAY; address mismatch -> DENY signed_address_mismatch
2. amount mismatch via raw integer + 6 decimals -> DENY signed_amount_mismatch;
   correct raw conversion passes
3. asset/network mismatch -> DENY signed_asset_mismatch
4. malformed signed payload -> DENY signed_payload_malformed; require_signed_payload
   with none -> DENY signed_payload_required; default still allows none
5. bad EVM address formats (wrong length / non-hex / missing 0x) -> DENY
   bad_address_format; valid mixed-case + lowercase pass
Hardening:
6. NaN / Infinity / bool amount -> DENY; huge & high-precision amount does not crash
7. sub-cent precision (> 6 decimals) -> DENY amount_precision
8. bad source_url (javascript:, data:, no host) -> DENY bad_source_url; https passes
9. oversize nonce/description -> DENY (bad_nonce / description_too_long)
10. policy/config & db path errors -> clear exception/CLI error exit 2, no traceback
Audit:
11. enriched columns populated; audit export filters by verdict and orders newest first
12. JSONL --log writes well-formed line(s); existing DBs without new columns still open
Also: run the FULL suite — all prior 42 tests still pass.

## Success criteria — run all yourself, paste REAL output
1. `python3 -m unittest discover -s tests -v` -> all tests (old + new) pass, zero
   skips; paste full output with the new total count.
2. `python3 -m py_compile` over every module -> OK.
3. Real CLI demo on TEMP files (tmp db, tmp log, clean up after):
   - request with a matching signed payload -> allowed PAY, exit 0
   - same with a tampered signed address -> DENY signed_address_mismatch, exit 1
   - bad source_url / bad address example -> DENY, exit 1
   - `--audit` dumps real rows as JSON; `--log` writes a real JSONL line
   Paste exact commands and outputs.
4. Verify an OLD-style database (create minimal legacy tables if practical, or rely on
   the additive migration) still opens after the schema change.
5. README updated and accurate; then git commit everything (tests green).

## Constraints / FORBIDDEN
- Work only inside `/home/kings/projects/x402-firewall`.
- Python stdlib only. No pip installs, no network, no GPU, no crypto signing, no keys.
- Do not break existing tests, flags, exit codes, or DB open compatibility.
- No string-interpolated SQL (parameterize). No raw tracebacks to CLI users.
- Do not stub/fabricate test or CLI output — actually run and paste real results.
- Do not add servers, calendar resets, third-party deps, or real blockchain operations.
