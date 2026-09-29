# Task: x402 Firewall P0 — Persistence, Spend Budget, Signing Gate

## Goal
Upgrade the existing MVP in this repo into a usable firewall by adding the three P0
items. The existing pure-Python, standard-library-only, CPU-only constraints still
apply. **No third-party packages, no network, no on-chain keys.** Existing tests must
keep passing; new behavior gets real tests.

Current code: `x402_firewall/models.py` (PaymentRequest, Verdict, Result,
MalformedRequestError), `x402_firewall/policy.py` (PolicyConfig,
evaluate_payment_request, scan_description), `x402_firewall/cli.py`, examples, tests.

## Item 1 — Persistent nonce + spend store (SQLite via stdlib `sqlite3`)

The in-memory `seen_nonces` set is lost on process restart, allowing replays after a
restart. Introduce a small storage layer (e.g. `x402_firewall/store.py`) backed by a
SQLite database file:

- Table for consumed nonces: at minimum `(nonce TEXT PRIMARY KEY, pay_to TEXT,
  amount REAL, decision TEXT, created_at TEXT)`. Recording a nonce must be atomic and
  reject duplicates via the PRIMARY KEY (use INSERT, catch IntegrityError) — that is
  what makes replay detection safe across processes/threads.
- Table (or rows) for spend ledger: every approved `PAY` appends a row with
  `(amount, asset, network, pay_to, payee, nonce, created_at)` so cumulative spend can
  be summed.
- Provide a clean interface with methods such as `nonce_seen(nonce)`,
  `record_nonce(...)`, `total_spent(...)`, `record_spend(...)`, and a `close()`.
  Support a context manager (`with`). Use a file path supplied by config; if the path
  is the special sentinel `":memory:"` use an in-memory DB (useful for tests).
- The schema must be created idempotently (`CREATE TABLE IF NOT EXISTS`) on open.
- Keep an in-memory implementation option too (or a shared interface) so existing
  zero-file usage and tests still work without forcing a DB file. The evaluator should
  accept the store via dependency injection.

## Item 2 — Cumulative spend budget

Extend policy config with:

- `total_budget`: maximum cumulative approved spend (across the ledger), e.g. per
  period. A sensible default may be unlimited (None) but it must be explicit.
- Optional `period` concept for P0 is NOT required — a simple running cumulative cap
  over the persistent ledger is sufficient. (Do not build calendar/reset complexity;
  cumulative-since-store is fine.) Do not over-engineer.

Evaluation rule: when a request otherwise would `PAY`, first compute
`already_spent + amount`; if it exceeds `total_budget` -> `DENY`, rule id
`total_budget`, reason stating spent/amount/cap numbers. Because spend is read from the
persistent store, the cap must survive process restarts. Record the spend only on a
final `PAY` (never on DENY; for ASK record the nonce but do NOT add spend). Order this
check before the final PAY and after the per-request `over_budget` check; place it
logically with the other budget rules and update the rule-order doc comment.

Handle concurrency safely: the nonce-insert uniqueness and the spend-then-decide flow
should be inside a DB transaction so two simultaneous evaluations of the same nonce or
a double-spend near the cap cannot both succeed. Use `BEGIN IMMEDIATE` or equivalent
locking and test that duplicate nonce insert is rejected.

## Item 3 — Hard signing gate

Add a guard function (e.g. in `x402_firewall/gate.py`) that is the single choke point
an agent calls immediately before signing. It must make bypassing the decision
difficult:

- Function such as `guard_payment(request, policy, store=None, expected_amount=None,
  auto_approve_ask=False) -> GateResult` (names adaptable). It evaluates via
  `evaluate_payment_request` and enforces:
  - `PAY` -> allowed.
  - `ASK` -> blocked unless an explicit human approval token/flag is supplied
    (`auto_approve_ask=True` or an explicit approve call). Provide a separate
    `approve(gate_result)` style path that records the human approval and then allows.
  - `DENY` -> always blocked.
- The returned object must expose an unambiguous boolean `allowed` plus the underlying
  Result. Provide a method/property that returns the exact arguments needed to proceed
  only when allowed, and raise a clear exception (e.g. `PaymentBlockedError`) if code
  tries to obtain signing authorization while not allowed. The point: calling code
  cannot accidentally sign on DENY/ASK.
- Persist every gate decision (verdict, rule, reason, request fingerprint, timestamp)
  to the SQLite store in an audit/decisions table so there is an auditable trail. The
  audit row must be written for PAY, ASK and DENY.
- Keep it pure data: no actual blockchain signing, no private keys. This is the
  authorization gate, not a wallet.

## CLI updates
- Add `--db PATH` (default can be a local file like `x402_firewall.db` or a config
  value; document it; support `:memory:`) and `--total-budget AMOUNT`.
- Add a subcommand or flags to (a) evaluate/guard a request and print the gate result
  JSON including `allowed`, and (b) query current cumulative spend (e.g.
  `--report` / `spent` command) printing total spent from the store.
- Exit codes: not allowed (DENY) -> non-zero; PAY allowed -> 0; ASK -> a distinct
  non-zero code (choose e.g. 3) so scripts can tell "needs approval" apart from hard
  denial. Document the codes.
- Keep all existing invocation styles working.

## Examples / docs
- Update `examples/policy.json` (add `total_budget`) and add any new example requests.
- Add an example showing the store file and a guard invocation.
- Update README: storage/persistence section, cumulative budget rule, the signing
  gate contract (PAY/ASK/DENY + approval), CLI exit codes, and how to query spend.
- Update rule-order tables/comments to include `total_budget` and the gate.

## Tests — real, stdlib unittest, must cover
Persistence:
1. nonce recorded then seen across two store connections (simulate restart by closing
   and reopening the same file path) -> replay DENY.
2. duplicate concurrent/sequential nonce insert raises/handles IntegrityError and the
   second decision is DENY.
3. spend ledger records only on PAY; total_spent sums correctly; ASK and DENY add zero
   spend.
Budget:
4. cumulative cap: approve requests up to the cap, then the request that would cross
   it -> DENY `total_budget` with numbers in reason.
5. cumulative spend persists across a store close/reopen (restart) and the cap still
   blocks.
Gate:
6. PAY -> allowed True; DENY -> allowed False and attempting to get authorization
   raises PaymentBlockedError; ASK -> allowed False until explicit approval, then
   allowed True.
7. every gate decision writes an audit row (assert rows for PAY/ASK/DENY with verdict
   and rule).
Also run the FULL existing suite — all prior tests still pass (in-memory path).

## Success criteria — run all yourself, paste REAL output
1. `python3 -m unittest discover -s tests -v` -> all tests (old + new) pass, zero
   skips; paste full output with the new total count.
2. `python3 -m py_compile` over every module -> OK.
3. Real CLI demo on a TEMP db file (use a tmp path so you do not pollute the repo):
   - guard an ok request -> allowed true, exit 0
   - replay same request (same db) -> DENY, exit non-zero
   - close/reopen equivalent: run a second CLI invocation against the same db file and
     show replay still denied (proves persistence across processes)
   - push cumulative spend over total_budget -> DENY total_budget
   - spend report command prints real cumulative total
   Paste exact commands and JSON output. Clean up the temp db afterward.
4. README updated and accurate; then git commit everything (tests green).

## Constraints / FORBIDDEN
- Work only inside `/home/kings/projects/x402-firewall`.
- Python stdlib only (`sqlite3` included). No pip installs, no network, no GPU, no
  wallet keys or real signing.
- Do not break existing tests or CLI invocations.
- Do not stub or fabricate test/CLI output — actually execute and paste real results.
- Do not add calendar/period reset, servers, or third-party deps — cumulative-since-store
  is enough for P0.
- Never invent unsupported CLI flags; use argparse and make them real.
