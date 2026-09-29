# Task: x402 Firewall P2 — Interactive Approval + End-to-End Client Flow

## Goal
Make the firewall usable inside a real purchase flow. Same hard constraints still
apply: **Python standard library only, CPU-only, no third-party packages, no real
network calls in tests, no wallet keys or real on-chain signing.** All existing tests
(88) must keep passing; new behavior gets real stdlib-unittest tests.

Existing modules: `models.py`, `policy.py` (evaluate_payment_request, scan_description),
`store.py` (Store: nonces/spend/decisions + migration), `gate.py` (guard_payment,
approve, GateResult, PaymentBlockedError), `cli.py`, examples.

## Item 1 — Interactive ASK approval flow

Today an ASK verdict can only be approved via the library `approve()`. Add a way for a
human to actually approve or deny in a terminal, without any LLM auto-acting:

- Add an interactive approval function (e.g. in `gate.py` or a new `interactive.py`)
  that, given a GateResult whose verdict is ASK, presents a clear summary to the user
  (payee, amount + asset/network, destination address, nonce, source_url, the
  untrusted description clearly labeled as untrusted, and the reason it was flagged)
  and prompts for a decision. Accept simple inputs: yes/y to approve, no/n to reject;
  on invalid input re-prompt a bounded number of times then treat as rejected (safe
  default).
- The interactive function must read from an injectable input stream and write to an
  injectable output stream so it is fully testable without a real TTY (no `input()`
  hard-wired; pass streams in). EOF / closed stream -> reject.
- Add a CLI flag (e.g. `--interactive` / `-i`) that, when the verdict is ASK, runs the
  prompt: approved -> proceed and exit 0; rejected -> exit a distinct non-zero code for
  "human rejected" (reuse a clear code; if you add a new one, document it; you may use
  exit 4 for human-rejected to keep DENY=1 / ASK=3 / error=2 distinct). Non-interactive
  ASK keeps current behavior (exit 3). PAY and DENY are unaffected.
- Approval must go through the same gated path (`approve(...)`) so audit records the
  human approval; never bypass the gate or write spend unless truly approved.
- Also support a non-interactive explicit approval for scripting (e.g. `--approve`)
  that approves an ASK request deterministically (equivalent to answering yes), so
  automated pipelines can approve a specific reviewed request.

## Item 2 — End-to-end x402 client flow (simulated transport)

Create a client orchestration module (e.g. `x402_firewall/client.py`) that drives the
full x402 purchase loop, with the firewall as the mandatory decision point. Because
tests must not hit the network, model the transport as an injectable interface and
provide an in-memory simulation of a server.

Flow to implement:
1. Agent makes an initial request for a resource (URL + optionally the expected
   action/amount).
2. Transport responds either `200` with the resource (no payment needed) or
   `402 Payment Required` carrying a payment request payload (the fields already
   modeled: pay_to, amount, asset, network, payee, nonce, description, source_url) and
   optionally a structured signed payload.
3. Client normalizes the 402 payload into a PaymentRequest and calls the firewall
   (`guard_payment`), supplying policy, store, expected_amount and the signed payload.
   - PAY -> proceed to settle.
   - ASK -> by default do NOT settle; if an approval handler is supplied (callback or
     the interactive function / explicit approval), invoke it; settle only if the human
     approves.
   - DENY -> abort; return a structured outcome describing the block.
4. Settlement is represented by a pluggable "settler" interface. Provide a fake/in-memory
   settler that simulates a successful settlement (returns a transaction/reference id)
   WITHOUT any crypto or keys. The client must only call the settler when the gate
   allowed it; assert the settler is never invoked on DENY or un-approved ASK.
5. After successful settlement the client may re-request / present the resource
   (simulate the server returning the paid resource) and returns a final outcome object:
   status (e.g. `paid`/`blocked`/`not_required`/`rejected`), the firewall decision, the
   reason/rule, settlement reference if any, and resource if any.

Design requirements:
- Keep transport and settler as small protocols/ABCs with the in-memory simulation
  provided, so a real HTTP transport / real settler could be dropped in later (do NOT
  implement real HTTP or blockchain now). No third-party libs.
- The client orchestrator must be impossible to accidentally bypass: there should be no
  code path that calls the settler without an allowed GateResult. Centralize settlement
  behind one function that checks `allowed`.
- Reuse Store for nonce/spend/audit so a full purchase is reflected in the same
  persistent ledger and audit trail as direct guard calls.
- Add a CLI entry to run a built-in simulated demo end-to-end (e.g. a `demo` subcommand
  or `--demo` with scenario flags) so the closed loop can be observed without a server.
  Support at least scenarios: clean (PAY), injected (ASK then approve via --approve or
  reject), and malicious (DENY). If subcommands complicate the current flag parser, a
  `--demo SCENARIO` flag is acceptable and preferred.

## Examples / docs
- Add example script(s) under `examples/` showing programmatic end-to-end use with the
  in-memory transport + settler and the interactive/approval handlers.
- Update README: interactive approval usage + exit codes, the client purchase-flow
  architecture (transport → 402 → firewall → settler), how to run the demo scenarios,
  and how a real transport/settler would be plugged into the protocols. Include real
  sample output.
- Keep all existing documentation accurate (rule table, flags, exit codes).

## Tests — real stdlib unittest, must cover
Interactive:
1. ASK with input "y"/"yes" -> approved, allowed True, spend recorded, audit shows human
   approval; "n"/"no" -> rejected, no spend, no settler.
2. invalid input then valid -> re-prompts and honors the valid answer; repeated invalid /
   EOF -> rejected (safe default).
3. CLI `--interactive`: approved exits 0; rejected exits the documented code; without
   --interactive an ASK still exits 3.
4. `--approve` scripted approval settles an ASK deterministically.
Client flow:
5. 200 initially -> status not_required, firewall/settler never called.
6. 402 + PAY -> settler called exactly once, returns reference, final status paid, spend
   and audit recorded.
7. 402 + DENY -> settler never called, status blocked, reason/rule surfaced.
8. 402 + ASK: with no handler -> not settled (rejected/awaiting); with approving handler
   -> settled; with rejecting handler -> not settled.
9. signed-payload tampering in the 402 -> blocked before settlement.
10. demo scenario(s) via the CLI entry run to completion and print expected markers.
Also: run the FULL suite — all prior 88 tests still pass.

## Success criteria — run all yourself, paste REAL output
1. `python3 -m unittest discover -s tests -v` -> all tests (old + new) pass, zero skips;
   paste full output with the new total count.
2. `python3 -m py_compile` over every module -> OK.
3. Run the end-to-end demo CLI for each scenario (temp/in-memory db is fine for demo; if
   a file is used, clean it): clean PAY, ASK-approved, ASK-rejected, DENY. Paste exact
   commands and real JSON/text output showing settler invocation only on allowed paths.
4. Show at least one interactive approval driven via piped stdin (e.g. `echo y | ... -i`)
   and one rejection (`echo n | ... -i`).
5. README updated and accurate; then git commit everything (tests green).

## Constraints / FORBIDDEN
- Work only inside `/home/kings/projects/x402-firewall`.
- Python stdlib only. No pip installs, no real network in tests, no GPU, no real signing
  or keys. In-memory simulated transport/settler only.
- Do not break existing tests, flags, exit codes, or DB compatibility.
- Settlement must be unreachable without an allowed gate decision.
- Do not stub/fabricate test or CLI output — actually run and paste real results.
- Do not add real HTTP/blockchain, third-party deps, or background daemons.
