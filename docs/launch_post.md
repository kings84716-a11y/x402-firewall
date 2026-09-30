# Launch post (Reddit r/LocalLLaMA / Hacker News / X)

## Suggested title (Reddit / HN)
I built a payment firewall that stops an AI agent from signing a bad x402 payment — 150 tests, real Base Sepolia settlement, zero dependencies

## Body

Hi everyone — I've been building agentic workflows that call **x402** pay-per-call APIs,
and one thing kept making me nervous: the agent is literally one step away from signing
a transfer of real funds, with no human in the loop.

x402 is great for the *mechanism* — `402 Payment Required`, EIP-3009 gasless
authorization, settle through a facilitator. But nothing in the protocol answers the
question I actually care about: **is *this specific* payment safe?**

So I built a small **payment firewall** that sits between the 402 and the signature.
It evaluates a real x402 v2 payload and returns `PAY` / `ASK` / `DENY`.

**What it catches:**
- **Amount tampering** — compare against the amount the agent expected (epsilon-safe)
- **Address substitution** — whitelist the destination, *and* cross-check the address
  inside the actual signed EIP-712/EIP-3009 payload (the JSON can show a whitelisted
  address while the signature targets an attacker)
- **Nonce replay** — consumed nonces are recorded atomically in SQLite (PRIMARY KEY), so
  replay protection survives process restarts
- **Budget** — per-request cap *and* a cumulative spend total read from the ledger
- **Prompt injection** — scans the untrusted payment `description` for injection
  patterns ("ignore previous instructions", role markers, exfiltration phrases, …)
- **Asset/network** — only USDC on Base; validates EVM address format, rejects NaN/Inf
  amounts, sub-cent dust, and `javascript:`/`data:` source URLs

**The signing path is gated.** You can only obtain signing authorization when the
verdict is `PAY` (or an `ASK` after explicit human approval). On `DENY` it raises
`PaymentBlockedError` — there's no code path that "accidentally" signs.

**Verified for real, not just mocked:** the full loop runs on **Base Sepolia** —
request → 402 → firewall `PAY` → EIP-3009 signature → facilitator verify → settle →
resource `200`. Two real testnet tx (you can look them up on a Base Sepolia explorer):

```
0x16dfad1841923eb1ebeec275c4ff6250bf56fc3a20041a8d641bd9c7647f7744
0x75371858c6b4fa0a10d8b2db644dd8773eae39c1d54ef2095cbe31de50b21446
```

**Details:**
- Python standard library only — **zero third-party runtime dependencies**
- 150 unit tests, no skips
- No bundled keys; the core makes no network calls. The testnet integration is isolated
- MIT licensed

Repo: <GITHUB_URL>

I'd genuinely love feedback from people closer to x402 / payment security — especially:
1. Are there attacks on the agent→facilitator path I'm not modeling?
2. Is cross-checking the signed payload the right place to stop JSON↔signature mismatch,
   or should this live at the wallet?
3. What's a sane default policy for an autonomous agent (I currently default to DENY on
   unknown addresses)?

Happy to answer anything. Thanks for reading.

---

## X / Twitter version (short thread)

1/ I keep trusting my AI agent with something I'd never hand over without looking twice:
the ability to sign a real payment.

So I built an x402 **payment firewall** — it reads the `402`, and decides PAY / ASK / DENY
before the agent can sign. 🛡️

2/ It blocks: amount tampering, address substitution, nonce replay, over-budget spend,
prompt injection hidden in the payment description, and non-USDC/Base payloads.

The signing call is gated — DENY raises, ASK needs a human. No accidental signing.

3/ Verified end-to-end on Base Sepolia with real EIP-3009 signatures through a public
facilitator — two real tx, resource returns 200.

Zero dependencies (Python stdlib), 150 tests.

🔗 <GITHUB_URL>

Feedback very welcome — what attacks am I missing?
