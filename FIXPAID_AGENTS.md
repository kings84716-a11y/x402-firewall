# Task: Fix local demo server "paid" flag not flipping to 200

## Bug (already root-caused)
File `integration/local_server.py`, class `Local402Server`.

- The HTTP handler `_Handler.do_GET` reads `self.server.paid`, where `self.server` is
  the underlying `ThreadingHTTPServer` instance (`self._httpd`).
- In `start()` only `self._httpd.paid = False` is set.
- But `mark_paid()` sets `self.pad = True` on the WRAPPER (`Local402Server`), and
  never syncs `self._httpd.paid`.

Result: after a successful settle, `mark_paid()` does not change what the handler
reads, so GET still returns 402.

## Required fix
Make the paid state reach the handler. Simplest correct fix:

```python
def mark_paid(self) -> None:
    self.paid = True
    if self._httpd is not None:
        self._httpd.paid = True
```

You may instead make the handler read the wrapper via a stored reference, but the
above is sufficient and minimal. Keep everything stdlib-only.

## Verify (run real commands, paste output)
1. A focused offline test: start `Local402Server`, GET -> 402; call `mark_paid()`;
   GET same URL -> must now be 200 with the resource JSON. Add this as a stdlib
   unittest in the integration tests if a test file fits, otherwise a short script.
2. Re-run the FULL live testnet flow `.venv/bin/python -m integration.live` — the
   `resource_after_payment.status` must now be `200` (it produced a real tx before;
   funds are still present, this makes another small real settlement).
3. Confirm existing firewall stdlib suite still passes:
   `python3 -m unittest discover -s tests`.
4. Update README if it mentions the demo behavior, and commit.

## Constraints
- Work only in `/home/kings/projects/x402-firewall`. Stdlib only for the firewall.
- Do not change unrelated code. Paste real output; do not fabricate.
