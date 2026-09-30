"""Offline tests for the local 402 demo server (no SDK, no network).

Verifies the hard contract fixed in ``Local402Server.mark_paid``: the handler
serves a ``402`` with a ``payment-required`` header until ``mark_paid()`` is
called, after which the same URL returns ``200`` with the resource JSON.
"""

import json
import unittest
import urllib.error
import urllib.request

from integration.local_server import Local402Server

PAY_TO = "0x84f7fFF002D2b7817a7f20FDDA0779928c38C2E1"


def _get(url: str):
    request = urllib.request.Request(url, method="GET")
    try:
        response = urllib.request.urlopen(request, timeout=10.0)
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers), exc.read()
    with response:
        return response.status, dict(response.headers), response.read()


class TestLocal402ServerPaidFlag(unittest.TestCase):
    def test_get_402_then_mark_paid_then_200(self):
        server = Local402Server(pay_to=PAY_TO).start()
        try:
            status, headers, body = _get(server.url)
            self.assertEqual(status, 402)
            self.assertIn("payment-required", headers)
            self.assertIn("Payment required", json.loads(body.decode("utf-8"))["error"])

            server.mark_paid()

            status, headers, body = _get(server.url)
            self.assertEqual(status, 200)
            self.assertTrue(headers.get("Content-Type", "").startswith("application/json"))
            payload = json.loads(body.decode("utf-8"))
            self.assertTrue(payload["ok"])
            self.assertEqual(payload["data"], "paid testnet resource payload")
        finally:
            server.stop()

    def test_mark_paid_syncs_httpd_flag(self):
        server = Local402Server(pay_to=PAY_TO).start()
        try:
            self.assertFalse(server._httpd.paid)
            server.mark_paid()
            self.assertTrue(server.paid)
            self.assertTrue(server._httpd.paid)
        finally:
            server.stop()


if __name__ == "__main__":
    unittest.main()
