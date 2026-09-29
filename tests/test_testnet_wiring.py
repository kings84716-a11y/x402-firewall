"""Offline wiring tests for the testnet orchestrator (no SDK, no funds).

These assert the hard contract: the SDK signer / facilitator are unreachable
unless the firewall gate returned an allowed verdict. A fake signer records
every invocation; a fake facilitator records verify/settle calls. None of these
tests import the x402 SDK or touch the network.
"""

import unittest

from x402_firewall import (
    CAIP2_BASE_SEPOLIA,
    PolicyConfig,
    Store,
    Verdict,
    approve,
    parse_payment_required_json,
)

from integration.testnet_runner import (
    Facilitator,
    Signer,
    TestnetRunner,
    TestnetOutcome,
)

SEPOLIA_PAY_TO = "0x84f7fFF002D2b7817a7f20FDDA0779928c38C2E1"
SEPOLIA_USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
OTHER_ADDR = "0x1234567890abcdef1234567890abcdef12345678"


def make_payment_required(pay_to=SEPOLIA_PAY_TO):
    return parse_payment_required_json(
        {
            "x402Version": 2,
            "error": "Payment required",
            "resource": {
                "url": "https://example.testnet/resource",
                "description": "One testnet API call",
                "mimeType": "application/json",
                "serviceName": "Testnet Resource",
                "tags": ["testnet"],
            },
            "accepts": [
                {
                    "scheme": "exact",
                    "network": CAIP2_BASE_SEPOLIA,
                    "asset": SEPOLIA_USDC,
                    "amount": "10000",
                    "payTo": pay_to,
                    "maxTimeoutSeconds": 60,
                    "extra": {"name": "USDC", "version": "2"},
                }
            ],
            "extensions": {},
        }
    )


class FakeSigner(Signer):
    def __init__(self):
        self.calls = []

    def sign(self, option, resource):
        self.calls.append((option, resource))
        return {
            "authorization": {
                "from": "0x0000000000000000000000000000000000000001",
                "to": option.pay_to,
                "value": str(option.amount_raw),
                "validAfter": "0",
                "validBefore": "9999999999",
                "nonce": "1",
            },
            "signature": "0x" + "11" * 65,
        }


class FakeFacilitator(Facilitator):
    def __init__(self):
        self.verify_calls = []
        self.settle_calls = []

    def verify(self, option, resource, inner_payload):
        self.verify_calls.append((option, resource))
        return {"is_valid": True}

    def settle(self, option, resource, inner_payload):
        self.settle_calls.append((option, resource))
        return {
            "success": True,
            "transaction": "0x" + "ab" * 32,
            "network": CAIP2_BASE_SEPOLIA,
        }


def make_policy(allowed, ask_on_unknown=False):
    return PolicyConfig.from_dict(
        {
            "allowed_addresses": allowed,
            "max_amount": 1.0,
            "ask_on_unknown_address": ask_on_unknown,
        }
    )


class TestDenyBlocksSigning(unittest.TestCase):
    def setUp(self):
        self.signer = FakeSigner()
        self.facilitator = FakeFacilitator()

    def _runner(self, policy, approval_handler=None):
        return TestnetRunner(
            self.signer,
            self.facilitator,
            policy,
            store=Store(":memory:"),
            approval_handler=approval_handler,
        )

    def test_unknown_address_deny_never_signs(self):
        runner = self._runner(make_policy([OTHER_ADDR]))
        outcome = runner.process(make_payment_required())

        self.assertEqual(outcome.decision, "DENY")
        self.assertEqual(outcome.rule, "unknown_address")
        self.assertFalse(outcome.allowed)
        self.assertFalse(outcome.signed)
        self.assertEqual(self.signer.calls, [])
        self.assertEqual(self.facilitator.verify_calls, [])
        self.assertEqual(self.facilitator.settle_calls, [])

    def test_over_budget_deny_never_signs(self):
        policy = PolicyConfig.from_dict(
            {"allowed_addresses": [SEPOLIA_PAY_TO], "max_amount": 0.005}
        )
        runner = self._runner(policy)
        # 0.01 USDC vs max_amount 0.005 -> over_budget DENY
        outcome = runner.process(make_payment_required())

        self.assertEqual(outcome.decision, "DENY")
        self.assertEqual(outcome.rule, "over_budget")
        self.assertEqual(self.signer.calls, [])
        self.assertEqual(self.facilitator.settle_calls, [])


class TestPaySignsOnce(unittest.TestCase):
    def test_pay_signs_exactly_once_with_selected_option(self):
        signer = FakeSigner()
        facilitator = FakeFacilitator()
        runner = TestnetRunner(signer, facilitator, make_policy([SEPOLIA_PAY_TO]))

        outcome = runner.process(make_payment_required())

        self.assertEqual(outcome.decision, "PAY")
        self.assertEqual(outcome.rule, "valid")
        self.assertTrue(outcome.allowed)
        self.assertTrue(outcome.signed)
        self.assertEqual(len(signer.calls), 1)

        option, resource = signer.calls[0]
        self.assertEqual(option.scheme, "exact")
        self.assertEqual(option.network, CAIP2_BASE_SEPOLIA)
        self.assertEqual(option.amount_raw, 10000)
        self.assertEqual(option.pay_to.lower(), SEPOLIA_PAY_TO.lower())

        self.assertEqual(len(facilitator.verify_calls), 1)
        self.assertEqual(len(facilitator.settle_calls), 1)
        self.assertEqual(outcome.tx_hash, "0x" + "ab" * 32)


class TestAskRequiresApproval(unittest.TestCase):
    def test_unapproved_ask_does_not_sign(self):
        signer = FakeSigner()
        facilitator = FakeFacilitator()
        runner = TestnetRunner(
            signer,
            facilitator,
            make_policy([OTHER_ADDR], ask_on_unknown=True),
        )

        outcome = runner.process(make_payment_required())

        self.assertEqual(outcome.decision, "ASK")
        self.assertEqual(outcome.rule, "unknown_address")
        self.assertFalse(outcome.allowed)
        self.assertFalse(outcome.signed)
        self.assertEqual(signer.calls, [])
        self.assertEqual(facilitator.settle_calls, [])

    def test_approved_ask_signs_exactly_once(self):
        signer = FakeSigner()
        facilitator = FakeFacilitator()
        runner = TestnetRunner(
            signer,
            facilitator,
            make_policy([OTHER_ADDR], ask_on_unknown=True),
            approval_handler=approve,
        )

        outcome = runner.process(make_payment_required())

        self.assertEqual(outcome.decision, "ASK")
        self.assertTrue(outcome.allowed)
        self.assertTrue(outcome.approved)
        self.assertTrue(outcome.signed)
        self.assertEqual(len(signer.calls), 1)
        self.assertEqual(len(facilitator.settle_calls), 1)


class TestOutcomeShape(unittest.TestCase):
    def test_outcome_is_structured(self):
        signer = FakeSigner()
        runner = TestnetRunner(signer, FakeFacilitator(), make_policy([SEPOLIA_PAY_TO]))
        outcome = runner.process(make_payment_required())

        self.assertIsInstance(outcome, TestnetOutcome)
        d = outcome.to_dict()
        for key in (
            "decision",
            "rule",
            "reason",
            "allowed",
            "approved",
            "signed",
            "signer_calls",
            "pay_to",
            "amount",
            "network",
            "tx_hash",
        ):
            self.assertIn(key, d)
        self.assertEqual(d["amount"], 0.01)  # 10000 / 10**6


if __name__ == "__main__":
    unittest.main()
