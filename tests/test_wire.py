"""Tests for the x402 v2 wire parser / normalizer (Massive live payload).

Run with:  python3 -m unittest discover -s tests -v
"""

import base64
import json
import os
import unittest

from x402_firewall import (
    BASE_USDC_MAINNET,
    BASE_USDC_SEPOLIA,
    CAIP2_BASE_MAINNET,
    CAIP2_BASE_SEPOLIA,
    MalformedRequestError,
    PolicyConfig,
    UnknownAssetError,
    UnknownVersionError,
    UnsupportedSchemeError,
    NoMatchingOptionError,
    Verdict,
    evaluate_v2_payment_required,
    normalize_v2,
    option_to_request,
    parse_payment_required_header,
    parse_payment_required_json,
    resolve_asset,
    select_option,
)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HEADER_PATH = os.path.join(REPO_ROOT, "examples", "massive_payment_required.header.txt")
JSON_PATH = os.path.join(REPO_ROOT, "examples", "massive_payment_required.json")

MASSIVE_PAY_TO = "0x525f6dDcE9aF7a7179D7696aaBfCd5FCd15a21e6"
MASSIVE_ASSET = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
OTHER_ADDR = "0x1234567890abcdef1234567890abcdef12345678"


def load_header():
    with open(HEADER_PATH, "r", encoding="utf-8") as f:
        return f.read().strip()


def load_json_fixture():
    with open(JSON_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def make_policy(allowed=None, max_amount=1.0):
    return PolicyConfig.from_dict(
        {"allowed_addresses": allowed or [MASSIVE_PAY_TO], "max_amount": max_amount}
    )


def make_v2(version=2, accepts=None, resource=None):
    data = load_json_fixture()
    if version is not None:
        data["x402Version"] = version
    if accepts is not None:
        data["accepts"] = accepts
    if resource is not None:
        data["resource"] = resource
    return data


class TestParseRealHeader(unittest.TestCase):
    def test_parses_committed_base64_header(self):
        pr = parse_payment_required_header(load_header())
        self.assertEqual(pr.version, 2)
        self.assertEqual(len(pr.accepts), 1)

        option = pr.accepts[0]
        self.assertEqual(option.scheme, "exact")
        self.assertEqual(option.network, CAIP2_BASE_MAINNET)
        self.assertEqual(option.asset.lower(), MASSIVE_ASSET.lower())
        self.assertEqual(option.amount_raw, 10000)
        self.assertEqual(option.pay_to.lower(), MASSIVE_PAY_TO.lower())
        self.assertEqual(option.max_timeout_seconds, 60)

    def test_parses_decoded_json_fixture_identically(self):
        from_header = parse_payment_required_header(load_header())
        from_json = parse_payment_required_json(load_json_fixture())
        self.assertEqual(from_header, from_json)

    def test_resource_fields_populated(self):
        pr = parse_payment_required_json(load_json_fixture())
        self.assertEqual(pr.resource.service_name, "Massive")
        self.assertEqual(pr.resource.url, "https://agent.massive.com/v1/open-close/AAPL/2026-08-14")
        self.assertIn("open", pr.resource.description)
        self.assertEqual(pr.error, "Payment required")


class TestConversionToRequest(unittest.TestCase):
    def test_converts_amount_asset_network_payee(self):
        pr = parse_payment_required_json(load_json_fixture())
        option = select_option(pr)
        request = option_to_request(option, pr.resource)

        self.assertEqual(request.amount, 0.01)  # 10000 / 10**6
        self.assertEqual(request.asset, "USDC")
        self.assertEqual(request.network, "Base")
        self.assertEqual(request.payee, "Massive")
        self.assertEqual(request.pay_to, MASSIVE_PAY_TO)
        self.assertEqual(request.source_url, pr.resource.url)
        self.assertEqual(request.description, pr.resource.description)
        self.assertIsNone(request.nonce)

    def test_normalize_v2_end_to_end(self):
        request = normalize_v2(load_json_fixture())
        self.assertEqual(request.amount, 0.01)
        self.assertEqual(request.asset, "USDC")
        self.assertEqual(request.network, "Base")
        self.assertEqual(request.payee, "Massive")
        self.assertIsNone(request.nonce)


class TestEvaluationOfMassive(unittest.TestCase):
    def test_permissive_policy_pays(self):
        result = evaluate_v2_payment_required(load_json_fixture(), make_policy())
        self.assertEqual(result.decision, Verdict.PAY)
        self.assertEqual(result.rule, "valid")

    def test_unknown_pay_to_denies(self):
        result = evaluate_v2_payment_required(
            load_json_fixture(), make_policy(allowed=[OTHER_ADDR])
        )
        self.assertEqual(result.decision, Verdict.DENY)
        self.assertEqual(result.rule, "unknown_address")

    def test_over_budget_denies(self):
        result = evaluate_v2_payment_required(
            load_json_fixture(), make_policy(max_amount=0.005)
        )
        self.assertEqual(result.decision, Verdict.DENY)
        self.assertEqual(result.rule, "over_budget")


class TestMalformedPayloads(unittest.TestCase):
    def test_bad_base64_header_raises(self):
        with self.assertRaises(MalformedRequestError):
            parse_payment_required_header("!!!not-base64!!!")

    def test_not_an_object_raises(self):
        with self.assertRaises(MalformedRequestError):
            parse_payment_required_json([1, 2, 3])

    def test_missing_accepts_raises(self):
        with self.assertRaises(MalformedRequestError):
            parse_payment_required_json({"x402Version": 2, "resource": {}})

    def test_empty_accepts_raises(self):
        data = make_v2(accepts=[])
        with self.assertRaises(MalformedRequestError):
            parse_payment_required_json(data)

    def test_bad_version_raises_unknown_version(self):
        with self.assertRaises(UnknownVersionError):
            parse_payment_required_json(make_v2(version=3))

    def test_evaluation_maps_malformed_to_deny(self):
        result = evaluate_v2_payment_required([1, 2, 3], make_policy())
        self.assertEqual(result.decision, Verdict.DENY)
        self.assertEqual(result.rule, "malformed")

    def test_evaluation_maps_bad_version_to_malformed(self):
        result = evaluate_v2_payment_required(make_v2(version=99), make_policy())
        self.assertEqual(result.decision, Verdict.DENY)
        self.assertEqual(result.rule, "malformed")


class TestAmountValidation(unittest.TestCase):
    def test_non_numeric_amount_raises(self):
        data = make_v2(accepts=[
            {"scheme": "exact", "network": CAIP2_BASE_MAINNET, "asset": MASSIVE_ASSET,
             "amount": "abc", "payTo": MASSIVE_PAY_TO, "maxTimeoutSeconds": 60}
        ])
        with self.assertRaises(MalformedRequestError):
            parse_payment_required_json(data)

    def test_negative_amount_raises(self):
        data = make_v2(accepts=[
            {"scheme": "exact", "network": CAIP2_BASE_MAINNET, "asset": MASSIVE_ASSET,
             "amount": "-5", "payTo": MASSIVE_PAY_TO, "maxTimeoutSeconds": 60}
        ])
        with self.assertRaises(MalformedRequestError):
            parse_payment_required_json(data)

    def test_float_amount_raises(self):
        data = make_v2(accepts=[
            {"scheme": "exact", "network": CAIP2_BASE_MAINNET, "asset": MASSIVE_ASSET,
             "amount": 1.5, "payTo": MASSIVE_PAY_TO, "maxTimeoutSeconds": 60}
        ])
        with self.assertRaises(MalformedRequestError):
            parse_payment_required_json(data)


class TestUnknownAssetAndScheme(unittest.TestCase):
    def test_unknown_asset_raises_unknown_asset_error(self):
        data = make_v2(accepts=[
            {"scheme": "exact", "network": CAIP2_BASE_MAINNET,
             "asset": "0x" + "1" * 40, "amount": "10000",
             "payTo": MASSIVE_PAY_TO, "maxTimeoutSeconds": 60}
        ])
        with self.assertRaises(UnknownAssetError):
            resolve_asset(CAIP2_BASE_MAINNET, "0x" + "1" * 40)

    def test_unknown_asset_evaluation_denies_unsupported(self):
        data = make_v2(accepts=[
            {"scheme": "exact", "network": CAIP2_BASE_MAINNET,
             "asset": "0x" + "1" * 40, "amount": "10000",
             "payTo": MASSIVE_PAY_TO, "maxTimeoutSeconds": 60}
        ])
        result = evaluate_v2_payment_required(data, make_policy())
        self.assertEqual(result.decision, Verdict.DENY)
        self.assertEqual(result.rule, "unsupported_asset")

    def test_non_exact_scheme_unsupported(self):
        data = make_v2(accepts=[
            {"scheme": "upto", "network": CAIP2_BASE_MAINNET, "asset": MASSIVE_ASSET,
             "amount": "10000", "payTo": MASSIVE_PAY_TO, "maxTimeoutSeconds": 60}
        ])
        result = evaluate_v2_payment_required(data, make_policy())
        self.assertEqual(result.decision, Verdict.DENY)
        self.assertEqual(result.rule, "unsupported_scheme")

    def test_desired_network_no_match(self):
        pr = parse_payment_required_json(load_json_fixture())
        with self.assertRaises(NoMatchingOptionError):
            select_option(pr, desired_network="eip155:99999")


class TestNetworkAssetMapping(unittest.TestCase):
    def test_base_mainnet_mapping(self):
        symbol, decimals, name = resolve_asset(CAIP2_BASE_MAINNET, BASE_USDC_MAINNET)
        self.assertEqual((symbol, decimals, name), ("USDC", 6, "Base"))

    def test_base_sepolia_testnet_mapping(self):
        symbol, decimals, name = resolve_asset(CAIP2_BASE_SEPOLIA, BASE_USDC_SEPOLIA)
        self.assertEqual((symbol, decimals, name), ("USDC", 6, "Base Sepolia"))

    def test_unknown_network_raises(self):
        with self.assertRaises(UnknownAssetError):
            resolve_asset("eip155:1", BASE_USDC_MAINNET)


if __name__ == "__main__":
    unittest.main()
