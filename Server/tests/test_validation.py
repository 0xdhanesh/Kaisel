"""Strict-mode report validation and decision tests (Kaisel 1.4.0, spec P0.2).

The server must never answer `allow` in strict mode for an incomplete,
malformed, unsupported, tampered, replayed or unauthenticated report.

  python3 -m unittest discover -s Server/tests
"""
import base64
import copy
import json
import os
import sys
import tempfile
import unittest

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import appattest  # noqa: E402
import policy as pol  # noqa: E402
import server  # noqa: E402
from test_server import APP_ID, STOCK_IOS27, DOPAMINE, FakeAppleCA, report_dict, sha  # noqa: E402

STRICT = pol.Policy(expected_distribution=None)
LAB = pol.Policy(expected_distribution=None, mode="lab", require_app_attest=False)
ONE_MISSING = pol.ALL_CHECKS & ~(1 << pol.CHECK_NAMES.index("images"))


def decision(rep, policy=STRICT, app_attest="verified"):
    v = pol.validate_report(rep, policy)
    sigs = rep.get("signals") if isinstance(rep, dict) and isinstance(rep.get("signals"), list) else []
    sigs = [x for x in sigs if isinstance(x, dict) and pol._is_int(x.get("code")) and pol._is_int(x.get("confidence"))]
    return pol.decide(pol.assess(sigs, policy), app_attest, policy, v)


class StrictNeverAllows(unittest.TestCase):
    def assertNotAllowed(self, rep, want=None, **kw):
        d, reasons = decision(rep, **kw)
        self.assertNotEqual(d, "allow", reasons)
        if want:
            self.assertEqual(d, want, reasons)
        return reasons

    def test_valid_complete_report_is_allowed(self):
        self.assertEqual(decision(report_dict(STOCK_IOS27))[0], "allow")

    def test_empty_report(self):
        self.assertNotAllowed({}, "deny")

    def test_not_an_object(self):
        self.assertNotAllowed([], "deny")

    def test_checks_completed_zero(self):
        self.assertNotAllowed(report_dict([], checksCompleted=0), "deny")

    def test_checks_expected_zero(self):
        self.assertNotAllowed(report_dict([], checksExpected=0), "deny")

    def test_client_cannot_shrink_expected_set(self):
        # A client claiming fewer expected checks is contradicting the server profile.
        self.assertNotAllowed(report_dict([], checksExpected=ONE_MISSING, checksCompleted=ONE_MISSING), "deny")

    def test_missing_required_check_bit(self):
        rep = report_dict([{"code": 1000, "confidence": 95, "detail": "images: never entered"}],
                          checksCompleted=ONE_MISSING)
        reasons = self.assertNotAllowed(rep)
        self.assertTrue(any("images" in r for r in reasons), reasons)

    def test_missing_bit_without_check_suppressed_signal(self):
        reasons = self.assertNotAllowed(report_dict([], checksCompleted=ONE_MISSING))
        self.assertTrue(any("without a checkSuppressed" in r for r in reasons))

    def test_unknown_completion_bits(self):
        self.assertNotAllowed(report_dict([], checksCompleted=pol.ALL_CHECKS | (1 << 20)), "deny")

    def test_contradictory_check_suppressed(self):
        self.assertNotAllowed(report_dict([{"code": 1000, "confidence": 95, "detail": "x"}]), "deny")

    def test_invalid_bitmap_types(self):
        for bad in ("2047", 2047.0, True, None, -1, 1 << 32, [2047]):
            with self.subTest(bad=bad):
                self.assertNotAllowed(report_dict([], checksCompleted=bad), "deny")
                self.assertNotAllowed(report_dict([], checksExpected=bad), "deny")

    def test_unsupported_versions(self):
        self.assertNotAllowed(report_dict([], sdkVersion="9.9.9"), "deny")
        self.assertNotAllowed(report_dict([], sdkVersion=None), "deny")
        self.assertNotAllowed(report_dict([], reportSchemaVersion=3), "deny")
        self.assertNotAllowed(report_dict([], reportSchemaVersion="2"), "deny")

    def test_legacy_131_report_is_lab_only(self):
        legacy = report_dict([], sdkVersion="1.3.1")
        del legacy["reportSchemaVersion"]
        self.assertNotAllowed(legacy, "deny")
        self.assertEqual(decision(legacy, LAB, "missing")[0], "step_up")

    def test_unknown_critical_signal_code(self):
        self.assertNotAllowed(report_dict([{"code": 4242, "confidence": 90}]), "deny")
        self.assertNotEqual(decision(report_dict([{"code": 4242, "confidence": 90}]), LAB)[0], "allow")

    def test_malformed_signals(self):
        for sig in ({"code": "105", "confidence": 90}, {"code": 105, "confidence": 101},
                    {"code": 105, "confidence": "90"}, {"code": 105, "confidence": 90, "detail": 7},
                    {"code": True, "confidence": 90}, "105"):
            with self.subTest(sig=sig):
                rep = report_dict([])
                rep["signals"] = [sig]
                self.assertNotAllowed(rep, "deny")
        rep = report_dict([])
        rep["signals"] = "none"
        self.assertNotAllowed(rep, "deny")
        self.assertNotAllowed(report_dict([{"code": 800, "confidence": 1}] * 600), "deny")

    def test_missing_app_attest_assertion(self):
        self.assertNotAllowed(report_dict(STOCK_IOS27), "deny", app_attest="missing")

    def test_strict_ignores_require_app_attest_false(self):
        p = pol.Policy(expected_distribution=None, require_app_attest=False)
        self.assertEqual(decision(report_dict([]), p, "missing")[0], "deny")

    def test_lab_mode_is_never_allow_without_app_attest(self):
        self.assertEqual(decision(report_dict([]), LAB, "missing")[0], "step_up")

    def test_incomplete_report_in_lab_is_step_up(self):
        rep = report_dict([{"code": 1000, "confidence": 95, "detail": "images: never entered"}],
                          checksCompleted=ONE_MISSING)
        self.assertEqual(decision(rep, LAB, "verified")[0], "deny")   # checkSuppressed is hard -> runtime high
        self.assertNotEqual(decision(report_dict([], checksCompleted=ONE_MISSING), LAB)[0], "allow")


class DevelopmentExceptions(unittest.TestCase):
    def test_xcode_debug_build_with_policy_exceptions_is_allowed(self):
        p = pol.Policy(expected_distribution="development", debugger_expected=True)
        sigs = [{"code": 601, "confidence": 90}, {"code": 900, "confidence": 90}, {"code": 603, "confidence": 90},
                {"code": 400, "confidence": 95}, {"code": 401, "confidence": 95}, {"code": 800, "confidence": 95}]
        self.assertEqual(decision(report_dict(sigs), p)[0], "allow")

    def test_same_build_without_exceptions_is_not_allowed(self):
        sigs = [{"code": 400, "confidence": 95}, {"code": 401, "confidence": 95}]
        self.assertNotEqual(decision(report_dict(sigs), pol.Policy(expected_distribution=None))[0], "allow")


class StepUp(unittest.TestCase):
    def test_elevated_risk_steps_up(self):
        # An unknown external image and a URL scheme: indicators, not proof.
        sigs = [{"code": 201, "confidence": 70, "detail": "/var/mobile/x.dylib"}, {"code": 905, "confidence": 80, "detail": "sileo://"}]
        d, reasons = decision(report_dict(sigs))
        self.assertEqual(d, "step_up", reasons)


class SealedFlow(unittest.TestCase):
    """Through server.verify_sealed(), as the HTTP handler calls it."""

    def setUp(self):
        self.ca = FakeAppleCA()
        self.tmp = tempfile.TemporaryDirectory()
        self.store = server.Store(os.path.join(self.tmp.name, "db.json"))

        class Cfg:
            app_id = APP_ID; root_ca = self.ca.root_pem; allow_development = True
            expected_distribution = None; require_app_attest = True; debugger_expected = False; mode = "strict"
        self.Cfg = Cfg
        cid, ch = self.store.new_challenge()
        self.k, self.kid, obj = self.ca.attest(self.store.take_challenge(cid))
        att = appattest.verify_attestation(obj, self.kid, ch, APP_ID, self.ca.root_pem, allow_development=True)
        self.store.devices[self.kid] = {"publicKeyPEM": att.public_key_pem, "counter": 0, "sePublicKey": None}
        self.counter = 0
        self.se = ec.generate_private_key(ec.SECP256R1())

    def tearDown(self):
        self.tmp.cleanup()

    def sealed(self, rep: dict, nonce: bytes, assertion=True, se=True):
        payload = json.dumps(rep).encode()
        cdh = sha(payload + nonce)
        s = {"payload": base64.b64encode(payload).decode(), "nonce": base64.b64encode(nonce).decode(),
             "clientDataHash": base64.b64encode(cdh).decode()}
        if assertion:
            self.counter += 1
            s["appAttestKeyId"] = self.kid
            s["appAttestAssertion"] = base64.b64encode(self.ca.assertion(self.k, cdh, self.counter)).decode()
        if se:
            pub = self.se.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
            s["secureEnclaveSignature"] = base64.b64encode(self.se.sign(cdh, ec.ECDSA(hashes.SHA256()))).decode()
            s["secureEnclavePublicKey"] = base64.b64encode(pub).decode()
        return s

    def verify(self, rep, **kw):
        cid, ch = self.store.new_challenge()
        return server.verify_sealed(self.sealed(rep, ch, **kw), self.store.take_challenge(cid), self.store, self.Cfg)

    def test_valid_report_allowed(self):
        r = self.verify(report_dict(STOCK_IOS27))
        self.assertEqual((r["decision"], r["appAttest"], r["mode"]), ("allow", "verified", "strict"))

    def test_incomplete_report_not_allowed(self):
        r = self.verify(report_dict([], checksCompleted=ONE_MISSING))
        self.assertNotEqual(r["decision"], "allow")
        self.assertEqual(r["validation"]["action"], "step_up")

    def test_tampered_payload_and_signature(self):
        cid, ch = self.store.new_challenge()
        s = self.sealed(report_dict(DOPAMINE), ch)
        s["payload"] = base64.b64encode(json.dumps(report_dict(STOCK_IOS27)).encode()).decode()
        r = server.verify_sealed(s, self.store.take_challenge(cid), self.store, self.Cfg)
        self.assertEqual(r["decision"], "deny")
        cid, ch = self.store.new_challenge()
        s = self.sealed(report_dict(STOCK_IOS27), ch)
        sig = bytearray(base64.b64decode(s["appAttestAssertion"]))
        sig[-5] ^= 0xFF
        s["appAttestAssertion"] = base64.b64encode(bytes(sig)).decode()
        r = server.verify_sealed(s, self.store.take_challenge(cid), self.store, self.Cfg)
        self.assertEqual(r["decision"], "deny")
        self.assertTrue(r["appAttest"].startswith("failed"))

    def test_wrong_or_replayed_challenge(self):
        cid, ch = self.store.new_challenge()
        s = self.sealed(report_dict(STOCK_IOS27), b"\0" * 32)
        r = server.verify_sealed(s, self.store.take_challenge(cid), self.store, self.Cfg)
        self.assertEqual(r["decision"], "deny")
        with self.assertRaises(ValueError):          # challenge is single use
            self.store.take_challenge(cid)

    def test_missing_assertion_with_valid_se_signature_is_denied(self):
        r = self.verify(report_dict(STOCK_IOS27), assertion=False)
        self.assertEqual(r["decision"], "deny")
        self.assertIn("unbound", r["secureEnclave"])

    def test_unbound_se_key_never_writes_history(self):
        lab = type("LabCfg", (self.Cfg,), {"mode": "lab", "require_app_attest": False})
        cid, ch = self.store.new_challenge()
        s = self.sealed(report_dict(DOPAMINE), ch, assertion=False)
        server.verify_sealed(s, self.store.take_challenge(cid), self.store, lab)
        self.assertEqual(self.store.devices.get("_history", {}), {})

    def test_history_keyed_by_app_attest_and_hidden_rerun_denied(self):
        self.assertEqual(self.verify(report_dict(DOPAMINE))["decision"], "deny")
        self.assertIn("aa:" + self.kid, self.store.devices["_history"])
        r = self.verify(report_dict(STOCK_IOS27))        # same instance, app now hidden
        self.assertEqual(r["decision"], "deny")
        self.assertEqual(r["device"]["verdict"], "high")

    def test_stale_history_from_broad_marker_is_ignored(self):
        self.store.devices["_history"] = {"aa:" + self.kid: {"firstSeen": "2026-11-20T00:00:00Z", "evidence": [
            {"code": "200", "detail": "/var/containers/Bundle/Application/U/CraneBank.app/Frameworks/CraneBank.framework/CraneBank"}]}}
        self.assertEqual(self.verify(report_dict(STOCK_IOS27))["decision"], "allow")

    def test_legacy_se_history_honoured_only_when_bound(self):
        pub = base64.b64encode(self.se.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)).decode()
        self.store.devices["_history"] = {"se:" + pub: {"firstSeen": "2026-11-20T00:00:00Z", "evidence": [
            {"code": "200", "detail": "/var/containers/Bundle/Application/.jbroot-0/usr/lib/roothideinit.dylib"}]}}
        r = self.verify(report_dict(STOCK_IOS27))
        self.assertEqual(r["decision"], "deny")
        self.assertTrue(any("previously seen" in x for x in r["reasons"]))

    def test_malformed_sealed_inputs(self):
        cid, ch = self.store.new_challenge()
        self.assertEqual(server.verify_sealed("x", self.store.take_challenge(cid), self.store, self.Cfg)["decision"], "deny")
        cid, ch = self.store.new_challenge()
        s = self.sealed(report_dict([]), ch)
        bad = copy.deepcopy(s)
        bad["payload"] = "%%%"
        self.assertEqual(server.verify_sealed(bad, self.store.take_challenge(cid), self.store, self.Cfg)["decision"], "deny")


if __name__ == "__main__":
    unittest.main()
