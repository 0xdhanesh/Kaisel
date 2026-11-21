"""Offline tests for the reference server. A synthetic CA stands in for Apple's
App Attest root, so the full verification path runs without a device.

  python3 -m unittest discover -s Server/tests
"""
import base64
import datetime as dt
import hashlib
import json
import os
import sys
import tempfile
import unittest

import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import appattest  # noqa: E402
import policy as pol  # noqa: E402
import rules_tool  # noqa: E402
import server  # noqa: E402

APP_ID = "ABCDE12345.com.dhanesh.kaisel.integritycheck"
sha = lambda b: hashlib.sha256(b).digest()


def _cert(subject, issuer, pub, signer, ca, extensions=()):
    now = dt.datetime.now(dt.timezone.utc)
    b = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)]))
         .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer)]))
         .public_key(pub).serial_number(x509.random_serial_number())
         .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=30))
         .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    for e in extensions:
        b = b.add_extension(e, critical=False)
    return b.sign(signer, hashes.SHA256())


class FakeAppleCA:
    def __init__(self):
        self.root_key = ec.generate_private_key(ec.SECP384R1())
        self.root = _cert("Fake App Attest Root", "Fake App Attest Root", self.root_key.public_key(), self.root_key, True)
        self.int_key = ec.generate_private_key(ec.SECP384R1())
        self.inter = _cert("Fake App Attest CA 1", "Fake App Attest Root", self.int_key.public_key(), self.root_key, True)
        self.root_pem = self.root.public_bytes(serialization.Encoding.PEM)

    def attest(self, challenge: bytes, app_id=APP_ID, aaguid=appattest.AAGUID_DEVELOPMENT, counter=0):
        cred_key = ec.generate_private_key(ec.SECP256R1())
        raw = cred_key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        key_id = sha(raw)
        auth = (sha(app_id.encode()) + bytes([0x41]) + counter.to_bytes(4, "big") + aaguid
                + len(key_id).to_bytes(2, "big") + key_id + b"\xa5cose")
        nonce = sha(auth + sha(challenge))
        ext = x509.UnrecognizedExtension(appattest.APP_ATTEST_NONCE_OID, bytes([0x30, 0x24, 0xA1, 0x22, 0x04, 0x20]) + nonce)
        cred = _cert("cred", "Fake App Attest CA 1", cred_key.public_key(), self.int_key, False, [ext])
        obj = cbor2.dumps({"fmt": "apple-appattest", "authData": auth,
                           "attStmt": {"x5c": [cred.public_bytes(serialization.Encoding.DER),
                                               self.inter.public_bytes(serialization.Encoding.DER)],
                                       "receipt": b"r"}})
        return cred_key, base64.b64encode(key_id).decode(), obj

    @staticmethod
    def assertion(cred_key, client_data_hash: bytes, counter: int, app_id=APP_ID):
        auth = sha(app_id.encode()) + bytes([0x01]) + counter.to_bytes(4, "big")
        sig = cred_key.sign(sha(auth + client_data_hash), ec.ECDSA(hashes.SHA256()))
        return cbor2.dumps({"signature": sig, "authenticatorData": auth})


def report(signals):
    return json.dumps({"verdict": "trusted", "signals": signals, "build": {"textSHA256": "ab"}, "rulesVersion": 1}).encode()


STOCK_IOS27 = [  # iPhone18,1 iOS 27.2.1 Xcode install: all build/posture noise
    {"code": 603, "confidence": 90}, {"code": 601, "confidence": 90}, {"code": 900, "confidence": 90},
    {"code": 800, "confidence": 95}, {"code": 503, "confidence": 55}]
DOPAMINE = [{"code": 105, "confidence": 99}, {"code": 100, "confidence": 95}, {"code": 200, "confidence": 95},
            {"code": 701, "confidence": 95}]
FRIDA = [{"code": 500, "confidence": 95}, {"code": 502, "confidence": 97}, {"code": 503, "confidence": 55}]


class AppAttestTests(unittest.TestCase):
    def setUp(self):
        self.ca = FakeAppleCA()

    def test_attestation_ok_and_assertion_counter(self):
        ch = os.urandom(32)
        k, kid, obj = self.ca.attest(ch)
        att = appattest.verify_attestation(obj, kid, ch, APP_ID, self.ca.root_pem, allow_development=True)
        self.assertEqual(att.environment, "development")
        cdh = sha(b"payload" + b"nonce")
        c1 = appattest.verify_assertion(self.ca.assertion(k, cdh, 1), cdh, att.public_key_pem, APP_ID, 0)
        self.assertEqual(c1, 1)
        with self.assertRaises(appattest.AttestationError):   # replay
            appattest.verify_assertion(self.ca.assertion(k, cdh, 1), cdh, att.public_key_pem, APP_ID, c1)
        with self.assertRaises(appattest.AttestationError):   # different payload
            appattest.verify_assertion(self.ca.assertion(k, cdh, 2), sha(b"other"), att.public_key_pem, APP_ID, c1)

    def test_rejects_wrong_challenge_app_env_and_root(self):
        ch = os.urandom(32)
        _, kid, obj = self.ca.attest(ch)
        for kwargs, msg in [(dict(challenge=os.urandom(32)), "nonce"),
                            (dict(app_id="OTHER.app"), "RP ID"),
                            (dict(allow_development=False), "AAGUID"),
                            (dict(root_ca_pem=FakeAppleCA().root_pem), "chain")]:
            args = dict(attestation_object=obj, key_id_b64=kid, challenge=ch, app_id=APP_ID,
                        root_ca_pem=self.ca.root_pem, allow_development=True)
            args.update(kwargs)
            with self.assertRaises(appattest.AttestationError, msg=msg):
                appattest.verify_attestation(**args)

    def test_secure_enclave_signature(self):
        se = ec.generate_private_key(ec.SECP256R1())
        cdh = sha(b"x")
        sig = se.sign(cdh, ec.ECDSA(hashes.SHA256()))
        pub = se.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        appattest.verify_secure_enclave(sig, pub, cdh)
        with self.assertRaises(appattest.AttestationError):
            appattest.verify_secure_enclave(sig, pub, sha(b"y"))


class PolicyTests(unittest.TestCase):
    def test_stock_ios27_dev_build_is_allowed(self):
        p = pol.Policy(expected_distribution=None)
        a = pol.assess(STOCK_IOS27, p)
        self.assertEqual(a["device"]["verdict"], "trusted")
        self.assertEqual(a["runtime"]["verdict"], "trusted")
        self.assertEqual(pol.decide(a, "verified", p)[0], "allow")

    def test_same_signals_fail_app_store_expectation(self):
        p = pol.Policy(expected_distribution="appStore")
        a = pol.assess(STOCK_IOS27, p)
        self.assertIn(a["app"]["verdict"], ("elevated", "high", "compromised"))

    def test_jailbreak_and_frida_denied(self):
        p = pol.Policy()
        self.assertEqual(pol.assess(DOPAMINE, p)["device"]["verdict"], "compromised")
        self.assertEqual(pol.decide(pol.assess(DOPAMINE, p), "verified", p)[0], "deny")
        self.assertIn(pol.assess(FRIDA, p)["runtime"]["verdict"], ("high", "compromised"))

    def test_roothide_unhidden_device_is_compromised(self):
        # Lab: iPhone9,3, iOS 15.8.2, Dopamine + RootHide, app not hidden.
        signals = [
            {"code": 200, "confidence": 95, "detail": "/var/containers/Bundle/Application/.jbroot-0/usr/lib/roothideinit.dylib"},
            {"code": 304, "confidence": 70, "detail": "csops: no svc #0x80 in first 8 insns"},
            {"code": 905, "confidence": 80, "detail": "sileo://"},
        ]
        p = pol.Policy(expected_distribution=None, require_app_attest=False)
        a = pol.assess(signals, p)
        self.assertEqual(a["device"]["verdict"], "compromised")
        self.assertEqual(len(a["device"]["jailbreakEvidence"]), 1)
        self.assertEqual(pol.decide(a, "missing", p)[0], "deny")

    def test_frida_gadget_alone_is_not_a_jailbreak(self):
        p = pol.Policy(expected_distribution=None)
        a = pol.assess([{"code": 200, "confidence": 95, "detail": "/x/FridaGadget.dylib"}], p)
        self.assertEqual(a["device"]["jailbreakEvidence"], [])
        self.assertNotEqual(a["device"]["verdict"], "compromised")

    def test_history_flags_hidden_rerun(self):
        # Same key, later report is clean because the app was hidden.
        p = pol.Policy(expected_distribution=None, require_app_attest=False)
        a = pol.assess([], p)
        self.assertEqual(a["device"]["verdict"], "trusted")
        reasons = pol.apply_history(a, "2026-11-21T12:00:00Z")
        self.assertEqual(a["device"]["verdict"], "high")
        self.assertTrue(reasons)
        self.assertEqual(pol.decide(a, "missing", p)[0], "deny")

    def test_missing_app_attest_denied_when_required(self):
        p = pol.Policy(expected_distribution=None, require_app_attest=True)
        self.assertEqual(pol.decide(pol.assess([], p), "missing", p)[0], "deny")
        p2 = pol.Policy(expected_distribution=None, require_app_attest=False)
        self.assertEqual(pol.decide(pol.assess([], p2), "missing", p2)[0], "step_up")


class RulesTests(unittest.TestCase):
    def test_sign_verify_and_tamper(self):
        key = ec.generate_private_key(ec.SECP256R1())
        priv = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        pub = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        data = open(os.path.join(os.path.dirname(__file__), "..", "rules", "rules.json"), "rb").read()
        rules_tool.validate(json.loads(data))
        sig = rules_tool.sign_bytes(priv, data)
        rules_tool.verify_bytes(pub, data, sig)
        with self.assertRaises(Exception):
            rules_tool.verify_bytes(pub, data.replace(b'"version": 1', b'"version": 9'), sig)


class EndToEndTests(unittest.TestCase):
    """Enrol + sealed report through verify_sealed(), as the HTTP handler does."""

    def test_flow(self):
        ca = FakeAppleCA()
        with tempfile.TemporaryDirectory() as d:
            store = server.Store(os.path.join(d, "db.json"))

            class Cfg:
                app_id = APP_ID; root_ca = ca.root_pem; allow_development = True
                expected_distribution = None; require_app_attest = True; debugger_expected = False

            cid, ch = store.new_challenge()
            k, kid, obj = ca.attest(store.take_challenge(cid))
            att = appattest.verify_attestation(obj, kid, ch, APP_ID, ca.root_pem, allow_development=True)
            store.devices[kid] = {"publicKeyPEM": att.public_key_pem, "counter": 0, "sePublicKey": None}

            se = ec.generate_private_key(ec.SECP256R1())
            se_pub = se.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)

            def sealed(signals, counter, nonce):
                payload = report(signals)
                cdh = sha(payload + nonce)
                return {"payload": base64.b64encode(payload).decode(), "nonce": base64.b64encode(nonce).decode(),
                        "clientDataHash": base64.b64encode(cdh).decode(), "appAttestKeyId": kid,
                        "appAttestAssertion": base64.b64encode(ca.assertion(k, cdh, counter)).decode(),
                        "secureEnclaveSignature": base64.b64encode(se.sign(cdh, ec.ECDSA(hashes.SHA256()))).decode(),
                        "secureEnclavePublicKey": base64.b64encode(se_pub).decode()}

            cid, ch = store.new_challenge()
            r = server.verify_sealed(sealed(STOCK_IOS27, 1, ch), store.take_challenge(cid), store, Cfg)
            self.assertEqual((r["decision"], r["appAttest"], r["secureEnclave"]), ("allow", "verified", "verified (bound)"))

            cid, ch = store.new_challenge()
            r = server.verify_sealed(sealed(DOPAMINE, 2, ch), store.take_challenge(cid), store, Cfg)
            self.assertEqual(r["decision"], "deny")

            # challenge is single use
            with self.assertRaises(ValueError):
                store.take_challenge(cid)
            # payload swapped after sealing -> rejected
            cid, ch = store.new_challenge()
            s = sealed(DOPAMINE, 3, ch)
            s["payload"] = base64.b64encode(report(STOCK_IOS27)).decode()
            with self.assertRaises(ValueError):
                server.verify_sealed(s, store.take_challenge(cid), store, Cfg)


if __name__ == "__main__":
    unittest.main()
