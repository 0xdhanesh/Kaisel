"""Loaded-image classification on the server (Kaisel 1.4.0, spec P0.1).

Runs the shared fixtures that the C core and the Swift SDK also run.
"""
import json
import os
import sys
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "Server"))
import classification as cls  # noqa: E402
import policy as pol  # noqa: E402

FIXTURES = json.load(open(os.path.join(ROOT, "Tests", "Fixtures", "image_classification.json")))["cases"]
P = pol.Policy(expected_distribution=None)


class SharedFixtures(unittest.TestCase):
    def test_every_fixture(self):
        self.assertGreaterEqual(len(FIXTURES), 30)
        for c in FIXTURES:
            with self.subTest(c["name"]):
                self.assertEqual(cls.classify_image(c["path"], c["bundle"], c["simulator"], c["remoteMarkers"]),
                                 c["expected"])


class AcceptanceTable(unittest.TestCase):
    """The spec's P0.1 acceptance table, through server scoring."""

    def jb(self, code, detail):
        return pol.assess([{"code": code, "confidence": 95, "detail": detail}], P)["device"]["jailbreakEvidence"]

    def test_benign_framework_names(self):
        for d in ("/var/containers/Bundle/Application/U/CraneBank.app/Frameworks/CraneBank.framework/CraneBank",
                  "/var/containers/Bundle/Application/U/App.app/Frameworks/LibertyFinance.framework/LibertyFinance",
                  "/var/containers/Bundle/Application/U/App.app/Frameworks/ChoicyAnalytics.framework/ChoicyAnalytics"):
            for code in (200, 203, 206):
                with self.subTest(d=d, code=code):
                    self.assertEqual(self.jb(code, d), [])

    def test_roothide_injector_conclusive(self):
        d = "/private/var/containers/Bundle/Application/.jbroot-7351422000C774F3/usr/lib/roothideinit.dylib"
        self.assertEqual(len(self.jb(200, d)), 1)
        self.assertEqual(pol.assess([{"code": 200, "confidence": 95, "detail": d}], P)["device"]["verdict"], "compromised")

    def test_substrate_and_ellekit_preserved(self):
        for d in ("/Library/MobileSubstrate/MobileSubstrate.dylib", "/var/jb/usr/lib/libellekit.dylib",
                  "/var/jb/usr/lib/TweakLoader.dylib", "/usr/lib/libsubstrate.dylib"):
            with self.subTest(d=d):
                self.assertEqual(len(self.jb(200, d)), 1)

    def test_frida_gadget_is_runtime_not_jailbreak(self):
        d = "/var/containers/Bundle/Application/U/App.app/Frameworks/FridaGadget.dylib"
        a = pol.assess([{"code": 205, "confidence": 95, "detail": d}], P)
        self.assertEqual(a["device"]["jailbreakEvidence"], [])
        self.assertIn(a["runtime"]["verdict"], ("high", "compromised"))
        # A 1.3.x client reporting the gadget as 200 is not a jailbreak either.
        self.assertEqual(self.jb(200, d), [])

    def test_unknown_external_image_is_indicator(self):
        d = "/var/mobile/Library/Caches/libfoo.dylib"
        self.assertEqual(cls.classify_image(d), cls.UNKNOWN_EXTERNAL)
        self.assertEqual(self.jb(201, d), [])
        self.assertEqual(self.jb(200, d), [])     # even if a client mislabels it

    def test_bundle_boundary(self):
        self.assertFalse(cls.within("/var/App.app2/X", "/var/App.app"))
        self.assertTrue(cls.within("/private/var/App.app/X", "/var/App.app"))
        self.assertTrue(cls.within("/var/App.app", "/var/App.app/"))

    def test_remote_marker_never_conclusive(self):
        self.assertEqual(cls.classify_image("/var/mobile/evilhook.dylib", remote_markers=["evilhook"]), cls.MARKER)
        self.assertEqual(self.jb(206, "/var/mobile/evilhook.dylib"), [])

    def test_runtime_image_no_longer_conclusive_by_confidence(self):
        # 1.3.x: imageAddedAtRuntime >= 95 without "frida" was conclusive.
        self.assertEqual(self.jb(203, "/var/jb/usr/lib/libellekit.dylib"), [])


if __name__ == "__main__":
    unittest.main()
