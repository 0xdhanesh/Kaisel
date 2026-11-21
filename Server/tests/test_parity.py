"""Client/server classification parity (Kaisel 1.4.0, spec P1.2).

Parses the Swift sources (the same way Server/tools/export_weights.py does) and
checks the conclusive, indicator and corroborating sets against
Server/classification.json, which the server loads directly. Also checks that
weights.json matches Finding.swift and that the committed C string table
matches the manifest, so an indicator-list change cannot silently change
classification semantics.
"""
import json
import os
import re
import subprocess
import sys
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "Server"))
import classification as cls  # noqa: E402
import policy as pol  # noqa: E402

SWIFT = os.path.join(ROOT, "Sources", "KaiselKit")


def swift_set(path: str, name: str) -> set:
    src = open(os.path.join(SWIFT, path)).read()
    m = re.search(r"static let " + name + r": Set<FindingCode> = \[(.*?)\]", src, re.S)
    if not m:
        raise AssertionError(f"{name} not found in {path}")
    return set(re.findall(r"\.(\w+)", m.group(1)))


class Parity(unittest.TestCase):
    def test_conclusive_codes(self):
        self.assertEqual(swift_set("JailbreakDetector.swift", "conclusiveCodes"), set(cls.MANIFEST["conclusiveCodes"]))

    def test_indicator_codes(self):
        self.assertEqual(swift_set("JailbreakDetector.swift", "indicatorCodes"), set(cls.MANIFEST["indicatorCodes"]))

    def test_corroborating_codes(self):
        self.assertEqual(swift_set("IntegrityKit.swift", "corroboratingCodes"), set(cls.MANIFEST["corroboratingCodes"]))

    def test_conclusive_and_indicator_disjoint(self):
        self.assertFalse(set(cls.MANIFEST["conclusiveCodes"]) & set(cls.MANIFEST["indicatorCodes"]))

    def test_server_sets_derive_from_manifest(self):
        names = {c: m["name"] for c, m in pol.CODES.items()}
        self.assertEqual({names[c] for c in pol.CONCLUSIVE}, set(cls.MANIFEST["conclusiveCodes"]))
        self.assertEqual({names[c] for c in pol.CORROBORATING}, set(cls.MANIFEST["corroboratingCodes"]))

    def test_conclusive_set_is_pinned(self):
        # Changing what proves a jailbreak must be a deliberate, reviewed edit of this test too.
        self.assertEqual(set(cls.MANIFEST["conclusiveCodes"]), {
            "jailbreakPathPresent", "rootlessJailbreakRoot", "symlinkedSystemDirectory", "rootVolumeWritable",
            "sandboxWrite", "sandboxFork", "libcSyscallMismatch", "imageListMismatch", "envJailbreak",
            "suspiciousEntitlement", "bundlePathUnexpected", "suspiciousImage"})
        self.assertEqual(cls.MANIFEST["conclusiveRequiresImageRevalidation"], ["suspiciousImage"])

    def test_weights_json_matches_finding_swift(self):
        before = open(os.path.join(ROOT, "Server", "weights.json")).read()
        src = open(os.path.join(SWIFT, "Finding.swift")).read()
        codes = {m.group(1): m.group(2) for m in re.finditer(r"case (\w+)\s*=\s*(\d+)", src)}
        data = json.loads(before)
        self.assertEqual({v["name"]: k for k, v in data.items()}, codes)

    def test_c_string_table_matches_manifest(self):
        r = subprocess.run([sys.executable, os.path.join(ROOT, "Scripts", "gen_strings.py"), "--verify"],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_c_finding_codes_mirror_swift(self):
        hdr = open(os.path.join(ROOT, "Sources", "CIntegrityCore", "include", "rasp_core.h")).read()
        self.assertIn("RASP_F_INSTRUMENTATION_IMAGE  = 205", hdr)
        self.assertIn("RASP_F_IMAGE_MARKER_MATCH     = 206", hdr)


if __name__ == "__main__":
    unittest.main()
