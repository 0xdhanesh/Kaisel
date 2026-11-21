"""Tests for Lab/compare_results.py and Lab/expected.json (Kaisel 1.4.0, spec P1.2).

All inputs are synthetic and built in a temporary directory: they exercise the
comparison logic only and are not lab results.

  python3 -m unittest discover -s Lab/tests
"""
import json
import os
import sys
import tempfile
import unittest

LAB = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, LAB)
import compare_results as cr  # noqa: E402

META = {"kaiselVersion": "1.4.0", "sourceCommit": "0000000", "deviceModel": "iPhone0,0", "iosVersion": "0.0",
        "tool": "none", "installMethod": "Xcode", "scenario": "stock", "hiddenFromInjection": False,
        "date": "2026-01-01", "reproductionSteps": ["synthetic"], "limitations": ["synthetic"], "sanitised": True}
JB_CLEAN = {"status": "notJailbroken", "conclusive": [], "indicators": [], "checksRun": ["filesystem"],
            "checksIncomplete": [], "model": "iPhone0,0", "osVersion": "0.0", "sdkVersion": "1.4.0"}
IC_CLEAN = {"sdkVersion": "1.4.0", "signals": [], "checksCompleted": 2047, "checksExpected": 2047,
            "device": {"verdict": "trusted"}, "runtime": {"verdict": "trusted"}, "posture": {}}


class CompareResults(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, name, obj, meta=None):
        p = os.path.join(self.tmp.name, name)
        with open(p, "w") as f:
            json.dump(obj, f)
        if meta is not None:
            with open(p[:-5] + ".meta.json", "w") as f:
                json.dump(meta, f)
        return p

    def test_expected_json_is_well_formed(self):
        for scenario, exp in cr.EXPECTED.items():
            self.assertIn("description", exp, scenario)
            for app in cr.APPS:
                if app in exp:
                    e = exp[app]
                    self.assertTrue({"status", "device", "runtime", "any_codes"} & set(e), (scenario, app))
                    for c in e.get("any_codes", []):
                        self.assertIsInstance(c, int)

    def test_expected_codes_exist(self):
        weights = json.load(open(os.path.join(LAB, "..", "Server", "weights.json")))
        for scenario, exp in cr.EXPECTED.items():
            codes = set(exp.get("measure", []))
            for app in cr.APPS:
                codes |= set(exp.get(app, {}).get("any_codes", []))
            for c in codes:
                self.assertIn(str(c), weights, f"{scenario}: unknown code {c}")

    def test_pass(self):
        r = cr.check(self.write("stock__jbcheck__synthetic.json", JB_CLEAN, META))
        self.assertEqual(r["outcome"], "PASS", r)

    def test_fail_and_known_gap(self):
        meta = dict(META, scenario="dopamine_roothide_hidden", hiddenFromInjection=True)
        r = cr.check(self.write("dopamine_roothide_hidden__jbcheck__synthetic.json", JB_CLEAN, meta))
        self.assertEqual(r["outcome"], "FAIL")
        self.assertIn("known gap", r["why"])

    def test_partial(self):
        res = dict(JB_CLEAN, status="jailbroken", conclusive=[{"code": 105, "confidence": 99}])
        meta = dict(META, scenario="dopamine_roothide")
        r = cr.check(self.write("dopamine_roothide__jbcheck__synthetic.json", res, meta))
        self.assertEqual(r["outcome"], "PARTIAL", r)     # verdict met, expected code 200 absent

    def test_hand_made_summary_is_invalid(self):
        r = cr.check(self.write("stock__jbcheck__synthetic.json", {"status": "notJailbroken"}, META))
        self.assertEqual(r["outcome"], "INVALID")

    def test_metadata_required_and_validated(self):
        p = self.write("stock__integritycheck__synthetic.json", IC_CLEAN)
        self.assertEqual(cr.check(p)["outcome"], "PASS")
        self.assertEqual(cr.check(p, require_metadata=True)["outcome"], "INVALID")
        bad = dict(META)
        del bad["sourceCommit"]
        bad["sanitised"] = False
        r = cr.check(self.write("stock__integritycheck__synthetic.json", IC_CLEAN, bad))
        self.assertEqual(r["outcome"], "INVALID")
        self.assertIn("sourceCommit", r["why"])
        self.assertIn("sanitised", r["why"])

    def test_scenario_mismatch_in_metadata(self):
        r = cr.check(self.write("stock__jbcheck__synthetic.json", JB_CLEAN, dict(META, scenario="trollstore")))
        self.assertEqual(r["outcome"], "INVALID")

    def test_incomplete_checks_reported(self):
        res = dict(IC_CLEAN, checksCompleted=2047 & ~4)
        r = cr.check(self.write("stock__integritycheck__synthetic.json", res, META))
        self.assertIn("checks incomplete", r["why"])

    def test_coverage_lists_not_tested(self):
        rows = [cr.check(self.write("stock__jbcheck__synthetic.json", JB_CLEAN, META))]
        cov = cr.coverage(rows)
        self.assertNotIn(("stock", "jbcheck"), {(c["scenario"], c["app"]) for c in cov})
        self.assertIn(("palera1n_rootless", "jbcheck"), {(c["scenario"], c["app"]) for c in cov})
        self.assertTrue(all(c["outcome"] == "NOT TESTED" for c in cov))

    def test_bad_file_name(self):
        self.assertEqual(cr.check(self.write("stock.json", JB_CLEAN))["outcome"], "INVALID")


if __name__ == "__main__":
    unittest.main()
