#!/usr/bin/env python3
"""Checks exported lab results against expected.json (Kaisel 1.4.0).

Each real-device run is two files in Lab/results/:

  <scenario>__<app>__<device>.json       the app's own export ("Copy result JSON")
  <scenario>__<app>__<device>.meta.json  the run record (see METADATA_FIELDS below)

for example dopamine_roothide__jbcheck__iphone9-3-15.8.2.json and its .meta.json.
<app> is jbcheck or integritycheck. Paste the export exactly as copied: do not
build or edit result JSON by hand. Redact personal identifiers, internal app
names and local paths in the metadata before publishing.

  python3 Lab/compare_results.py Lab/results/*.json              # PASS/PARTIAL/FAIL per file
  python3 Lab/compare_results.py --coverage Lab/results/*.json   # also lists NOT TESTED scenarios
  python3 Lab/compare_results.py --require-metadata ...          # fail on a missing or invalid .meta.json

Outcome per file:
  PASS     the verdict expectation and the code expectation are both met
  PARTIAL  one of the two is met
  FAIL     neither is met (or the only expectation is missed)
  INVALID  the file is not a recognisable app export, or its metadata is invalid
"""
from __future__ import annotations

import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(HERE, "expected.json")) as _f:
    EXPECTED = {k: v for k, v in json.load(_f).items() if not k.startswith("_")}

APPS = ("jbcheck", "integritycheck")
OUTCOMES = ("PASS", "PARTIAL", "FAIL", "NOT TESTED")
# Required run-record fields (spec P1.1). Types: str unless noted.
METADATA_FIELDS = {
    "kaiselVersion": str,          # e.g. "1.4.0"
    "sourceCommit": str,           # git commit the apps were built from
    "deviceModel": str,            # e.g. "iPhone9,3"
    "iosVersion": str,             # exact, e.g. "15.8.2"
    "tool": str,                   # jailbreak or instrumentation tool and version, or "none"
    "installMethod": str,          # e.g. "Xcode", "Sideloadly (free Apple ID)", "TrollStore"
    "scenario": str,               # key in expected.json
    "hiddenFromInjection": bool,   # app on a hiding list (RootHide Blacklist, Choicy, Shadow)
    "date": str,                   # YYYY-MM-DD
    "reproductionSteps": list,     # ordered steps, as text
    "limitations": list,           # anything that weakens the result
    "sanitised": bool,             # must be true before publishing
}


def load_json(path: str):
    with open(path) as f:
        return json.load(f)


def codes_of(result: dict) -> set:
    sigs = result.get("signals") or (result.get("conclusive", []) + result.get("indicators", []))
    return {int(s["code"]) for s in sigs if isinstance(s, dict) and "code" in s}


def validate_export(app: str, r) -> list[str]:
    """Structural check that this is an app export, not a hand-made summary."""
    if not isinstance(r, dict):
        return ["result is not a JSON object"]
    need = {"jbcheck": ("status", "conclusive", "indicators", "checksRun", "model", "osVersion"),
            "integritycheck": ("sdkVersion", "signals", "checksCompleted", "checksExpected", "device", "runtime",
                               "posture")}[app]
    missing = [k for k in need if k not in r]
    return [f"not an app export: missing {', '.join(missing)}"] if missing else []


def validate_metadata(meta, scenario: str) -> list[str]:
    if not isinstance(meta, dict):
        return ["metadata is not a JSON object"]
    problems = []
    for k, t in METADATA_FIELDS.items():
        if k not in meta:
            problems.append(f"metadata missing {k}")
        elif not isinstance(meta[k], t) or (t is str and not meta[k].strip()):
            problems.append(f"metadata {k} must be a non-empty {t.__name__}")
    if meta.get("scenario") not in (None, scenario):
        problems.append(f"metadata scenario {meta.get('scenario')!r} differs from file name {scenario!r}")
    if meta.get("sanitised") is False:
        problems.append("metadata sanitised is false: redact before publishing")
    return problems


def completion_note(app: str, r: dict) -> str:
    if app == "integritycheck":
        done, exp = r.get("checksCompleted"), r.get("checksExpected")
        if isinstance(done, int) and isinstance(exp, int):
            return "checks complete" if done & exp == exp else f"checks incomplete (mask {exp & ~done:#x})"
    if app == "jbcheck":
        inc = r.get("checksIncomplete")
        if inc:
            return f"checks incomplete: {', '.join(inc)}"
        return "checks complete" if inc == [] else "completion not exported (pre-1.4.0 build)"
    return ""


def evaluate(app: str, exp: dict, r: dict) -> tuple[str, list[str]]:
    verdict_ok, verdict_checked, problems = True, False, []
    if app == "jbcheck" and "status" in exp:
        verdict_checked = True
        if r.get("status") not in exp["status"]:
            verdict_ok = False
            problems.append(f"status {r.get('status')} not in {exp['status']}")
    if app == "integritycheck":
        for dom in ("device", "runtime"):
            if dom in exp:
                verdict_checked = True
                v = (r.get(dom) or {}).get("verdict")
                if v not in exp[dom]:
                    verdict_ok = False
                    problems.append(f"{dom} {v} not in {exp[dom]}")
    codes_checked = "any_codes" in exp
    codes_ok = not codes_checked or bool(codes_of(r) & set(exp["any_codes"]))
    if not codes_ok:
        problems.append(f"none of codes {exp['any_codes']} seen")
    if verdict_ok and codes_ok:
        return "PASS", problems
    if verdict_checked and codes_checked and (verdict_ok or codes_ok):
        return "PARTIAL", problems
    return "FAIL", problems


def check(path: str, require_metadata: bool = False) -> dict:
    name = os.path.basename(path)[:-len(".json")]
    parts = name.split("__")
    row = {"file": os.path.basename(path), "scenario": parts[0], "app": parts[1].lower() if len(parts) > 1 else "?"}
    if len(parts) < 3:
        return {**row, "outcome": "INVALID", "why": "file name must be <scenario>__<app>__<device>.json"}
    scenario, app = row["scenario"], row["app"]
    if app not in APPS:
        return {**row, "outcome": "INVALID", "why": f"app must be one of {APPS}"}
    exp = EXPECTED.get(scenario, {}).get(app)
    if exp is None:
        return {**row, "outcome": "INVALID", "why": "no expectation for this scenario/app in expected.json"}
    try:
        r = load_json(path)
    except (OSError, ValueError) as e:
        return {**row, "outcome": "INVALID", "why": f"unreadable JSON: {e}"}
    problems = validate_export(app, r)
    meta_path = path[:-len(".json")] + ".meta.json"
    if os.path.exists(meta_path):
        try:
            problems += validate_metadata(load_json(meta_path), scenario)
        except ValueError as e:
            problems.append(f"unreadable metadata: {e}")
    elif require_metadata:
        problems.append(f"missing {os.path.basename(meta_path)}")
    if problems:
        return {**row, "outcome": "INVALID", "why": "; ".join(problems)}
    outcome, why = evaluate(app, exp, r)
    gap = " [known gap]" if EXPECTED[scenario].get("knownGap") and outcome != "PASS" else ""
    detail = "; ".join(why) or "expectations met"
    return {**row, "outcome": outcome,
            "why": f"{detail}{gap}; codes {sorted(codes_of(r))}; {completion_note(app, r)}"}


def coverage(rows: list[dict]) -> list[dict]:
    seen = {(r["scenario"], r["app"]) for r in rows if r["outcome"] in OUTCOMES}
    out = []
    for scenario, exp in EXPECTED.items():
        for app in APPS:
            if app in exp and (scenario, app) not in seen:
                out.append({"file": "-", "scenario": scenario, "app": app, "outcome": "NOT TESTED",
                            "why": "no exported result"})
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="*")
    ap.add_argument("--coverage", action="store_true", help="also list scenarios with no result as NOT TESTED")
    ap.add_argument("--require-metadata", action="store_true", help="treat a missing .meta.json as INVALID")
    a = ap.parse_args(argv)
    paths = [p for p in a.paths if not p.endswith(".meta.json")]
    rows = [check(p, a.require_metadata) for p in paths]
    if a.coverage:
        rows += coverage(rows)
    if not rows:
        print("no results given")
        return 0
    w = max(len(r["scenario"]) for r in rows)
    for r in rows:
        print(f"{r['outcome']:<10}  {r['scenario']:<{w}}  {r['app']:<15}  {r['why']}")
    return 1 if any(r["outcome"] in ("FAIL", "INVALID") for r in rows) else 0


if __name__ == "__main__":
    sys.exit(main())
