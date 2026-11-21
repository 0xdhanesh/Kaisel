#!/usr/bin/env python3
"""Checks exported lab results against expected.json.

Export a result from the app ("Copy result JSON"), save it as
Lab/results/<scenario>__<app>__<device>.json, for example
  Lab/results/dopamine__jbcheck__iphone11-16.6.json
then run
  python3 Lab/compare_results.py Lab/results/*.json
and send back the printed table plus the JSON files.
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
EXPECTED = json.load(open(os.path.join(HERE, "expected.json")))


def codes_of(result: dict) -> set:
    sigs = result.get("signals") or (result.get("conclusive", []) + result.get("indicators", []))
    return {int(s["code"]) for s in sigs}


def check(path: str):
    name = os.path.basename(path).rsplit(".", 1)[0]
    parts = name.split("__")
    if len(parts) < 2:
        return name, "?", "SKIP", "file name must be <scenario>__<app>__<device>.json"
    scenario, app = parts[0], parts[1].lower()
    exp = EXPECTED.get(scenario, {}).get(app)
    if exp is None:
        return scenario, app, "SKIP", "no expectation for this scenario/app"
    r = json.load(open(path))
    problems = []
    if app == "jbcheck" and r.get("status") not in exp.get("status", [r.get("status")]):
        problems.append(f"status {r.get('status')} not in {exp['status']}")
    if app == "integritycheck":
        for dom in ("device", "runtime"):
            if dom in exp:
                v = (r.get(dom) or {}).get("verdict")
                if v not in exp[dom]:
                    problems.append(f"{dom} {v} not in {exp[dom]}")
    if "any_codes" in exp and not (codes_of(r) & set(exp["any_codes"])):
        problems.append(f"none of codes {exp['any_codes']} seen (got {sorted(codes_of(r))})")
    return scenario, app, "PASS" if not problems else "FAIL", "; ".join(problems) or f"codes {sorted(codes_of(r))}"


def main(paths):
    rows = [check(p) for p in paths]
    w = max([len(r[0]) for r in rows] + [8])
    for s, a, res, why in rows:
        print(f"{res:4}  {s:<{w}}  {a:<15}  {why}")
    return 1 if any(r[2] == "FAIL" for r in rows) else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
