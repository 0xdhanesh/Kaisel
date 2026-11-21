#!/usr/bin/env python3
"""Exports finding codes, weights, hard flags and domains from Finding.swift to
Server/weights.json so the server scores exactly like the SDK.
Run after changing Finding.swift:  python3 Server/tools/export_weights.py"""
import json, os, re

here = os.path.dirname(os.path.abspath(__file__))
root = os.path.abspath(os.path.join(here, "..", ".."))
src = open(os.path.join(root, "Sources/KaiselKit/Finding.swift")).read()

codes = {m.group(1): int(m.group(2)) for m in re.finditer(r"case (\w+)\s*=\s*(\d+)", src)}
meta = {}
for m in re.finditer(r"case \.(\w+):\s*return \.init\(category: \.(\w+),\s*weight: ([\d.]+),\s*hard: (true|false),\s*title: \"([^\"]*)\"\)", src):
    meta[m.group(1)] = dict(category=m.group(2), weight=float(m.group(3)), hard=m.group(4) == "true", title=m.group(5))

dom_block = src[src.index("public var domain: IntegrityDomain"):]
domains = {}
for m in re.finditer(r"case ((?:\.\w+,?\s*)+):\s*return \.(\w+)", dom_block):
    for name in re.findall(r"\.(\w+)", m.group(1)):
        domains[name] = m.group(2)

out = {}
for name, raw in codes.items():
    if name not in meta:
        continue
    out[str(raw)] = dict(name=name, domain=domains.get(name, "runtime"), **meta[name])
missing = [n for n in codes if n not in meta or n not in domains]
if missing:
    raise SystemExit(f"unparsed codes: {missing}")
path = os.path.join(root, "Server", "weights.json")
with open(path, "w") as f:
    json.dump(out, f, indent=1, sort_keys=True)
print(f"wrote {len(out)} codes to {path}")
