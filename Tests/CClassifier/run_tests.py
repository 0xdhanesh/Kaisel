#!/usr/bin/env python3
"""Builds the C image classifier for the host and checks it against
Tests/Fixtures/image_classification.json and against Server/classification.py.

  python3 Tests/CClassifier/run_tests.py          (needs cc/clang/gcc)
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
CORE = os.path.join(ROOT, "Sources", "CIntegrityCore")
sys.path.insert(0, os.path.join(ROOT, "Server"))
import classification  # noqa: E402


def build(out_dir: str) -> str:
    cc = os.environ.get("CC") or shutil.which("clang") or shutil.which("cc") or shutil.which("gcc")
    if not cc:
        raise SystemExit("NOT TESTED: no C compiler found")
    exe = os.path.join(out_dir, "classify")
    cmd = [cc, "-std=c11", "-D_DEFAULT_SOURCE", "-D_GNU_SOURCE", "-Wall", "-Wextra", "-Werror", "-Wno-unknown-pragmas",
           "-I", os.path.join(CORE, "include"), "-I", CORE,
           os.path.join(HERE, "classify_main.c"), os.path.join(CORE, "rasp_classify.c"),
           os.path.join(CORE, "rasp_util.c"), "-o", exe]
    subprocess.run(cmd, check=True)
    return exe


def main() -> int:
    cases = json.load(open(os.path.join(ROOT, "Tests", "Fixtures", "image_classification.json")))["cases"]
    with tempfile.TemporaryDirectory() as d:
        exe = build(d)
        lines = "".join(f"{1 if c['simulator'] else 0}\t{c['bundle'] or '-'}\t{','.join(c['remoteMarkers']) or '-'}\t{c['path']}\n"
                        for c in cases)
        out = subprocess.run([exe], input=lines, capture_output=True, text=True, check=True).stdout.splitlines()
    fails = 0
    for c, row in zip(cases, out):
        got_c, code = row.split("\t")
        got_py = classification.classify_image(c["path"], c["bundle"], c["simulator"], c["remoteMarkers"])
        ok = got_c == c["expected"] == got_py and int(code) == classification.CLASS_CODE.get(got_c, 0)
        fails += not ok
        print(f"{'PASS' if ok else 'FAIL'}  C={got_c:<18} py={got_py:<18} want={c['expected']:<18} {c['name']}")
    if len(out) != len(cases):
        print(f"FAIL  driver printed {len(out)} rows for {len(cases)} cases")
        fails += 1
    print(f"{len(cases) - fails}/{len(cases)} classification cases agree (C core, server, fixture)")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
