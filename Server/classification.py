"""Evidence classification shared with the SDK (Kaisel 1.4.0).

Loads Server/classification.json, the same manifest Scripts/gen_strings.py
compiles into the C core, and mirrors rasp_image_class() in
Sources/CIntegrityCore/rasp_classify.c. Tests/Fixtures/image_classification.json
is run against this module, the C classifier and the Swift wrapper, so the
three cannot drift apart silently.
"""
from __future__ import annotations

import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(HERE, "classification.json")) as _f:
    MANIFEST: dict = json.load(_f)

_IMG = MANIFEST["images"]
_INJECTOR = {s.lower() for s in _IMG["jailbreakInjectorBasenames"]}
_JB_PREFIXES = list(_IMG["jailbreakRootPrefixes"])
_JB_COMPONENTS = [s.lower() for s in _IMG["jailbreakRootComponentPrefixes"]]
_INSTR = {s.lower() for s in _IMG["instrumentationBasenames"]}
_INSTR_PREFIXES = [s.lower() for s in _IMG["instrumentationBasenamePrefixes"]]
_MARKERS = [s.lower() for s in _IMG["broadMarkers"]]
_TRUSTED = list(_IMG["trustedPrefixes"])

TRUSTED = "trusted"
JAILBREAK_INJECTOR = "jailbreakInjector"
INSTRUMENTATION = "instrumentation"
MARKER = "marker"
UNKNOWN_EXTERNAL = "unknownExternal"
UNKNOWN = "unknown"

CLASS_CODE = {JAILBREAK_INJECTOR: 200, INSTRUMENTATION: 205, MARKER: 206, UNKNOWN_EXTERNAL: 201}


def normalise(path: str) -> str:
    if path.startswith("/private/var/") or path.startswith("/private/preboot/"):
        return path[len("/private"):]
    return path


def within(path: str, directory: str) -> bool:
    """Directory-boundary prefix test on normalised paths."""
    if not path or not directory:
        return False
    p, d = normalise(path), normalise(directory)
    while len(d) > 1 and d.endswith("/"):
        d = d[:-1]
    if not p.startswith(d):
        return False
    return len(p) == len(d) or p[len(d)] == "/"


def _has_app_component(p: str) -> bool:
    parts = p.split("/")[:-1]          # directory components only
    return any(len(c) > 4 and c.lower().endswith(".app") for c in parts)


def classify_image(raw_path: str | None, bundle: str | None = None, simulator: bool = False,
                   remote_markers: tuple | list = ()) -> str:
    if not raw_path or "/" not in raw_path:
        return UNKNOWN
    p = normalise(raw_path[raw_path.index("/"):])
    base = p.rsplit("/", 1)[-1]
    if not base or len(p) >= 1024:
        return UNKNOWN
    b = base.lower()
    inside = within(p, bundle) if bundle else _has_app_component(p)

    if b in _INSTR or any(b.startswith(x) for x in _INSTR_PREFIXES):
        return INSTRUMENTATION
    injector = b in _INJECTOR
    if injector and inside:
        return INSTRUMENTATION
    if not inside and (injector or any(within(p, x) for x in _JB_PREFIXES)
                       or any(c.lower().startswith(x) for c in p.split("/") for x in _JB_COMPONENTS)):
        return JAILBREAK_INJECTOR
    if inside or simulator:
        return TRUSTED
    if any(within(p, x) for x in _TRUSTED):
        return TRUSTED
    if any(m in b for m in _MARKERS) or any(m.lower() in b for m in remote_markers if m):
        return MARKER
    return UNKNOWN_EXTERNAL


def image_code(raw_path: str | None, bundle: str | None = None) -> int:
    return CLASS_CODE.get(classify_image(raw_path, bundle), 0)
