"""Server-side re-scoring and decision. Mirrors RiskScorer.swift.

The server never trusts the client's verdict or its `informational` flags: it
re-derives both from finding codes, its own weights and its own policy.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field

HERE = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(HERE, "weights.json")) as _f:
    CODES: dict[str, dict] = json.load(_f)

VERDICTS = ["trusted", "low", "elevated", "high", "compromised"]
DEBUGGER_CODES = {"400", "401", "402", "403", "302"}
CORROBORATING = {"500", "502", "504", "501", "300", "301", "200", "202"}
APP_INFORMATIONAL_BY_DIST = {
    "enterprise": {"900", "603", "903"},
    "adHoc": {"900", "603"},
    "development": {"900", "603", "601"},
}


# Same rule as JailbreakEvidence in the SDK: evidence a stock, sealed iOS cannot produce.
CONCLUSIVE_NAMES = {
    "jailbreakPathPresent", "rootlessJailbreakRoot", "symlinkedSystemDirectory", "rootVolumeWritable",
    "sandboxWrite", "sandboxFork", "libcSyscallMismatch", "imageListMismatch", "envJailbreak",
    "suspiciousEntitlement", "bundlePathUnexpected", "dyldModified",
}
CONCLUSIVE = {c for c, m in CODES.items() if m["name"] in CONCLUSIVE_NAMES}
INJECTOR_CODES = {c for c, m in CODES.items() if m["name"] in ("suspiciousImage", "imageAddedAtRuntime")}


def _is_tweak_injector(detail: str) -> bool:
    d = detail.lower()
    return not ("frida" in d or "gadget" in d or "gum-js" in d)


def is_conclusive(code: str, confidence: int, detail: str) -> bool:
    if code in INJECTOR_CODES:
        if CODES[code]["name"] == "imageAddedAtRuntime" and confidence < 95:
            return False
        return _is_tweak_injector(detail)
    return code in CONCLUSIVE


@dataclass
class Policy:
    expected_distribution: str | None = "appStore"   # None = app domain informational
    require_app_attest: bool = True
    debugger_expected: bool = False
    damping: float = 0.5
    thresholds: tuple = (15, 35, 60, 85)
    hard_confidence_floor: int = 75
    weight_overrides: dict = field(default_factory=dict)


def _informational(code: str, domain: str, policy: Policy) -> bool:
    if domain == "posture":
        return True
    if domain == "app":
        if policy.expected_distribution is None:
            return True
        return code in APP_INFORMATIONAL_BY_DIST.get(policy.expected_distribution, set())
    if domain == "runtime" and policy.debugger_expected and code in DEBUGGER_CODES:
        return True
    return False


def _verdict(score: int, hard: list[dict], policy: Policy) -> str:
    t = policy.thresholds
    v = 0 if score < t[0] else 1 if score < t[1] else 2 if score < t[2] else 3 if score < t[3] else 4
    if hard:
        v = max(v, 3)
    if len({h["category"] for h in hard}) >= 2:
        v = 4
    return VERDICTS[v]


def assess(signals: list[dict], policy: Policy) -> dict:
    scored: dict[str, list[dict]] = {"device": [], "runtime": [], "app": []}
    for s in signals:
        code = str(s.get("code"))
        meta = CODES.get(code)
        if not meta or _informational(code, meta["domain"], policy):
            continue
        conf = max(0, min(100, int(s.get("confidence", 0))))
        w = float(policy.weight_overrides.get(code, meta["weight"]))
        scored[meta["domain"]].append(dict(code=code, category=meta["category"], hard=meta["hard"],
                                           confidence=conf, ew=w * conf / 100.0, title=meta["title"],
                                           detail=s.get("detail", "")))
    # Anonymous exec memory needs corroboration (as in the SDK).
    rt = scored["runtime"]
    if not any(x["code"] in CORROBORATING for x in rt):
        scored["runtime"] = [x for x in rt if x["code"] != "503"]

    out = {}
    for domain, sigs in scored.items():
        by_cat: dict[str, list[float]] = {}
        for x in sigs:
            by_cat.setdefault(x["category"], []).append(x["ew"])
        survive = 1.0
        for ws in by_cat.values():
            cat_survive, factor = 1.0, 1.0
            for w in sorted(ws, reverse=True):
                cat_survive *= 1.0 - min(max(w * factor, 0.0), 1.0)
                factor *= policy.damping
            survive *= cat_survive          # 1 - p_cat == cat_survive
        score = round((1.0 - survive) * 100)
        hard = [x for x in sigs if x["hard"] and x["confidence"] >= policy.hard_confidence_floor]
        out[domain] = dict(score=score, verdict=_verdict(score, hard, policy),
                           signals=[{k: x[k] for k in ("code", "title", "detail", "confidence")} for x in sigs])
    # A conclusive jailbreak signal in any domain (a tweak injector is scored
    # under runtime) makes the device compromised, as in Kaisel JB Check.
    evidence = [x for d in ("device", "runtime") for x in scored[d]
                if is_conclusive(x["code"], x["confidence"], x["detail"])]
    out["device"]["jailbreakEvidence"] = [{k: x[k] for k in ("code", "title", "detail")} for x in evidence]
    if evidence:
        out["device"]["verdict"] = "compromised"
        out["device"]["score"] = max(out["device"]["score"], policy.thresholds[3])
    if policy.expected_distribution is None:
        out["app"]["verdict"] = "not_enforced"
    return out


def apply_history(assessment: dict, first_seen: str | None) -> list[str]:
    """Raises the device verdict to at least `high` when this device key was
    seen jailbroken before but the current report is clean (for example after
    the app was hidden with RootHide or Choicy). Returns extra reasons."""
    dev = assessment["device"]
    if not first_seen or dev["jailbreakEvidence"]:
        return []
    if VERDICTS.index(dev["verdict"]) < VERDICTS.index("high"):
        dev["verdict"] = "high"
    return [f"jailbreak previously seen for this device key ({first_seen})"]


def decide(assessment: dict, app_attest: str, policy: Policy) -> tuple[str, list[str]]:
    """Returns (decision, reasons). decision: allow | step_up | deny."""
    reasons = []
    rank = {v: i for i, v in enumerate(VERDICTS)}
    if app_attest != "verified":
        reasons.append(f"App Attest {app_attest}")
        if policy.require_app_attest:
            return "deny", reasons + ["report origin cannot be trusted"]
    worst = "allow"
    for domain in ("device", "runtime", "app"):
        v = assessment[domain]["verdict"]
        if v == "not_enforced":
            continue
        if rank[v] >= rank["high"]:
            reasons.append(f"{domain} {v}")
            worst = "deny"
        elif rank[v] == rank["elevated"] and worst != "deny":
            reasons.append(f"{domain} {v}")
            worst = "step_up"
    if app_attest != "verified" and worst == "allow":
        worst = "step_up"
    return worst, reasons
