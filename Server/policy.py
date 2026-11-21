"""Server-side validation, re-scoring and decision. Mirrors RiskScorer.swift.

The server never trusts the client's verdict or its `informational` flags: it
re-derives both from finding codes, its own weights and its own policy.
"""
from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, field

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)
with open(os.path.join(HERE, "weights.json")) as _f:
    CODES: dict[str, dict] = json.load(_f)

import classification as cls  # noqa: E402  (shared manifest, Server/classification.json)

VERDICTS = ["trusted", "low", "elevated", "high", "compromised"]
DEBUGGER_CODES = {"400", "401", "402", "403", "302"}
APP_INFORMATIONAL_BY_DIST = {
    "enterprise": {"900", "603", "903"},
    "adHoc": {"900", "603"},
    "development": {"900", "603", "601"},
}
_NAME_TO_CODE = {m["name"]: c for c, m in CODES.items()}


def _codes(names) -> set:
    missing = [n for n in names if n not in _NAME_TO_CODE]
    if missing:
        raise RuntimeError(f"classification.json names unknown finding codes: {missing}")
    return {_NAME_TO_CODE[n] for n in names}


# Same rule as JailbreakEvidence in the SDK (both are checked against
# classification.json by Server/tests/test_parity.py): an explicit allow-list
# of evidence a stock, sealed iOS cannot produce. An image is conclusive only
# as suspiciousImage (200) whose path still classifies as a known injector.
CONCLUSIVE = _codes(cls.MANIFEST["conclusiveCodes"])
REVALIDATE_IMAGE = _codes(cls.MANIFEST["conclusiveRequiresImageRevalidation"])
INDICATORS = _codes(cls.MANIFEST["indicatorCodes"])
CORROBORATING = _codes(cls.MANIFEST["corroboratingCodes"])


def is_conclusive(code: str, confidence: int, detail: str) -> bool:
    """`confidence` is accepted for API compatibility; the rule does not use it.

    1.4.0: replaces the 1.3.x negative rule "suspiciousImage or
    imageAddedAtRuntime whose detail does not mention Frida is an injector".
    """
    code = str(code)
    if code not in CONCLUSIVE:
        return False
    if code in REVALIDATE_IMAGE:
        return cls.classify_image(detail or "") == cls.JAILBREAK_INJECTOR
    return True


# ---------------------------------------------------------------------------
# Report validation (1.4.0)
#
# The expected check set comes from the server's own SDK profile, never from
# the client. Completion bits are self-reported: App Attest proves which app
# instance signed the report, not that the measurements inside a possibly
# compromised process are true. A complete bitmap is therefore necessary for
# "allow", never sufficient on its own.
# ---------------------------------------------------------------------------
CHECK_NAMES = ["filesystem", "sandbox", "images", "hooks", "debugger", "frida", "codesign",
               "environment", "devmode", "canary", "selfIntegrity"]          # RASP_CHECK_* bit order
ALL_CHECKS = (1 << len(CHECK_NAMES)) - 1
SDK_PROFILES = {
    # sdkVersion: report schema and the checks IntegrityKit.evaluate() always runs.
    "1.4.0": {"schema": 2, "expectedChecks": ALL_CHECKS, "legacy": False},
    # 1.3.x sent no reportSchemaVersion. Accepted only in lab mode.
    "1.3.0": {"schema": 1, "expectedChecks": ALL_CHECKS, "legacy": True},
    "1.3.1": {"schema": 1, "expectedChecks": ALL_CHECKS, "legacy": True},
}
MAX_SIGNALS = 512
CHECK_SUPPRESSED = _NAME_TO_CODE["checkSuppressed"]


def _is_int(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _check_names(mask: int) -> str:
    return ", ".join(n for i, n in enumerate(CHECK_NAMES) if mask & (1 << i)) or "none"


def validate_report(report, policy: "Policy") -> dict:
    """Structure and completeness checks run before any decision.

    Returns {"action": "allow" | "step_up" | "deny", "reasons": [...]}, where
    "allow" means only "no validation objection".
    """
    deny, step = [], []
    strict = policy.mode == "strict"
    if not isinstance(report, dict):
        return {"action": "deny", "reasons": ["report is not a JSON object"]}

    sdk = report.get("sdkVersion")
    schema = report.get("reportSchemaVersion")
    profile = SDK_PROFILES.get(sdk) if isinstance(sdk, str) else None
    if not isinstance(sdk, str):
        deny.append("sdkVersion missing or not a string")
    elif profile is None:
        deny.append(f"unsupported SDK version {sdk!r}")
    elif profile["legacy"]:
        if schema is not None:
            deny.append(f"SDK {sdk} cannot send reportSchemaVersion {schema!r}")
        elif strict:
            deny.append(f"legacy report format (SDK {sdk}) is accepted in lab mode only")
        else:
            step.append(f"legacy report format (SDK {sdk})")
    elif not _is_int(schema) or schema != profile["schema"]:
        deny.append(f"unsupported reportSchemaVersion {schema!r} for SDK {sdk}")

    signals = report.get("signals")
    codes_seen = set()
    if not isinstance(signals, list):
        deny.append("signals missing or not an array")
        signals = []
    elif len(signals) > MAX_SIGNALS:
        deny.append(f"too many signals ({len(signals)} > {MAX_SIGNALS})")
    for i, s in enumerate(signals[:MAX_SIGNALS]):
        if not isinstance(s, dict):
            deny.append(f"signal {i} is not an object")
            continue
        code, conf, detail = s.get("code"), s.get("confidence"), s.get("detail", "")
        if not _is_int(code) or not 0 <= code <= 0xFFFF:
            deny.append(f"signal {i}: code {code!r} is not a finding code")
            continue
        if not _is_int(conf) or not 0 <= conf <= 100:
            deny.append(f"signal {i}: confidence {conf!r} outside 0...100")
        if not isinstance(detail, str):
            deny.append(f"signal {i}: detail is not a string")
        if str(code) not in CODES:
            (deny if strict else step).append(f"unknown finding code {code}")
        codes_seen.add(str(code))

    done, expected = report.get("checksCompleted"), report.get("checksExpected")
    if not _is_int(done) or not _is_int(expected) or not 0 <= done <= 0xFFFFFFFF or not 0 <= expected <= 0xFFFFFFFF:
        deny.append("checksCompleted/checksExpected missing or not 32-bit unsigned integers")
    elif profile is not None:
        want = profile["expectedChecks"]
        if expected == 0:
            deny.append("checksExpected is 0")
        elif expected != want:
            deny.append(f"checksExpected {expected:#x} differs from the server profile {want:#x} for SDK {sdk}")
        if done & ~want:
            deny.append(f"checksCompleted has bits outside the profile ({done & ~want:#x})")
        if done == 0:
            deny.append("no checks completed (checksCompleted is 0)")
        missing = want & ~done
        if missing:
            step.append(f"checks incomplete: {_check_names(missing)}")
            if CHECK_SUPPRESSED not in codes_seen:
                step.append("incomplete checks reported without a checkSuppressed signal")
        elif CHECK_SUPPRESSED in codes_seen:
            deny.append("contradictory report: checkSuppressed with every check complete")

    action = "deny" if deny else "step_up" if step else "allow"
    return {"action": action, "reasons": deny + step}


@dataclass
class Policy:
    expected_distribution: str | None = "appStore"   # None = app domain informational
    # "strict": fail closed. App Attest is always required, the report must be
    # a supported schema with every expected check complete, and unknown
    # finding codes deny. "lab": explicitly permissive for test benches;
    # missing App Attest and legacy (1.3.x) reports give step_up, never allow.
    mode: str = "strict"
    # Lab mode only: strict mode requires App Attest whatever this says.
    require_app_attest: bool = True
    debugger_expected: bool = False
    damping: float = 0.5
    thresholds: tuple = (15, 35, 60, 85)
    hard_confidence_floor: int = 75
    weight_overrides: dict = field(default_factory=dict)

    def __post_init__(self):
        if self.mode not in ("strict", "lab"):
            raise ValueError(f"unknown policy mode {self.mode!r}")

    @property
    def app_attest_required(self) -> bool:
        return self.mode == "strict" or self.require_app_attest


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


def history_valid(entry) -> bool:
    """A history entry counts only if its recorded evidence is still conclusive
    under the current rule. Entries from 1.3.0 (plain strings, possibly from the
    dyld false positive on stock iOS 27) are ignored and overwritten, and since
    1.4.0 an image entry must still classify as a known jailbreak injector (a
    1.3.x entry for a broad-marker match such as a "Crane..." framework is ignored)."""
    if not isinstance(entry, dict):
        return False
    return any(is_conclusive(str(e.get("code")), 100, e.get("detail", "")) for e in entry.get("evidence", []))


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


def decide(assessment: dict, app_attest: str, policy: Policy,
           validation: dict | None = None) -> tuple[str, list[str]]:
    """Returns (decision, reasons). decision: allow | step_up | deny.

    `validation` is the result of validate_report(). Omitting it is only for
    unit tests of the scoring path; the server always passes it.
    """
    reasons = []
    rank = {v: i for i, v in enumerate(VERDICTS)}
    if validation is not None and validation["action"] == "deny":
        return "deny", ["report failed validation"] + validation["reasons"]
    if app_attest != "verified":
        reasons.append(f"App Attest {app_attest}")
        if policy.app_attest_required:
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
    if validation is not None and validation["action"] == "step_up":
        reasons += validation["reasons"]
        if worst == "allow":
            worst = "step_up"
    return worst, reasons
