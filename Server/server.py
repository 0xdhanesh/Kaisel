#!/usr/bin/env python3
"""KaiselKit reference server (stdlib HTTP + cryptography + cbor2).

NOT production code: single process, JSON-file storage, no auth, no TLS.
It shows the verification steps your real backend must implement.

  pip install -r requirements.txt
  curl -O https://www.apple.com/certificateauthority/Apple_App_Attestation_Root_CA.pem
  python3 server.py --app-id ABCDE12345.com.dhanesh.kaisel.integritycheck \
      --root-ca Apple_App_Attestation_Root_CA.pem --allow-development \
      --expected-distribution none --port 8080

Endpoints
  POST /v1/challenge                    -> {challengeId, challenge}
  POST /v1/attest  {challengeId, keyId, attestationObject}        -> {ok, environment}
  POST /v1/verify  {challengeId, sealed}                          -> decision

Modes: --mode strict (default) fails closed: App Attest required, supported
report schema, every expected check complete. --mode lab is permissive and
labelled as such in every response; never expose it to production traffic.
  GET  /v1/rules.json, /v1/rules.sig    signed detection rules
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import appattest
import policy as pol

CHALLENGE_TTL = 300


class Store:
    def __init__(self, path: str):
        self.path = path
        self.lock = threading.Lock()
        self.challenges: dict[str, tuple[bytes, float]] = {}
        self.devices: dict = {}
        if os.path.exists(path):
            with open(path) as f:
                self.devices = json.load(f)

    def save(self):
        tmp = self.path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(self.devices, f, indent=1)
        os.replace(tmp, self.path)

    def new_challenge(self) -> tuple[str, bytes]:
        cid, ch = secrets.token_urlsafe(16), secrets.token_bytes(32)
        with self.lock:
            now = time.time()
            self.challenges = {k: v for k, v in self.challenges.items() if v[1] > now}
            self.challenges[cid] = (ch, now + CHALLENGE_TTL)
        return cid, ch

    def take_challenge(self, cid: str) -> bytes:
        """Single use: removed on first read."""
        with self.lock:
            item = self.challenges.pop(cid, None)
        if not item or item[1] < time.time():
            raise ValueError("unknown or expired challenge")
        return item[0]


def b64(x) -> bytes:
    return base64.b64decode(x) if x else b""


def _deny(reason: str, **extra) -> dict:
    return {"decision": "deny", "reasons": [reason], "appAttest": "not checked", "secureEnclave": "not checked",
            "validation": {"action": "deny", "reasons": [reason]}, **extra}


def _policy(cfg) -> pol.Policy:
    # Older Cfg objects have no `mode`: --no-require-app-attest used to mean
    # "permissive", which is lab mode in 1.4.0.
    mode = getattr(cfg, "mode", None) or ("strict" if cfg.require_app_attest else "lab")
    return pol.Policy(expected_distribution=cfg.expected_distribution, mode=mode,
                      require_app_attest=cfg.require_app_attest, debugger_expected=cfg.debugger_expected)


def verify_sealed(sealed: dict, challenge: bytes, store: Store, cfg) -> dict:
    """Verifies one sealed report. Never raises for a bad report: tampering,
    a wrong challenge or a malformed payload return a structured `deny`."""
    policy = _policy(cfg)
    if not isinstance(sealed, dict):
        return _deny("sealed report is not a JSON object", mode=policy.mode)
    try:
        payload, nonce, cdh = b64(sealed.get("payload")), b64(sealed.get("nonce")), b64(sealed.get("clientDataHash"))
    except (ValueError, TypeError):
        return _deny("sealed report fields are not valid base64", mode=policy.mode)
    if not payload or nonce != challenge:
        return _deny("nonce is not the issued challenge", mode=policy.mode)
    if appattest.sha256(payload + nonce) != cdh:
        return _deny("clientDataHash != SHA256(payload || nonce): payload or hash tampered", mode=policy.mode)

    result = {"appAttest": "missing", "secureEnclave": "missing"}
    key_id = sealed.get("appAttestKeyId")
    device = store.devices.get(key_id) if isinstance(key_id, str) and not key_id.startswith("_") else None
    if sealed.get("appAttestAssertion"):
        if not device:
            result["appAttest"] = "unknown key (not enrolled)"
        else:
            try:
                device["counter"] = appattest.verify_assertion(
                    b64(sealed["appAttestAssertion"]), cdh, device["publicKeyPEM"], cfg.app_id, device["counter"])
                result["appAttest"] = "verified"
            except (appattest.AttestationError, ValueError, TypeError) as e:
                result["appAttest"] = f"failed: {e}"

    # A Secure Enclave signature proves possession of a key the client chose.
    # It is evidence of continuity only once bound to an App Attest-verified
    # instance; an unbound signature never authenticates the report.
    if sealed.get("secureEnclaveSignature") and sealed.get("secureEnclavePublicKey"):
        try:
            se_pub = b64(sealed["secureEnclavePublicKey"])
            appattest.verify_secure_enclave(b64(sealed["secureEnclaveSignature"]), se_pub, cdh)
            if device is not None and result["appAttest"] == "verified":
                bound = device.get("sePublicKey")
                if bound is None:
                    device["sePublicKey"] = base64.b64encode(se_pub).decode()   # bind on first verified use
                    result["secureEnclave"] = "verified (bound)"
                elif bound == base64.b64encode(se_pub).decode():
                    result["secureEnclave"] = "verified"
                else:
                    result["secureEnclave"] = "key changed"
            else:
                result["secureEnclave"] = "signature valid (unbound, not authentication)"
        except (appattest.AttestationError, ValueError, TypeError) as e:
            result["secureEnclave"] = f"failed: {e}"
    with store.lock:
        store.save()

    try:
        report = json.loads(payload)
    except ValueError:
        return _deny("payload is not JSON", mode=policy.mode, **result)
    validation = pol.validate_report(report, policy)
    signals = report.get("signals") if isinstance(report, dict) and isinstance(report.get("signals"), list) else []
    signals = [x for x in signals if isinstance(x, dict) and pol._is_int(x.get("code"))
               and pol._is_int(x.get("confidence"))]
    assessment = pol.assess(signals, policy)

    # Per-device history, keyed only by an App Attest-verified key: an
    # arbitrary self-generated key must not create or clear device history.
    # A 1.3.x entry keyed by a Secure Enclave key is still read when that key
    # is bound to this verified App Attest instance.
    extra_reasons: list = []
    if result["appAttest"] == "verified":
        hist_key = "aa:" + key_id
        legacy_keys = ["se:" + sealed["secureEnclavePublicKey"]] if result["secureEnclave"].startswith("verified") else []
        with store.lock:
            history = store.devices.setdefault("_history", {})
            evidence = assessment["device"]["jailbreakEvidence"]
            if evidence and not pol.history_valid(history.get(hist_key)):
                history[hist_key] = {"firstSeen": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                                     "evidence": [{"code": e["code"], "detail": e["detail"]} for e in evidence]}
                store.save()
            elif not evidence:
                entry = next((history.get(k) for k in [hist_key] + legacy_keys if pol.history_valid(history.get(k))),
                             None)
                extra_reasons = pol.apply_history(assessment, entry["firstSeen"] if entry else None)
    decision, reasons = pol.decide(assessment, result["appAttest"], policy, validation)
    reasons += extra_reasons
    rep = report if isinstance(report, dict) else {}
    build = rep.get("build") if isinstance(rep.get("build"), dict) else {}
    return {"decision": decision, "reasons": reasons, "mode": policy.mode, "validation": validation, **result,
            "device": assessment["device"], "runtime": assessment["runtime"], "app": assessment["app"],
            "clientVerdict": rep.get("verdict"), "sdkVersion": rep.get("sdkVersion"),
            "rulesVersion": rep.get("rulesVersion"), "textSHA256": build.get("textSHA256")}


def make_handler(store: Store, cfg):
    class H(BaseHTTPRequestHandler):
        def _send(self, code: int, body, ctype="application/json"):
            data = body if isinstance(body, bytes) else json.dumps(body, indent=1).encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _json(self) -> dict:
            n = int(self.headers.get("Content-Length", "0"))
            if n > 2_000_000:
                raise ValueError("body too large")
            return json.loads(self.rfile.read(n) or b"{}")

        def do_GET(self):
            if self.path in ("/v1/rules.json", "/v1/rules.sig"):
                p = os.path.join(cfg.rules_dir, os.path.basename(self.path))
                if os.path.exists(p):
                    return self._send(200, open(p, "rb").read(),
                                      "application/json" if p.endswith(".json") else "text/plain")
            self._send(404, {"error": "not found"})

        def do_POST(self):
            try:
                if self.path == "/v1/challenge":
                    cid, ch = store.new_challenge()
                    return self._send(200, {"challengeId": cid, "challenge": base64.b64encode(ch).decode()})
                body = self._json()
                if self.path == "/v1/attest":
                    ch = store.take_challenge(body["challengeId"])
                    k = appattest.verify_attestation(b64(body["attestationObject"]), body["keyId"], ch, cfg.app_id,
                                                     cfg.root_ca, allow_development=cfg.allow_development)
                    with store.lock:
                        store.devices[k.key_id] = {"publicKeyPEM": k.public_key_pem, "counter": 0,
                                                   "environment": k.environment, "sePublicKey": None,
                                                   "enrolledAt": int(time.time())}
                        store.save()
                    return self._send(200, {"ok": True, "environment": k.environment})
                if self.path == "/v1/verify":
                    try:
                        ch = store.take_challenge(body["challengeId"])
                    except (ValueError, KeyError, TypeError) as e:
                        return self._send(400, _deny(f"challenge rejected: {e}"))
                    return self._send(200, verify_sealed(body.get("sealed"), ch, store, cfg))
                self._send(404, {"error": "not found"})
            except (appattest.AttestationError, ValueError, KeyError) as e:
                self._send(400, {"error": str(e)})

        def log_message(self, fmt, *args):
            print("[server]", fmt % args)

    return H


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--app-id", required=True, help="TEAMID.bundle.identifier")
    ap.add_argument("--root-ca", required=True, help="Apple_App_Attestation_Root_CA.pem")
    ap.add_argument("--allow-development", action="store_true", help="accept the App Attest development environment")
    ap.add_argument("--expected-distribution", default="appStore",
                    choices=["appStore", "enterprise", "adHoc", "development", "none"])
    ap.add_argument("--mode", choices=["strict", "lab"], default="strict",
                    help="strict (default): fail closed. lab: permissive test bench, never for production")
    ap.add_argument("--no-require-app-attest", action="store_true",
                    help="lab mode only: accept reports without App Attest as step_up (implies --mode lab)")
    ap.add_argument("--debugger-expected", action="store_true")
    ap.add_argument("--rules-dir", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "rules"))
    ap.add_argument("--db", default="devices.json")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--clear-history", action="store_true",
                    help="forget all 'seen jailbroken' device keys (e.g. after a false positive), then serve")
    a = ap.parse_args(argv)

    class Cfg:
        app_id = a.app_id
        root_ca = open(a.root_ca, "rb").read()
        allow_development = a.allow_development
        expected_distribution = None if a.expected_distribution == "none" else a.expected_distribution
        mode = "lab" if a.no_require_app_attest else a.mode
        require_app_attest = not a.no_require_app_attest
        debugger_expected = a.debugger_expected
        rules_dir = a.rules_dir

    store = Store(a.db)
    if a.clear_history:
        n = len(store.devices.pop("_history", {}) or {})
        store.save()
        print(f"cleared jailbreak history for {n} device key(s)")
    srv = ThreadingHTTPServer((a.host, a.port), make_handler(store, Cfg))
    print(f"listening on http://{a.host}:{a.port}  app-id={a.app_id}  mode={Cfg.mode}")
    if Cfg.mode == "lab":
        print("WARNING: lab mode is permissive (no App Attest requirement, legacy reports). Never use it in production.")
    srv.serve_forever()


if __name__ == "__main__":
    main()
