#!/usr/bin/env python3
"""Detection-rules signing tool.

  python3 rules_tool.py genkey  --out keys/            # rules_private.pem, rules_public.pem
  python3 rules_tool.py sign    --key keys/rules_private.pem rules/rules.json   # writes rules/rules.sig
  python3 rules_tool.py verify  --pub keys/rules_public.pem rules/rules.json

Paste rules_public.pem into the app (RulesStore(publicKeyPEM:)). Keep the
private key offline / in your HSM or KMS; never ship it.
"""
import argparse
import base64
import json
import os
import sys
from datetime import datetime, timezone

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

REQUIRED = {"version": int, "issuedAt": str, "expiresAt": str, "extraJailbreakPaths": list,
            "extraImageMarkers": list, "extraURLSchemes": list, "extraFridaPorts": list, "weightOverrides": dict}


def validate(rules: dict) -> None:
    for k, t in REQUIRED.items():
        if not isinstance(rules.get(k), t):
            raise SystemExit(f"rules.{k} missing or not {t.__name__}")
    for k in ("issuedAt", "expiresAt"):
        datetime.fromisoformat(rules[k].replace("Z", "+00:00"))
    if datetime.fromisoformat(rules["expiresAt"].replace("Z", "+00:00")) <= datetime.now(timezone.utc):
        raise SystemExit("rules already expired")
    for p in rules["extraJailbreakPaths"]:
        if not p.startswith("/") or len(p) >= 256:
            raise SystemExit(f"bad path {p!r}")


def sign_bytes(private_pem: bytes, data: bytes) -> str:
    key = serialization.load_pem_private_key(private_pem, password=None)
    return base64.b64encode(key.sign(data, ec.ECDSA(hashes.SHA256()))).decode()


def verify_bytes(public_pem: bytes, data: bytes, sig_b64: str) -> None:
    pub = serialization.load_pem_public_key(public_pem)
    pub.verify(base64.b64decode(sig_b64), data, ec.ECDSA(hashes.SHA256()))


def main(argv=None):
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("genkey"); g.add_argument("--out", default="keys")
    s = sub.add_parser("sign"); s.add_argument("--key", required=True); s.add_argument("rules")
    v = sub.add_parser("verify"); v.add_argument("--pub", required=True); v.add_argument("rules")
    a = ap.parse_args(argv)

    if a.cmd == "genkey":
        os.makedirs(a.out, exist_ok=True)
        key = ec.generate_private_key(ec.SECP256R1())
        priv = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                 serialization.NoEncryption())
        pub = key.public_key().public_bytes(serialization.Encoding.PEM,
                                            serialization.PublicFormat.SubjectPublicKeyInfo)
        with open(os.path.join(a.out, "rules_private.pem"), "wb") as f:
            f.write(priv)
        os.chmod(os.path.join(a.out, "rules_private.pem"), 0o600)
        with open(os.path.join(a.out, "rules_public.pem"), "wb") as f:
            f.write(pub)
        print(pub.decode())
    elif a.cmd == "sign":
        data = open(a.rules, "rb").read()
        validate(json.loads(data))
        sig = sign_bytes(open(a.key, "rb").read(), data)
        out = os.path.splitext(a.rules)[0] + ".sig"
        with open(out, "w") as f:
            f.write(sig + "\n")
        print(f"signed {a.rules} -> {out}")
    elif a.cmd == "verify":
        data = open(a.rules, "rb").read()
        sig = open(os.path.splitext(a.rules)[0] + ".sig").read().strip()
        verify_bytes(open(a.pub, "rb").read(), data, sig)
        print("signature OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
