"""App Attest and Secure Enclave verification (server side).

Implements Apple's documented steps:
https://developer.apple.com/documentation/devicecheck/validating_apps_that_connect_to_your_server
"""
from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone

import cbor2
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

APP_ATTEST_NONCE_OID = x509.ObjectIdentifier("1.2.840.113635.100.8.2")
AAGUID_PRODUCTION = b"appattest" + b"\x00" * 7
AAGUID_DEVELOPMENT = b"appattestdevelop"


class AttestationError(Exception):
    pass


def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


@dataclass
class AuthData:
    rp_id_hash: bytes
    flags: int
    counter: int
    aaguid: bytes | None = None
    credential_id: bytes | None = None


def parse_auth_data(ad: bytes) -> AuthData:
    if len(ad) < 37:
        raise AttestationError("authenticatorData too short")
    out = AuthData(rp_id_hash=ad[:32], flags=ad[32], counter=int.from_bytes(ad[33:37], "big"))
    if out.flags & 0x40 and len(ad) >= 37 + 18:          # attested credential data present
        out.aaguid = ad[37:53]
        n = int.from_bytes(ad[53:55], "big")
        out.credential_id = ad[55:55 + n]
    return out


def _nonce_from_extension(cert: x509.Certificate) -> bytes:
    try:
        ext = cert.extensions.get_extension_for_oid(APP_ATTEST_NONCE_OID).value
    except x509.ExtensionNotFound as e:
        raise AttestationError("nonce extension missing") from e
    der = ext.value
    # SEQUENCE { [1] EXPLICIT { OCTET STRING (32) } }
    if len(der) < 2 + 2 + 2 + 32 or der[0] != 0x30 or der[-34] != 0x04 or der[-33] != 0x20:
        raise AttestationError("unexpected nonce extension encoding")
    return der[-32:]


def _check_validity(cert: x509.Certificate, now: datetime) -> None:
    nb = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before.replace(tzinfo=timezone.utc)
    na = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after.replace(tzinfo=timezone.utc)
    if not (nb <= now <= na):
        raise AttestationError("certificate outside validity period")


@dataclass
class AttestedKey:
    key_id: str
    public_key_pem: str
    environment: str          # "production" or "development"
    receipt: bytes


def verify_attestation(attestation_object: bytes, key_id_b64: str, challenge: bytes, app_id: str,
                       root_ca_pem: bytes, allow_development: bool = False,
                       now: datetime | None = None) -> AttestedKey:
    now = now or datetime.now(timezone.utc)
    obj = cbor2.loads(attestation_object)
    if obj.get("fmt") != "apple-appattest":
        raise AttestationError("fmt is not apple-appattest")
    stmt = obj["attStmt"]
    x5c = stmt["x5c"]
    if len(x5c) < 2:
        raise AttestationError("x5c chain too short")
    cred = x509.load_der_x509_certificate(x5c[0])
    inter = x509.load_der_x509_certificate(x5c[1])
    root = x509.load_pem_x509_certificate(root_ca_pem)

    # 1. Chain: credCert <- intermediate <- Apple App Attest Root CA
    try:
        inter.verify_directly_issued_by(root)
        cred.verify_directly_issued_by(inter)
    except (ValueError, TypeError, InvalidSignature) as e:
        raise AttestationError(f"certificate chain invalid: {e}") from e
    for c in (cred, inter):
        _check_validity(c, now)

    # 2-4. nonce = SHA256(authData || SHA256(challenge)) must equal the cert extension
    auth_data: bytes = obj["authData"]
    nonce = sha256(auth_data + sha256(challenge))
    if _nonce_from_extension(cred) != nonce:
        raise AttestationError("nonce mismatch")

    # 5. SHA256(public key) == keyId
    pub = cred.public_key()
    if not isinstance(pub, ec.EllipticCurvePublicKey):
        raise AttestationError("credential key is not EC")
    raw = pub.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    key_id = base64.b64decode(key_id_b64)
    if sha256(raw) != key_id:
        raise AttestationError("keyId does not match credential public key")

    # 6-9. authenticator data
    ad = parse_auth_data(auth_data)
    if ad.rp_id_hash != sha256(app_id.encode()):
        raise AttestationError("RP ID hash does not match app ID")
    if ad.counter != 0:
        raise AttestationError("attestation counter must be 0")
    if ad.aaguid == AAGUID_PRODUCTION:
        env = "production"
    elif ad.aaguid == AAGUID_DEVELOPMENT and allow_development:
        env = "development"
    else:
        raise AttestationError("unexpected AAGUID (environment)")
    if ad.credential_id != key_id:
        raise AttestationError("credentialId does not match keyId")

    pem = pub.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    return AttestedKey(key_id=key_id_b64, public_key_pem=pem, environment=env, receipt=stmt.get("receipt", b""))


def verify_assertion(assertion: bytes, client_data_hash: bytes, public_key_pem: str, app_id: str,
                     previous_counter: int) -> int:
    """Returns the new counter. Raises AttestationError on any failure."""
    obj = cbor2.loads(assertion)
    sig: bytes = obj["signature"]
    auth_data: bytes = obj["authenticatorData"]
    nonce = sha256(auth_data + client_data_hash)
    pub = serialization.load_pem_public_key(public_key_pem.encode())
    try:
        pub.verify(sig, nonce, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as e:
        raise AttestationError("assertion signature invalid") from e
    ad = parse_auth_data(auth_data)
    if ad.rp_id_hash != sha256(app_id.encode()):
        raise AttestationError("assertion RP ID hash mismatch")
    if ad.counter <= previous_counter:
        raise AttestationError(f"assertion counter not increasing ({ad.counter} <= {previous_counter})")
    return ad.counter


def verify_secure_enclave(signature_der: bytes, public_key_x963: bytes, client_data_hash: bytes) -> None:
    """CryptoKit P256.Signing signature(for: data) = ECDSA-SHA256 over data."""
    pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), public_key_x963)
    try:
        pub.verify(signature_der, client_data_hash, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as e:
        raise AttestationError("Secure Enclave signature invalid") from e
