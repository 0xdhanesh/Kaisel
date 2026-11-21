# Attestation and the reference server

App Attest, the Secure Enclave seal and how a backend should verify a sealed report.

## Is there an iOS equivalent of Play Integrity?

Not on the device. Play Integrity's verdicts are produced by Google's servers. The app only relays a signed token. The Apple equivalent has the same shape, and it is **server-side**:

| Android | iOS |
|---|---|
| Play Integrity `appIntegrity` (genuine, unmodified app) | **App Attest** (`DCAppAttestService`): a hardware-backed key whose attestation and assertions your server verifies against Apple's CA. A re-signed or modified app cannot produce valid assertions. |
| Play Integrity `deviceIntegrity` (`MEETS_DEVICE_INTEGRITY`) | **No Apple equivalent.** Apple does not attest "this device is not jailbroken". App Attest proves a real Apple device and a genuine app, but it can still succeed on a jailbroken phone. Jailbreak status comes only from on-device checks such as this kit. |
| Device recall bits | **DeviceCheck** (`DCDevice`): two bits per device, stored by Apple, that you set from your server (for example "seen jailbroken"). |
| Root checker apps | `JailbreakDetector` / the Kaisel JB Check app. |

The robust design is therefore: run the on-device checks, seal the report with App Attest (`IntegrityKit.seal`), and let the server verify the assertion and decide. The client-side verdict is evidence, not proof.

## Reference server

```bash
cd Server
python3 -m venv .venv && . .venv/bin/activate && pip install -r requirements.txt
python3 -m unittest discover -s tests                # 9 offline tests, synthetic Apple CA
curl -O https://www.apple.com/certificateauthority/Apple_App_Attestation_Root_CA.pem
python3 server.py --app-id ABCDE12345.com.dhanesh.kaisel.integritycheck \
  --root-ca Apple_App_Attestation_Root_CA.pem --allow-development --expected-distribution none
```

In Kaisel Integrity Attest, enter `http://<your-mac-ip>:8080`, tap **Enrol App Attest** once, then tap **Verify with server**. In Kaisel Integrity Check (free Apple ID) the enrol button is disabled and **Verify with server** sends a Secure Enclave-only seal, so start the server with `--no-require-app-attest`. The response shows `decision`, `reasons`, the server's own device, runtime and app verdicts, and the App Attest and Secure Enclave status. App Attest needs a paid developer team (it is not available on a free personal team) and a real device. Without it the server answers `deny` (use `--no-require-app-attest` for `step_up` instead).

### Remembering jailbroken devices

The reference server applies the same jailbreak rule as the apps: conclusive evidence in any domain sets
the device verdict to `compromised` and lists it in `device.jailbreakEvidence`. It also keeps a
per-key history in its store (`_history`), keyed by the Secure Enclave public key (or the App Attest key).
When a key that once sent conclusive evidence later sends a clean report, for example after the app was
hidden with RootHide, the device verdict is raised to at least `high` and the reason says when the jailbreak
was first seen.

For production, also use **DeviceCheck**: call `IntegrityKit.deviceCheckToken()`, and from your server set
one of the two per-device bits (`update_two_bits`) when conclusive evidence arrives. The bits are stored by
Apple per device and per developer team, survive app deletion and hiding, and are reset only when you
reset them. Query them (`query_two_bits`) on every sensitive request.

## Server-side verification

1. Issue a single-use nonce with a short TTL, bound to the session.
2. Check that `clientDataHash == SHA256(payload || nonce)`.
3. Verify the App Attest assertion with the key from enrolment. The counter must strictly increase and the RP ID must match `<TeamID>.<BundleID>`. No assertion, or a failed assertion, means the report did not come from your genuine app: treat it as `compromised`.
4. Verify the Secure Enclave signature with the public key enrolled for that device.
5. Re-score `payload.signals` under the server's own weights, and apply the policy per transaction risk (step-up, block, limit, or allow and flag).
6. Optionally store a per-device DeviceCheck bit ("seen compromised") so that a reinstall does not reset it.
7. Compare `facts.textSHA256` with the value your CI recorded for that build.
