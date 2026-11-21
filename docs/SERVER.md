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
python3 -m unittest discover -s tests                # offline tests, synthetic Apple CA
curl -O https://www.apple.com/certificateauthority/Apple_App_Attestation_Root_CA.pem
python3 server.py --app-id ABCDE12345.com.dhanesh.kaisel.integritycheck \
  --root-ca Apple_App_Attestation_Root_CA.pem --allow-development --expected-distribution none
```

In Kaisel Integrity Attest, enter `http://<your-mac-ip>:8080`, tap **Enrol App Attest** once, then tap **Verify with server**. In Kaisel Integrity Check (free Apple ID) the enrol button is disabled and **Verify with server** sends a Secure Enclave-only seal, so start the server with `--mode lab` (or the older `--no-require-app-attest`, which now means lab mode). A lab-mode server never answers `allow` without App Attest. The response shows `decision`, `reasons`, the server's own device, runtime and app verdicts, and the App Attest and Secure Enclave status. App Attest needs a paid developer team (it is not available on a free personal team) and a real device. Without it the server answers `deny` (use `--no-require-app-attest` for `step_up` instead).

### Strict and lab modes (1.4.0)

| | `--mode strict` (default) | `--mode lab` |
|---|---|---|
| App Attest assertion | Required; missing or failed means `deny` | Missing means `step_up` |
| Report schema | `sdkVersion` 1.4.0 with `reportSchemaVersion` 2 | Also 1.3.x reports (no schema field), as `step_up` |
| Unknown finding code | `deny` | `step_up` |
| Malformed fields, tampered payload, wrong or reused challenge | `deny` | `deny` |
| Incomplete checks | `step_up` (never `allow`) | `step_up` |

Before scoring, `policy.validate_report()` checks the structure: a supported SDK and schema; a signals
array whose codes are integers, confidences are 0 to 100 and details are strings; `checksCompleted` and
`checksExpected` as 32-bit unsigned integers. The **expected check set comes from the server's own SDK
profile** (`policy.SDK_PROFILES`), never from the client: a client that reports fewer expected checks, or
completion bits outside the profile, is denied. A missing check is incomplete coverage (`step_up`), and
`checkSuppressed` alongside a complete bitmap is a contradiction (`deny`). Every response carries
`mode`, `validation.action` and `validation.reasons`.

**Limitation.** Completion bits are reported by the app. App Attest proves which genuine app instance
signed the report and that the payload was not changed afterwards; it does not prove that the
measurements made inside a possibly compromised process are true. A complete bitmap is necessary for
`allow`, never sufficient on its own.

### Remembering jailbroken devices

The reference server applies the same jailbreak rule as the apps: conclusive evidence in any domain sets
the device verdict to `compromised` and lists it in `device.jailbreakEvidence`. It also keeps a
per-key history in its store (`_history`). Since 1.4.0 it is keyed only by an **App Attest-verified key**
(`aa:<keyId>`). A Secure Enclave key is chosen by the client, so an unbound Secure Enclave signature is
reported as `signature valid (unbound, not authentication)` and can neither create nor clear history. A
1.3.x entry keyed by a Secure Enclave key is still honoured when that key is bound to the verified App
Attest instance.
When a key that once sent conclusive evidence later sends a clean report, for example after the app was
hidden with RootHide, the device verdict is raised to at least `high` and the reason says when the jailbreak
was first seen.

For production, also use **DeviceCheck**: call `IntegrityKit.deviceCheckToken()`, and from your server set
one of the two per-device bits (`update_two_bits`) when conclusive evidence arrives. The bits are stored by
Apple per device and per developer team, survive app deletion and hiding, and are reset only when you
reset them. Query them (`query_two_bits`) on every sensitive request.

Entries are written only from conclusive evidence, and entries whose evidence is no longer conclusive
under the current rule are ignored (this discards entries created by the 1.3.0 dyld false positive and,
since 1.4.0, image entries that no longer classify as a known jailbreak injector).
To wipe the history, start the server with `--clear-history`. There is deliberately no HTTP endpoint for
this, because a client must not be able to erase its own record.

## Server-side verification

1. Issue a single-use nonce with a short TTL, bound to the session.
2. Check that `clientDataHash == SHA256(payload || nonce)`.
3. Verify the App Attest assertion with the key from enrolment. The counter must strictly increase and the RP ID must match `<TeamID>.<BundleID>`. No assertion, or a failed assertion, means the report did not come from your genuine app: treat it as `compromised`.
4. Verify the Secure Enclave signature with the public key enrolled for that device.
5. Re-score `payload.signals` under the server's own weights, and apply the policy per transaction risk (step-up, block, limit, or allow and flag).
6. Optionally store a per-device DeviceCheck bit ("seen compromised") so that a reinstall does not reset it.
7. Compare `facts.textSHA256` with the value your CI recorded for that build.
