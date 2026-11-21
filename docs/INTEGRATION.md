# Integrating KaiselKit

Adding the Swift package to your own app, build hardening and signed remote rules.

## Integration

### 1. Add the package

In Xcode, choose **File › Add Package Dependencies…** and enter the repository URL, or add it to `Package.swift`:

```swift
.package(url: "https://github.com/0xdhanesh/Kaisel.git", from: "1.2.0")
// target dependency:
.product(name: "KaiselKit", package: "Kaisel")
```

You can also vendor the folder and use **Add Local…**. The package has no third-party dependencies.

### 2. Host app `Info.plist`

```xml
<key>LSApplicationQueriesSchemes</key>
<array>
  <string>cydia</string><string>sileo</string><string>zbra</string><string>filza</string>
  <string>undecimus</string><string>activator</string>
</array>
```

### 3. App Attest entitlement

Add the App Attest capability: `com.apple.developer.devicecheck.appattest-environment` set to `production` for release builds. This needs a paid developer team. Without the entitlement the kit still works: `attestKey` throws `IntegrityError.appAttestUnavailable`, `appAttestStatus` reports `notEnrolled`, and `seal` returns a report signed with the Secure Enclave key only, with `attestationError` set to `appattest: not enrolled`. Your server should then treat App Attest as absent.

### 4. Use it

```swift
import KaiselKit

let kit = IntegrityKit(configuration: .init(
    expectedDistribution: .appStore,             // nil = app-build signals informational
    expectedTeamIdentifier: "ABCDE12345",
    expectedBundleIdentifier: "com.example.app",
    allowedExceptionPorts: 1                    // e.g. your crash reporter
))

// Once per install: enrol the App Attest key with your server.
let enrolment = try await kit.attestKey(serverChallenge: challengeFromServer)

// Before a sensitive operation (login, payment, adding a payee):
let report = await kit.evaluate()
let sealed = try await kit.seal(report, serverNonce: nonceFromServer)
try await api.submitIntegrity(sealed)            // the server decides

// Optional: continuous monitoring.
let monitor = IntegrityMonitor(kit: kit, interval: 30, jitter: 10) { report in
    if report.verdict >= .high { /* re-seal and send */ }
}
monitor.start()
```

### 5. Regenerating the indicator table

Edit the lists in `Scripts/gen_strings.py`, then run `python3 Scripts/gen_strings.py`. Each run uses new random keys. Set `RASP_SEED` for reproducible output. Keep the order of the `MISC` list in step with the `RASP_MISC_*` enum in `rasp_internal.h`.

### 6. Jailbreak-only use

```swift
let result = await JailbreakDetector().check()
switch result.status {
case .jailbroken:    print("Jailbroken:", result.conclusive.map(\.detail))
case .suspicious:    print("Suspicious:", result.indicators.map(\.detail))
case .notJailbroken: print("Not jailbroken")
}
```

## Build hardening

`Apps/Hardening.xcconfig` is applied to Release builds of both apps. Copy the same settings into your app:

- `STRIP_STYLE = all`, `STRIP_INSTALLED_PRODUCT = YES`, `DEPLOYMENT_POSTPROCESSING = YES`, `STRIP_SWIFT_SYMBOLS = YES`. The shipped binary has no symbol table, so `rasp_check_*` names are not visible. Keep the dSYM for crash symbolication.
- `GCC_SYMBOLS_PRIVATE_EXTERN = YES`, `DEAD_CODE_STRIPPING = YES`, `LLVM_LTO = YES`, `SWIFT_COMPILATION_MODE = wholemodule`, optimised builds. These inline the raw-syscall helpers into their callers.

Limits:
- **Swift metadata stays visible.** Type names such as `IntegrityKit` remain readable to class-dump-style tools. `SWIFT_REFLECTION_METADATA_LEVEL = none` hides them but breaks `String(describing:)` and some SwiftUI and Mirror use. A commercial obfuscator (symbol renaming, control-flow flattening) is the next step if you need more.
- **SwiftPM sets its own flags.** It does not let a package set `-fvisibility=hidden` without unsafe flags. Stripping at link time removes the symbols from the final executable anyway.

## Remote rules

```bash
cd Server
python3 rules_tool.py genkey --out keys            # keep keys/rules_private.pem offline
# edit rules/rules.json (bump "version"), then:
python3 rules_tool.py sign --key keys/rules_private.pem rules/rules.json   # writes rules/rules.sig
```

In the app:

```swift
let store = try RulesStore(publicKeyPEM: pinnedRulesPublicKeyPEM)
try? await store.update(rulesURL: rulesJSON, signatureURL: rulesSig)    // background, e.g. at launch
let kit = IntegrityKit(configuration: cfg, rules: store.current)       // applies verified rules
```

Safety rules:
- **Signature.** The rules are checked against the pinned public key on every load, including from disk.
- **Anti-rollback.** The highest accepted `version` is stored in the Keychain, and older files are refused.
- **Expiry.** Rules stop applying after `expiresAt`.
- **Minimum SDK.** Rules are ignored by SDKs older than `minSdkVersion`.
- **Additive only.** Rules can never remove compiled-in indicators.
- **Bounded tuning.** Weights stay within 0.5x to 1.5x of the built-in value, and thresholds move by at most ±15 points.
- **Fail-safe.** Any failure keeps the previous valid rules, or none.
- **URL schemes.** A scheme added by rules only works if it is already listed in `LSApplicationQueriesSchemes`.

## App Store considerations

- **Required-reason APIs.** App Store Connect enforces these at submission, whatever the deployment target. The kit references `stat`/`lstat` (File Timestamp), `statfs` (Disk Space) and `sysctl`. Apple's approved reasons do not include a security or anti-tamper reason. `PrivacyInfo.xcprivacy` therefore declares **no** reasons for you. Decide with your compliance team what to declare in the host app's manifest, or remove the libc cross-checks (the raw-syscall versions have no symbol reference).
- **`canOpenURL`** needs the schemes listed. App Review has accepted this for fraud prevention, but justify it in the review notes.
- **Raw syscalls and `fork`.** These are not private API, but they are unusual. Banking and RASP vendors ship equivalent code. Keep the `fork` probe behind `allowForkProbe` if your review history makes it a concern.
- **Loopback probing** does not trigger the Local Network permission prompt.
