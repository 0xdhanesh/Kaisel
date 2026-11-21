# Architecture

Package layout, components and the professional RASP features.

## Feature overview

| Feature | Where | What it does |
|---|---|---|
| Runtime self-integrity | `rasp_self.c`, code `610` / `306` | At start-up it records the SHA-256 of the app's `__text` and the first 32 bytes of about 40 sensitive functions (libsystem and the RASP core). Every evaluation compares them again. Any code patched in memory after launch (Frida `Interceptor`, late Substrate or ElleKit hooks, breakpoints) is reported, even when the patch uses an encoding the prologue decoder does not recognise. |
| Static prologue and GOT checks | `rasp_hooks.c` | Trampoline decoding, fishhook and interposing detection, swizzle checks (since v1.0). |
| Scattered inline guard | `IntegrityGuard` / `rasp_quick_guard()` | A header-only, `always_inline` check using raw syscalls only (P_TRACED, CS_DEBUGGED, `/var/jb`). Call `IntegrityGuard.isClean` at many sensitive points so there is no single function to hook. |
| Check-completion bookkeeping | `IntegrityKit` | Each check sets "started" and "completed" bits, and missing bits raise `checkSuppressed`. Checks run in random order. |
| Tamper-evident result | `ProtectedVerdict` (`kit.lastVerdict`) | The verdict is held XOR-masked with an HMAC under per-process random keys. A patched value reads as `compromised`. |
| String obfuscation | `Scripts/gen_strings.py` | Every indicator string is XOR-encoded with a per-string rolling key and wiped after use. No indicators appear in plaintext in the binary. |
| Build hardening | `Apps/Hardening.xcconfig` | Strip all symbols, private-extern C symbols, `-Os`/`-O`, whole-module optimisation, LTO, dead-code stripping. See [Build hardening](INTEGRATION.md#build-hardening). |
| Signed remote rules | `DetectionRules.swift`, `Server/rules_tool.py` | Lets you add jailbreak paths, image markers, URL schemes and Frida ports, and tune weights and thresholds within bounds, without an app release. Rules are ECDSA-P256-signed, versioned with anti-rollback, have an expiry, and are additive only. See [Remote rules](INTEGRATION.md#remote-rules). |
| Reference server | `Server/` | Verifies App Attest attestations and assertions, the Secure Enclave seal and challenge freshness, re-scores signals with its own weights and returns `allow`, `step_up` or `deny`. It also serves the signed rules. There are 9 offline tests. |
| Lab harness | `Lab/` | A jailbroken-device checklist, expected signals per scenario, in-app "Copy result JSON" and `compare_results.py`. |

## Architecture

```
Kaisel/
├── Package.swift                      SwiftPM manifest, iOS 15+, product: KaiselKit
├── Sources/CIntegrityCore/            C core: evidence only, no policy
│   ├── include/rasp_core.h            public C API, finding codes, inline guard
│   ├── rasp_internal.h                force-inlined raw `svc #0x80` syscalls
│   ├── rasp_strings_table.h           GENERATED, no plaintext indicators
│   ├── rasp_fs.c                      artefacts, errno oracle, SSV, sandbox, canaries
│   ├── rasp_images.c                  dyld images (two sources), interposing, runtime monitor
│   ├── rasp_hooks.c                   inline hooks, GOT rebinding, stub integrity, swizzling
│   ├── rasp_debug.c                   P_TRACED, CS_DEBUGGED, exception ports, ppid, Developer Mode
│   ├── rasp_frida.c                   threads, loopback D-Bus probe, anonymous exec memory
│   ├── rasp_codesign.c                csops flags, entitlements blob, cryptid, __TEXT hash
│   ├── rasp_env.c                     DYLD_* / jailbreak variables, getenv cross-check
│   ├── rasp_self.c                    __text hash and prologue snapshots (self-integrity)
│   └── rasp_rules.c                   extra indicators from signed rules
├── Sources/KaiselKit/                 Swift: policy, scoring, sealing
│   ├── IntegrityKit.swift             entry point, orchestration, tamper bookkeeping
│   ├── JailbreakDetector.swift        jailbreak-only API used by Kaisel JB Check
│   ├── Finding.swift                  codes, domains, weights, hard indicators
│   ├── RiskScorer.swift               damped noisy-OR scoring per domain
│   ├── Report.swift                   Signal, IntegrityReport, posture and build facts
│   ├── Configuration.swift            distribution profile, expectations, overrides
│   ├── IntegrityGuard.swift           inline guard and tamper-evident verdict
│   ├── DetectionRules.swift           signed remote rules (verify, store, apply)
│   ├── Attestation.swift              App Attest, Secure Enclave, DeviceCheck, SealedReport
│   ├── IntegrityMonitor.swift         jittered periodic re-evaluation
│   ├── PlatformCapabilities.swift     per-version observability notes
│   └── Checks/                        C bridge, app-integrity and posture probes
├── Tests/KaiselKitTests/              scorer, policy and hardening unit tests
├── Apps/                              XcodeGen spec for the two apps
│   ├── project.yml                    schemes: KaiselJBCheck, KaiselIntegrityCheck(+Attest)
│   ├── KaiselJBCheck/                 Kaisel JB Check (SwiftUI)
│   ├── KaiselIntegrityCheck/          Kaisel Integrity Check (SwiftUI)
│   └── Hardening.xcconfig             Release hardening settings
├── Server/                            Python reference server (attestation, policy, rules)
├── Lab/                               jailbroken-device test plan and result comparison
├── Scripts/                           IPA builds, string obfuscation, icon generator
├── Branding/                          icon masters and preview
└── docs/                              documentation
```

The C layer reports findings (`code`, `confidence`, `detail`) and sets a "started" and a "completed" bit per check. The Swift layer applies the configuration, weights, scoring and sealing.
