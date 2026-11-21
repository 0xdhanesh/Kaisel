# Changelog

All notable changes are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the project uses [Semantic Versioning](https://semver.org/).

## [1.4.1] - 2026-11-21

### Fixed
- Release packaging: the app version (`MARKETING_VERSION` in `Apps/project.yml`) is now 1.4.1. The v1.4.0
  release IPAs were built with the stale 1.3.1 version in their file names and `CFBundleShortVersionString`.
  No code changes; the SDK version reported to the server stays 1.4.0.

## [1.4.0] - 2026-11-21

Reduces image false positives, makes the reference server fail closed, and adds reproducible lab evidence
tooling. Not yet run on a device; do not tag until the open release gates pass.

### Fixed
- **Broad image markers could prove a "jailbreak".** Up to 1.3.1 the C core matched substrings such as
  `crane`, `liberty` and `choicy` against the whole image path, and Swift and the server treated every such
  match that did not mention Frida as a conclusive tweak injector. A framework named `CraneBank`,
  `LibertyFinance` or `ChoicyAnalytics` could therefore make a stock phone "Jailbroken". Found by code
  review; never observed on a device.
- **Bundle prefix without a directory boundary.** `/var/App.app2/...` counted as inside `/var/App.app`.
- **Late-loaded images were conclusive on confidence alone** (`imageAddedAtRuntime` at 95 without "frida").
- **Signed remote-rules image markers could create a conclusive verdict.** They are now indicators only.
- **Server accepted reports without checking completion.** A report with no signals and incomplete checks
  could be allowed.
- **Server history trusted unbound Secure Enclave keys.** A self-generated key could create or clear
  device history.

### Added
- Explicit image classes in the C core (`rasp_classify.c`, `rasp_image_class`): jailbreak injector,
  instrumentation, trusted, marker, unknown external, unknown. Swift wrapper `ImageEvidence` /
  `ImageEvidenceClass`.
- Finding codes `instrumentationImage` (205, runtime, hard, weight 0.90) and `imageMarkerMatch`
  (206, runtime, indicator, weight 0.50).
- `Server/classification.json`: one manifest for the conclusive, indicator and corroborating code sets and
  the image lists. `Scripts/gen_strings.py` compiles the lists into the C core; the server loads it directly.
- `Server/classification.py`, the server's copy of the classifier.
- Server strict and lab modes (`--mode`), `policy.validate_report()`, server-side SDK profiles with the
  expected check set, and `validation` / `mode` in every `/v1/verify` response.
- `IntegrityReport.reportSchemaVersion` (2) and `IntegrityReport.currentSchemaVersion`.
- `JailbreakResult.checksIncomplete` and `JailbreakResult.sdkVersion` for lab records.
- `JailbreakEvidence.isConclusive(code:detail:)`.
- Tests: shared fixtures `Tests/Fixtures/image_classification.json` (34 cases) run by the C core
  (`Tests/CClassifier`), the server (`test_classification.py`) and Swift (`ImageClassificationTests`);
  `test_validation.py` (32 strict-mode and sealed-flow tests); `test_parity.py` (Swift/manifest/server
  parity, weights, string table); `Lab/tests` (11 tests).
- `Scripts/gen_strings.py --verify` (seed-independent check of the committed table) and reproducible
  output with `RASP_SEED`.
- Lab: run metadata (`.meta.json`) and its validation, PARTIAL / INVALID / NOT TESTED outcomes and
  `--coverage` in `compare_results.py`; `Lab/templates/`; `Lab/SCENARIOS.md` (P2 measurement plans);
  `Lab/COVERAGE.md`; scenarios `stock_ios26`, `dopamine_roothide_hidden_fresh`,
  `dopamine_roothide_hidden_seen`, `frida_spawn`, `frida_renamed`, `frida_late_attach`,
  `shadow_class_hiding`.
- CI: C classifier job, Lab tests, string-table verification and seeded reproducibility.
- `docs/V1.4.0-VALIDATION.md`, `IMPLEMENTATION_REPORT.md`.

### Changed (classification, with reasons)
- `suspiciousImage` (200) now means *known jailbreak injector* only: an exact injector basename outside the
  app bundle, or an image under `/var/jb/`, `MobileSubstrate/DynamicLibraries/`, `/usr/lib/TweakInject/` or a
  `.jbroot-*` component. It is in the conclusive set and is re-validated from its path wherever it is read.
  Title changed to "Known jailbreak injection library loaded".
- FridaGadget, frida-agent and Cycript images are `instrumentationImage` (205): runtime risk, never a
  jailbreak (before: 200, not conclusive because of the Frida exception).
- An injector basename **inside** the app bundle (for example Substrate injected into a re-signed IPA) is 205,
  not a jailbreak: such apps run on stock phones.
- Broad markers apply only to the file name of images outside the system and the bundle, and produce 206.
- `/usr/lib/libsubstrate.dylib` (rootful) is now conclusive by exact identity. 1.3.1 missed it because no
  marker matched; the same file is already a conclusive jailbreak path (100).
- Late-loaded images are reported with their class (200/205/206/201) plus `imageAddedAtRuntime` (203),
  which is an indicator only.
- `JailbreakEvidence.isTweakInjector(_:)` now means "classifies as a known jailbreak injector".
- Keychain markers and server history entries are re-validated with the new rule; 1.3.x entries from a
  broad-marker match are ignored.
- Server: strict mode is the default and always requires App Attest; `--no-require-app-attest` now
  selects lab mode. Tampered payloads, wrong challenges and malformed payloads return a structured `deny`
  instead of raising. History is keyed by the App Attest key (`aa:`); legacy `se:` entries are read only
  when the Secure Enclave key is bound to the verified App Attest instance.
- `IntegrityKit.sdkVersion` is "1.4.0".
- Docs: README, DETECTION, SERVER, LIMITATIONS, LAB, LAB_CHECKLIST and expected.json distinguish measured
  results from expectations, state that "Not jailbroken" is not proof, and list untested combinations.

### Compatibility
- Server: 1.3.x reports (no `reportSchemaVersion`) are rejected in strict mode and accepted as `step_up`
  in lab mode. Deploy the 1.4.0 SDK before switching a production server to strict mode.
- Integrators who matched on `suspiciousImage` for Frida must also handle `instrumentationImage` (205).
- `IntegrityReport` gained a stored property; code that builds reports by hand must pass it.

## Documentation and lab updates after 1.3.1 (2026-11-21, folded into 1.4.0)

### Added
- `docs/Pentesting iOS RASP.md`: adversary-centred assessment methodology in five layers (hide, hook/patch,
  tamper, kernel, server), tiered test plan, results and reporting templates, MASVS/MASTG/ATT&CK/CBUAE/PCI DSS
  mapping, and a gap analysis of Kaisel with proposed improvements.

### Changed
- README: version 1.3.1, lab results so far, roadmap from the gap analysis, and clearer limitations
  (per-app hiding, dyld indicator). Lab results, limitations and roadmap now state the hidden RootHide case
  as a miss, matching the screenshots.

### Lab
- Dopamine + RootHide with the app hidden (iPhone9,3, iOS 15.8.2): an earlier 1.3.1 run read **Suspicious**,
  but the latest runs read clean in both apps (Not jailbroken, Trusted 0). The hidden case is a miss.
  Result JSON not yet exported.
- Screenshots of the RootHide hidden and unhidden runs and the stock iPhone18,1 (iOS 27.2.1) run added
  under `docs/images/lab/` and embedded in the README.
- TrollStore installed with TrollInstallerX: detected by both apps.
- Stock iOS 26 and iOS 27.2.1: clean on 1.3.1.

## [1.3.1] - 2026-11-21

### Fixed
- **False "Jailbroken" on a stock iPhone18,1 / iOS 27.2.1.** The 1.3.0 dyld check compared the dyld running
  from the shared cache (iOS 16+) with `/usr/lib/dyld` and found 162,671 differing words. The check now skips
  in-cache dyld, ignores large layout differences, and `dyldModified` is an indicator, not conclusive.
- Keychain jailbreak markers and server history entries created by that false positive are discarded.
- Keychain markers are written only for conclusive evidence with confidence 90 or more.

### Added
- `JailbreakHistory.reset()` and a **Reset jailbreak history** button in both apps; `--clear-history` for the server.
- Stock iOS 27 regression tests (Swift and server).

## [1.3.0] - 2026-11-21

First jailbroken-device results: Dopamine + RootHide on iPhone9,3, iOS 15.8.2.

### Added
- `JailbreakEvidence`: one rule for "conclusive" evidence, shared by JB Check, the full kit and the server.
- `dyldModified` (110): dyld `__text` compared with `/usr/lib/dyld` on disk, and dyld's load path checked (made an indicator in 1.3.1).
- `userspaceReboot` (111): `kern.userspacereboottime` indicator (Dopamine restarts userspace).
- `previouslyJailbroken` (908): Keychain memory of an earlier conclusive result.
- Reference server: per-key jailbreak history and `device.jailbreakEvidence`.
- `IntegrityReport.jailbreakEvidence` and a "Jailbreak" row in Kaisel Integrity Check.
- Lab scenarios `dopamine_roothide` and `dopamine_roothide_hidden`, with the first recorded run.

### Changed
- The device verdict is `compromised` whenever conclusive jailbreak evidence exists in any domain
  (a RootHide-injected device showed "Elevated 56" before).
- `syscallStubAltered` follows a same-image branch before firing, records the entry bytes, and uses confidence 60.

### Known gap
- With the app in RootHide's Blacklist, 1.2 reported a clean device. See docs/LIMITATIONS.md.

## [1.2.0] - 2026-11-21

### Added
- Rebranded as **Kaisel**: Swift package `KaiselKit`, apps **Kaisel JB Check** and **Kaisel Integrity Check**, new app icons.
- `KaiselIntegrityCheckAttest` scheme: App Attest is now opt-in, so both main apps build with a free Apple ID.
- `IntegrityKit.appAttestStatus` and `IntegrityError.appAttestUnavailable`; App Attest failures no longer surface as raw errors.
- Unsigned IPA builds (`Scripts/build_unsigned_ipa.sh`) and a release workflow for Impactor and Sideloadly users.
- Runtime self-integrity (`__text` hash, prologue snapshots), inline guard, tamper-evident verdict.
- Signed remote rules with anti-rollback and bounded tuning.
- Python reference server with App Attest verification and policy re-scoring.
- Lab harness: checklist, expected results and `compare_results.py`.
- GitHub CI, issue and pull request templates, contributing and security guides.

### Changed
- Results are split into device, runtime and app domains; build and posture signals are informational by default.

### Fixed
- A stock iOS 27 device was reported as compromised (build-context signals, the `apple-magnifier` URL scheme and objc trampoline memory).
- Swift type-checker timeouts in `IntegrityKit.swift` and related files.

## [1.0.0]

### Added
- First version: C core with raw-syscall checks and the Swift scoring layer.

[Unreleased]: https://github.com/0xdhanesh/Kaisel/compare/v1.4.1...HEAD
[1.4.1]: https://github.com/0xdhanesh/Kaisel/compare/v1.4.0...v1.4.1
[1.4.0]: https://github.com/0xdhanesh/Kaisel/compare/v1.3.1...v1.4.0
[1.3.1]: https://github.com/0xdhanesh/Kaisel/compare/v1.3.0...v1.3.1
[1.3.0]: https://github.com/0xdhanesh/Kaisel/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/0xdhanesh/Kaisel/releases/tag/v1.2.0
