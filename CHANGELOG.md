# Changelog

All notable changes are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

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

[Unreleased]: https://github.com/0xdhanesh/Kaisel/compare/v1.3.1...HEAD
[1.3.1]: https://github.com/0xdhanesh/Kaisel/compare/v1.3.0...v1.3.1
[1.3.0]: https://github.com/0xdhanesh/Kaisel/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/0xdhanesh/Kaisel/releases/tag/v1.2.0
