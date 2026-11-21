# Changelog

All notable changes are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

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

[Unreleased]: https://github.com/0xdhanesh/Kaisel/compare/v1.2.0...HEAD
[1.2.0]: https://github.com/0xdhanesh/Kaisel/releases/tag/v1.2.0
