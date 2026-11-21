# Implementation report: Kaisel 1.4.0

Scope: the "Kaisel v1.4.0 Implementation Specification" (P0, P1, P2), applied to the repository at
commit `1cbb965`. Date: 2026-11-21. 1.4.0 is **not released or tagged**; device-dependent release gates
are open (see [docs/V1.4.0-VALIDATION.md](docs/V1.4.0-VALIDATION.md)).

## Defects addressed

Each spec claim was checked against the code before it was changed.

| # | Claim | Verified? | Where | Fix |
|---|---|---|---|---|
| 1 | Broad image markers (`crane`, `liberty`, `choicy`, ...) are matched against the whole path | **Confirmed** | `rasp_images.c` `rasp_classify_image` (1.3.1) | Markers apply only to the file name of external images and yield 206 (indicator) |
| 2 | Swift and Python infer an injector from any suspicious image not mentioning Frida | **Confirmed** | `JailbreakEvidence.isTweakInjector`, `policy._is_tweak_injector` | Explicit conclusive allow-list; 200 re-validated by the classifier |
| 3 | Bundle prefix check has no directory boundary | **Confirmed** | `in_bundle` (1.3.1): `/var/App.app2` matched `/var/App.app` | `rasp_path_within` with boundary and `/private` normalisation |
| 4 | Remote-rules markers can create a conclusive verdict | **Confirmed** | `rasp_rules_marker_match` returned 200 | Now 206 only |
| 5 | Late-loaded images conclusive on confidence | **Confirmed** (not in the spec) | `imageAddedAtRuntime` at 95 | Late images reported with their class plus 203 (indicator) |
| 6 | Server does not enforce completion bitmaps | **Confirmed** | `server.verify_sealed` (1.3.1) | `policy.validate_report`, server-side SDK profiles, strict mode |
| 7 | Arbitrary self-reported key used as device identity for history | **Confirmed** | `hist_key = "se:" + ...` for unbound signatures | History keyed by App Attest-verified key only |
| 8 | Tampered payload raised an exception rather than a structured decision | Confirmed (minor) | `verify_sealed` | Structured `deny` with reasons |

Replaying the shared fixtures through the 1.3.1 rule shows the false positives concretely: 1.3.1 would
have reported **conclusive** evidence for the `CraneBank` app executable, `CraneBank.framework`,
`LibertyFinance.framework`, `ChoicyAnalytics.framework`, an in-app framework re-validated without a
bundle path, and two external images whose names contain broad markers. One case moves the other way:
`/usr/lib/libsubstrate.dylib` (rootful) is now conclusive by exact identity; 1.3.1 missed it because no
marker matched it, and the same file was already conclusive as a jailbreak path (100).

## Where I disagree with or narrowed the spec

- **"Don't trust a framework solely because it is in the bundle."** Implemented only by identity: an
  in-bundle image with a known Frida, Cycript or injector name is flagged (205). Telling the app's own
  frameworks from a renamed library added by a re-signer needs a build manifest, which is new detection
  outside this release; it stays on the roadmap and is recorded as a limitation.
- **Incomplete reports in strict mode** give `step_up`, not `deny`. The spec allows either; `step_up` is
  never `allow`, and a hard `checkSuppressed` signal usually pushes the runtime verdict to `deny` anyway.
- **Swift/Python parity** is enforced by parsing the Swift sets and comparing them with the manifest and
  by running one fixture file through C, Python and Swift. The Swift scorer is not executed side by side
  with the Python scorer on the same reports.
- **Real-device evidence (P1.1)** could not be produced: no device runs of 1.4.0 have been made and no
  JSON was exported from earlier runs. Those scenarios are NOT TESTED; existing screenshots are cited as
  screenshots. No result JSON was constructed by hand.
- **P2** is delivered as measurement plans and templates (`Lab/SCENARIOS.md`), as the spec asks. It
  deliberately contains no instructions for building, renaming or concealing instrumentation or
  jailbreak tooling.

## Files changed

C core: `include/rasp_core.h` (codes 205, 206, image-class API), `rasp_classify.c` (new), `rasp_images.c`,
`rasp_frida.c`, `rasp_internal.h`, `rasp_strings_table.h` (regenerated).
Swift: `Finding.swift`, `JailbreakDetector.swift` (`ImageEvidence`, new `JailbreakEvidence` rule,
`JailbreakResult.checksIncomplete`/`sdkVersion`), `IntegrityKit.swift`, `Report.swift`
(`reportSchemaVersion`), `Checks/CoreBridge.swift`, `DetectionRules.swift`, `ObfuscatedLists.swift`
(regenerated).
Server: `classification.json` (new), `classification.py` (new), `policy.py`, `server.py`, `weights.json`
(regenerated), tests `test_server.py` (updated), `test_validation.py`, `test_classification.py`,
`test_parity.py` (new).
Scripts and lab: `Scripts/gen_strings.py` (manifest input, `--verify`), `Lab/compare_results.py`,
`Lab/expected.json`, `Lab/LAB_CHECKLIST.md`, `Lab/SCENARIOS.md`, `Lab/COVERAGE.md`, `Lab/templates/*`,
`Lab/tests/test_compare_results.py`.
Tests: `Tests/Fixtures/image_classification.json`, `Tests/CClassifier/*`,
`Tests/KaiselKitTests/ImageClassificationTests.swift`.
CI: `.github/workflows/ci.yml` (C classifier job, lab tests, string-table verification).
Docs: `README.md`, `CHANGELOG.md`, `docs/DETECTION.md`, `docs/SERVER.md`, `docs/LIMITATIONS.md`,
`docs/LAB.md`, `docs/V1.4.0-VALIDATION.md`, this report.

## Tests executed

| Suite | Where | Result |
|---|---|---|
| Server unit tests (`Server/tests`: 14 existing, 32 validation, 9 classification, 9 parity) | Linux, Python 3.13 | **64/64 passed** |
| Lab tooling tests (`Lab/tests`) | Linux, Python 3.13 | **11/11 passed** |
| C image classifier vs fixtures and server (`Tests/CClassifier/run_tests.py`) | Linux, clang and gcc, `-Wall -Wextra -Werror` | **34/34 agree** with both compilers |
| `gen_strings.py --verify` and seeded reproducibility | Linux | **Passed** |
| `py_compile` of lab and server tools | Linux | **Passed** |
| Swift package tests (`xcodebuild test -scheme KaiselKit`) | macOS, Xcode 27.2 (27B52), Swift 6.4.2, iPhone 18 Pro simulator | **27/27 passed** (ImageClassificationTests 9, HardeningTests 3, JailbreakEvidenceTests 5, RiskScorerTests 10) |
| App builds (KaiselJBCheck, KaiselIntegrityCheck, KaiselIntegrityCheckAttest) | macOS, Xcode 27.2, Release, generic iOS, unsigned | **All three succeeded**, 0 errors (1 standard AppIntents metadata warning each) |
| Full C core compile (Apple headers) | macOS, Xcode 27.2 | **Passed** (compiled as part of the three app builds and the package tests) |
| Server, lab, C classifier and `gen_strings.py --verify` re-run on the Mac | macOS, Python venv from `Server/requirements.txt` | **Passed** (64, 11, 34/34, 205 strings) |

## Build status

Built and tested on macOS (Xcode 27.2, Swift 6.4.2) on 2026-11-21: the three apps build unsigned in
Release for generic iOS, and the KaiselKit package tests pass on the iPhone 18 Pro simulator. The server,
lab, C classifier and string-table checks were also re-run on the Mac and passed. No source changes were
needed. This is a build and simulator result only: 1.4.0 has not been run on a device.

## Real-device evidence

None for 1.4.0. Existing evidence (screenshots and owner reports for 1.2 to 1.3.x) is listed in
[Lab/COVERAGE.md](Lab/COVERAGE.md).

## Unsupported or untested scenarios

Everything in `Lab/expected.json` except the runs listed in COVERAGE.md: palera1n, Dopamine without
RootHide, Shadow-class hiding, all Frida scenarios, iOS 16 to 25, iPad, the App Attest variant on a
device, and the reference server with a real App Attest enrolment.

## Remaining risks

- RootHide per-app hiding remains a measured miss.
- In-bundle code is classified by identity only.
- Completion bits are self-reported; App Attest does not prove in-process measurements are true.
- 1.4.0 has not been run on a stock device, so a new false positive cannot yet be ruled out.
- Strict mode rejects 1.3.x reports; deploy the SDK before switching a production server to strict.

## Regressions identified

None in the suites that ran. Existing server tests were updated in three places to reflect deliberate
behaviour changes: strict mode requires App Attest even with `require_app_attest=False` (lab mode now
gives `step_up`), the end-to-end test now sends a complete 1.4.0 report, and a tampered payload returns
`deny` instead of raising `ValueError`.