# Lab validation

How to validate detections on real jailbroken devices, and current test status.

## Lab validation plan

The step-by-step harness is in [`Lab/LAB_CHECKLIST.md`](../Lab/LAB_CHECKLIST.md). It covers the scenarios, how to export results from either app (**Copy result JSON**), the run record (`.meta.json`, template in [`Lab/templates/`](../Lab/templates/)), the file-name convention, and `python3 Lab/compare_results.py --coverage --require-metadata Lab/results/*.json`, which prints PASS, PARTIAL, FAIL, INVALID or NOT TESTED per scenario against `Lab/expected.json`. P2 measurement scenarios (Frida attach, spawn, gadget, renamed markers, late attach; palera1n; Shadow-class hiding; fresh versus previously seen hidden installs) are in [`Lab/SCENARIOS.md`](../Lab/SCENARIOS.md). What has actually been measured is in [`Lab/COVERAGE.md`](../Lab/COVERAGE.md).

The table below summarises the expectations. They are targets and hypotheses, not measurements.

Run these on authorised test devices only. Record the signals each scenario produces, and tune the weights from that data.

| Scenario | Expected signals |
|---|---|
| Stock device, App Store or TestFlight build | None, or only `developerModeEnabled` if it is on. |
| Xcode debug run | `ptraced`, `codeSigningDebugged`, `getTaskAllow`, `parentProcessUnexpected`, `developerMode*` (all discounted by `.development`). |
| Dopamine (iOS 15 or 16, A12+), no hiding | `rootlessJailbreakRoot`, `jailbreakPathPresent` for `/var/jb/*`, `suspiciousImage` (systemhook, libellekit, TweakLoader), `envJailbreak`, URL schemes. |
| Dopamine with a hiding tweak | `libcSyscallMismatch`, `imageListMismatch`, `symbolRebound`, `inlineHook` on `stat`/`access`, `objcSwizzled`. |
| palera1n rootful (A8–A11) | `rootVolumeWritable`/`rootVolumeNotSealed`, `/.procursus_strapped`, `/cores/binpack`. |
| frida-server and `frida -U -f` | `fridaThread`, `fridaDBus`, `parentProcessUnexpected`, `anonymousExecutableMemory`, `inlineHook` on instrumented functions, `exceptionPorts`. |
| Repackaged IPA with FridaGadget (no jailbreak) | `instrumentationImage` (205, gadget; `suspiciousImage` before 1.4.0), `fridaThread`, `binaryDecrypted`, `provisioningProfilePresent`, `teamIdentifierMismatch`, `getTaskAllow`, App Attest failure on the server. |
| TrollStore install | `suspiciousEntitlement` (device), `binaryDecrypted` (app). |
| **Tested:** stock iPhone18,1, iOS 27.2.1, Xcode install (v1.0) | v1.0 wrongly reported **Compromised 91**. The causes were build-context signals (`cryptid=0`, `get-task-allow`, provisioning profile), Developer Mode, the `apple-magnifier` false positive and one anonymous r-x region (`0x100fe4000+0xc000`). v1.1 made these informational or removed them. The jailbreak-only app then reported **Not jailbroken** on the same device. If an anonymous executable region still appears on a stock device, open a false-positive issue with the `tag=`/`share=` details shown in the signal. |

## Recorded runs

| Date | Device / iOS | Scenario | Result |
|---|---|---|---|
| 2026-11-21 | iPhone18,1 / 27.2.1 | Stock | v1.0 false positive, fixed in 1.1; JB Check then reported **Not jailbroken** |
| 2026-11-21 | iPhone9,3 / 15.8.2 | Dopamine + RootHide, app not hidden | JB Check **PASS** (`roothideinit.dylib`). Full app device verdict inconsistent, fixed in 1.3.0 |
| 2026-11-21 | iPhone9,3 / 15.8.2 | Dopamine + RootHide, app hidden (Blacklist) | **FAIL**: both apps clean in 1.2. New checks in 1.3.x to be re-tested |
| 2026-11-21 | iPhone18,1 / 27.2.1 | Stock, Kaisel 1.3.0 | **False positive**: JB Check said Jailbroken (`dyldModified`, 162,671 words). Fixed in 1.3.1 |
| 2026-11-21 | iPhone18,1 / 27.2.1 | Stock, Kaisel 1.3.1 | **PASS**: both apps clean |
| 2026-11-21 | Stock device / iOS 26 | Stock, Kaisel 1.3.1 | **PASS**: clean |
| 2026-11-21 | iPhone9,3 / 15.8.2 | Dopamine + RootHide, app not hidden, Kaisel 1.3.1 | **PASS**: Jailbroken |
| 2026-11-21 | iPhone9,3 / 15.8.2 | Dopamine + RootHide, app hidden (Blacklist), Kaisel 1.3.1 | **Partial**: Suspicious (was clean in 1.2). Signals not yet exported; send the result JSON to identify which residual check fired |
| 2026-11-21 | Lab device (not recorded) | TrollStore via TrollInstallerX, Kaisel 1.3.1 | **PASS**: detected by both apps |
| 2026-11-21 | iPhone9,3 / 15.8.2 | Dopamine + RootHide, app not hidden, Kaisel 1.3.x, screenshots | **PASS**: JB Check Jailbroken (`roothideinit.dylib` from `.jbroot-*`, `sileo://`); Integrity Check device Compromised 85, runtime Compromised 97, inline guard flags 2 |
| 2026-11-21 | iPhone9,3 / 15.8.2 | Dopamine + RootHide, app hidden (Blacklist), Kaisel 1.3.x, screenshots | **FAIL**: both apps clean (JB Check Not jailbroken, no indicators; Integrity Check Trusted 0, inline guard clean). The earlier *Suspicious* result did not reproduce; no residual signal fired |
| 2026-11-21 | iPhone18,1 / 27.2.1 | Stock, Kaisel 1.3.x, screenshots | **PASS**: JB Check Not jailbroken; Integrity Check Trusted 0 |

Details: [Lab/results/2026-11-21_iphone9-3_ios15.8.2_dopamine-roothide.md](../Lab/results/2026-11-21_iphone9-3_ios15.8.2_dopamine-roothide.md). Screenshots of the latest runs are in [`docs/images/lab/`](images/lab/) and embedded in the [README](../README.md#lab-results-so-far).

**Current status of the hidden case:** a miss. The latest screenshots show both apps clean with the app on RootHide's Blacklist, so treat the earlier *Suspicious* row as unconfirmed until result JSON from a hidden run shows which signal, if any, fires.

## Test status

| Version | What has been verified |
|---|---|
| 1.0 | Compiled in Xcode and ran on a stock iPhone18,1 (iOS 27.2.1). That run drove the false-positive fixes in 1.1. |
| 1.1 | Jailbreak-only app ran on the same device and reported **Not jailbroken**. |
| 1.4.0 (unreleased) | Image classification and strict server validation. Not run on a device. See [V1.4.0-VALIDATION.md](V1.4.0-VALIDATION.md) for the tests that ran and their results. |
| 1.3.1 | Fixes the 1.3.0 stock iOS 27 false positive. Server tests pass (14). |
| 1.3 | Server tests pass (12). C changes pass `clang -Wall -Wextra -fsyntax-only` against stub headers, including the arm64 paths. Swift changes are not compiled here; CI on GitHub builds them. |
| 1.2 | C core passes `clang -Wall -Wextra -fsyntax-only` (x86_64 and AArch64, stub headers). The reference server's 9 tests and an HTTP smoke test pass. The Swift changes in 1.2 (self-integrity, rules, App Attest opt-in, Kaisel rename) are verified by the CI build on GitHub, not yet on a device. |

**Only one jailbroken device so far** (see Recorded runs and [Lab/COVERAGE.md](../Lab/COVERAGE.md)). No result JSON has been exported for any run yet. Every other jailbreak, hiding-tweak and Frida expectation in
[`Lab/expected.json`](../Lab/expected.json) is a hypothesis until the [lab checklist](../Lab/LAB_CHECKLIST.md)
has been run. Results are welcome through the *Detection gap or lab result* issue template.
