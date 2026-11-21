# Lab validation

How to validate detections on real jailbroken devices, and current test status.

## Lab validation plan

The step-by-step harness is in [`Lab/LAB_CHECKLIST.md`](../Lab/LAB_CHECKLIST.md). It covers the scenarios, how to export results from either app (**Copy result JSON**), the file-name convention, and `python3 Lab/compare_results.py Lab/results/*.json`, which prints PASS or FAIL per scenario against `Lab/expected.json`. The table below summarises those expectations.

Run these on authorised test devices only. Record the signals each scenario produces, and tune the weights from that data.

| Scenario | Expected signals |
|---|---|
| Stock device, App Store or TestFlight build | None, or only `developerModeEnabled` if it is on. |
| Xcode debug run | `ptraced`, `codeSigningDebugged`, `getTaskAllow`, `parentProcessUnexpected`, `developerMode*` (all discounted by `.development`). |
| Dopamine (iOS 15 or 16, A12+), no hiding | `rootlessJailbreakRoot`, `jailbreakPathPresent` for `/var/jb/*`, `suspiciousImage` (systemhook, ellekit), `envJailbreak`, URL schemes. |
| Dopamine with a hiding tweak | `libcSyscallMismatch`, `imageListMismatch`, `symbolRebound`, `inlineHook` on `stat`/`access`, `objcSwizzled`. |
| palera1n rootful (A8–A11) | `rootVolumeWritable`/`rootVolumeNotSealed`, `/.procursus_strapped`, `/cores/binpack`. |
| frida-server and `frida -U -f` | `fridaThread`, `fridaDBus`, `parentProcessUnexpected`, `anonymousExecutableMemory`, `inlineHook` on instrumented functions, `exceptionPorts`. |
| Repackaged IPA with FridaGadget (no jailbreak) | `suspiciousImage` (gadget), `fridaThread`, `binaryDecrypted`, `provisioningProfilePresent`, `teamIdentifierMismatch`, `getTaskAllow`, App Attest failure on the server. |
| TrollStore install | `suspiciousEntitlement` (device), `binaryDecrypted` (app). |
| **Tested:** stock iPhone18,1, iOS 27.2.1, Xcode install (v1.0) | v1.0 wrongly reported **Compromised 91**. The causes were build-context signals (`cryptid=0`, `get-task-allow`, provisioning profile), Developer Mode, the `apple-magnifier` false positive and one anonymous r-x region (`0x100fe4000+0xc000`). v1.1 made these informational or removed them. The jailbreak-only app then reported **Not jailbroken** on the same device. If an anonymous executable region still appears on a stock device, open a false-positive issue with the `tag=`/`share=` details shown in the signal. |

## Recorded runs

| Date | Device / iOS | Scenario | Result |
|---|---|---|---|
| 2026-11-21 | iPhone18,1 / 27.2.1 | Stock | v1.0 false positive, fixed in 1.1; JB Check then reported **Not jailbroken** |
| 2026-11-21 | iPhone9,3 / 15.8.2 | Dopamine + RootHide, app not hidden | JB Check **PASS** (`roothideinit.dylib`). Full app device verdict inconsistent, fixed in 1.3.0 |
| 2026-11-21 | iPhone9,3 / 15.8.2 | Dopamine + RootHide, app hidden (Blacklist) | **FAIL**: both apps clean in 1.2. New checks in 1.3.0 to be re-tested |

Details: [Lab/results/2026-11-21_iphone9-3_ios15.8.2_dopamine-roothide.md](../Lab/results/2026-11-21_iphone9-3_ios15.8.2_dopamine-roothide.md).

## Test status

| Version | What has been verified |
|---|---|
| 1.0 | Compiled in Xcode and ran on a stock iPhone18,1 (iOS 27.2.1). That run drove the false-positive fixes in 1.1. |
| 1.1 | Jailbreak-only app ran on the same device and reported **Not jailbroken**. |
| 1.3 | Server tests pass (12). C changes pass `clang -Wall -Wextra -fsyntax-only` against stub headers, including the arm64 paths. Swift changes are not compiled here; CI on GitHub builds them. |
| 1.2 | C core passes `clang -Wall -Wextra -fsyntax-only` (x86_64 and AArch64, stub headers). The reference server's 9 tests and an HTTP smoke test pass. The Swift changes in 1.2 (self-integrity, rules, App Attest opt-in, Kaisel rename) are verified by the CI build on GitHub, not yet on a device. |

**Only one jailbroken device so far** (see Recorded runs). Every other jailbreak, hiding-tweak and Frida expectation in
[`Lab/expected.json`](../Lab/expected.json) is a hypothesis until the [lab checklist](../Lab/LAB_CHECKLIST.md)
has been run. Results are welcome through the *Detection gap or lab result* issue template.
