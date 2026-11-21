# Coverage

What Kaisel detects, how each claim is backed, and what has never been tested. Updated for 1.4.0
(unreleased) on 2026-11-21. **Measured** means observed on a real device; everything else is a design
intent or a unit test.

Evidence levels used below:

- **Implemented**: code exists.
- **Unit-tested**: an automated test exercises the logic on synthetic input (C, Swift or server).
- **Device-validated**: observed on a real device, with the evidence named. "Screenshots" means the app
  JSON was not exported, so individual finding codes and confidences beyond what is on screen are unknown.

## Devices and OS versions actually tested

| Device | iOS | Kaisel | Scenario | Evidence | Result |
|---|---|---|---|---|---|
| iPhone9,3 (iPhone 7) | 15.8.2 | 1.2.0 | Dopamine + RootHide, not hidden | Screenshots (transcribed in [the lab record](results/2026-11-21_iphone9-3_ios15.8.2_dopamine-roothide.md)) | JB Check PASS; full app inconsistent (fixed in 1.3.0) |
| iPhone9,3 | 15.8.2 | 1.2.0 | Dopamine + RootHide, hidden | Screenshots | FAIL: both apps clean |
| iPhone9,3 | 15.8.2 | 1.3.x | Dopamine + RootHide, not hidden | [Screenshots](../docs/images/lab/) | PASS: Jailbroken; device Compromised 85, runtime Compromised 97 |
| iPhone9,3 | 15.8.2 | 1.3.x | Dopamine + RootHide, hidden | [Screenshots](../docs/images/lab/) | FAIL: Not jailbroken, Trusted 0 (known gap) |
| iPhone9,3 | 15.8.2 | 1.3.1 | Dopamine + RootHide, hidden | Owner's report only | Suspicious; not exported and not reproduced, so unconfirmed |
| iPhone18,1 | 27.2.1 | 1.0 / 1.3.0 | Stock | Screenshots | False positives, fixed in 1.1 and 1.3.1 |
| iPhone18,1 | 27.2.1 | 1.3.x | Stock | [Screenshots](../docs/images/lab/) | PASS: Not jailbroken, Trusted 0 |
| Not recorded | 26 | 1.3.1 | Stock | Owner's report only | PASS: clean |
| Not recorded | Not recorded | 1.3.1 | TrollStore (TrollInstallerX) | Owner's report only | PASS: detected by both apps |

**Kaisel 1.4.0 has not been run on any device.** Its classification changes are unit-tested only.
No result JSON has been exported for any run, so `compare_results.py` has nothing to check yet.

## Assessment categories

| Category | Main codes | Implemented | Unit-tested | Device-validated |
|---|---|---|---|---|
| Rootless jailbreak artefacts (`/var/jb`) | 105, 100, 101 | Yes | Scoring only | No (RootHide removes `/var/jb`) |
| Rootful artefacts, sealed volume | 102, 103, 104 | Yes | Scoring only | No |
| Sandbox integrity | 120, 121, 122 | Yes | Scoring only | No |
| Hiding hooks (libc vs kernel) | 108 | Yes | Scoring only | No |
| Known jailbreak injector image | 200 | Yes (1.4.0 identity rules) | Yes: C, Swift, server, 34 shared fixtures | Yes: `roothideinit.dylib`, iPhone9,3 / 15.8.2 (1.2 and 1.3.x, screenshots) |
| Instrumentation image (Frida, Cycript, in-bundle injector) | 205 | Yes (new in 1.4.0) | Yes | No |
| Broad marker / unknown external image | 206, 201 | Yes | Yes | No |
| Image-list filtering | 202 | Yes | Scoring only | No |
| Late-loaded images | 203 | Yes | Classification only | No |
| Inline hooks, rebinding, swizzling | 300-306 | Yes | Scoring only | Partly: 304 seen with RootHide unhidden (1.2) |
| Debugger | 400-403 | Yes | Scoring only | Xcode debug run on iPhone18,1 (1.0) |
| Frida runtime (threads, D-Bus, memory) | 500-504 | Yes | Scoring only | No |
| Code signing, entitlements (TrollStore) | 600-610 | Yes | Scoring only | TrollStore detected (owner's report, 1.3.1) |
| Package-manager URL schemes | 905 | Yes | Scoring only | Yes: `sileo://` with RootHide unhidden |
| Residual signals for hidden jailbreaks | 110, 111, 908 | Yes | Yes | **Did not fire** in the 1.3.x hidden run |
| Server per-key history | server | Yes (App Attest key only since 1.4.0) | Yes | No |
| Server strict report validation | server | Yes (new in 1.4.0) | Yes (32 tests) | No |

## Detected and missed conditions (measured)

| Condition | Outcome |
|---|---|
| RootHide injector in a non-hidden app | Detected (conclusive) |
| RootHide per-app hiding (Blacklist) | **Missed**, both apps, two builds |
| Package-manager URL scheme with RootHide unhidden | Detected (indicator) |
| Stock iPhone18,1 / iOS 27.2.1 | No false positive since 1.3.1 |
| Stock iOS 26 device | No false positive (owner's report) |

## False-positive regressions

| Release | Device | Cause | Status |
|---|---|---|---|
| 1.0 | iPhone18,1 / 27.2.1 | Build-context signals, Developer Mode, `apple-magnifier`, anonymous r-x region | Fixed in 1.1 (scored as informational) |
| 1.3.0 | iPhone18,1 / 27.2.1 | `dyldModified` compared shared-cache dyld with `/usr/lib/dyld` | Fixed in 1.3.1 (indicator only, skipped in cache) |
| up to 1.3.1 | None observed | Broad image markers (`crane`, `liberty`, `choicy`, ...) matched anywhere in a path and were conclusive | Fixed in 1.4.0 by code review; covered by fixtures, never observed on a device |

## Unknown coverage

Not tested on any device: palera1n (rootless and rootful), Dopamine without RootHide, Dopamine on A12+,
any Shadow-class hiding tweak, frida-server attach or spawn, FridaGadget repackaging, renamed
instrumentation, late attach, iOS 16, 17, 18, 19 to 25, any iPad, the App Attest variant on a device,
and the reference server against a real App Attest enrolment.

## Open research gaps

- Per-app hiding (RootHide Blacklist): no in-process signal survived in measured runs. Candidates
  (mount-table enumeration, DeviceCheck bits) are listed in the README roadmap and are unproven.
- In-bundle code is classified by identity only. A re-signed app with a renamed injected library inside
  its bundle is not detected by image classification; a build manifest of expected bundle contents is
  needed (roadmap).
- Completion bits are self-reported. App Attest proves which app instance signed a report, not that the
  measurements inside a compromised process are true.
