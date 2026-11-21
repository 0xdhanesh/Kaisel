# Limitations

What Kaisel cannot do, and what has not been proven yet.

## What is still unproven

Be clear about this before relying on the kit:

- **No jailbroken-device testing yet.** The only real-device run so far is a stock iPhone18,1 on iOS 27.2.1. Every jailbreak, hiding-tweak and Frida expectation in `Lab/expected.json` is a hypothesis until the [lab checklist](../Lab/LAB_CHECKLIST.md) has been run.
- **Prologue decoding and stub checks** are heuristics. Apple can change the system stubs between releases.
- **Self-integrity cannot see anything patched before the baseline.** For example, a dylib constructor that hooks before the kit initialises. The static decoder, the server-side `__TEXT` hash comparison and App Attest are the backstops.
- **A determined attacker with code execution can bypass any on-device check.** That includes this kit's tamper evidence. App Attest verified on your server is the only part an attacker cannot forge without a genuine, unmodified app.
- **The reference server is a teaching implementation.** It has single-process JSON storage, no TLS and no authentication. Port the verification steps into your backend.

## Known bypasses and limits

The point of this list is honesty. Every item below has been publicly demonstrated against RASP products.

| Bypass | Effect on this kit | Mitigation |
|---|---|---|
| **Patching the binary** (NOP the call, force the score to 0) | Defeats all client-side logic. | App Attest assertion fails for a modified binary; `cryptid`, team ID and `__TEXT` hash all change. **This is why the server must decide.** |
| **Hooking Swift or C entry points** with Frida, so `evaluate()` returns a forged report | Defeats a local verdict. | The sealed report's App Attest assertion still needs the genuine app's key. A forged payload must be signed in-process, which is possible under Frida. Signals such as threads, hooks and memory in the same run usually expose Frida. Pair this with server-side behavioural fraud signals. |
| **Kernel-level hiding** (vnode filtering, patched `csops`) | Raw-syscall filesystem checks and `csops` lie. | Image list, hooks, threads, entitlements and memory checks still apply. Treat absence of filesystem evidence as weak. |
| **Hiding tweaks that clean up dyld state** (removing images from `infoArray` as well as the API) | Defeats the image-list comparison. | Anonymous executable memory, the prologue and GOT checks, and swizzle checks remain. |
| **Renamed Frida** (strongR-frida, custom builds with renamed threads and strings, random port) | Defeats thread-name, port and marker checks. | Anonymous executable memory, inline hooks on the functions it instruments, exception ports and `CS_DEBUGGED` remain. |
| **Frida in "stalker" or no-trampoline modes** | Fewer inline patches. | Thread and anonymous-memory signals remain. |
| **Hardware-breakpoint or watchpoint debugging** | No `BRK` in code. | `P_TRACED`, `CS_DEBUGGED`, exception ports and ppid remain. |
| **Debugger attached after the check** | A launch-time check misses it. | `IntegrityMonitor`, and evaluating right before each sensitive operation. `CS_DEBUGGED` is sticky. |
| **TrollStore install with crafted entitlements** | Detected through the entitlement blob, unless the attacker picks entitlements that are not on our list. | Extend the list; check `cryptid` and the team ID. |
| **Instrumentation without Frida** (Dobby, custom inline hooks, `DYLD_INSERT` on a jailbroken device) | Partially covered by the generic trampoline, GOT and image allow-list checks. | The allow-list is location based, so unknown names are still caught. |
| **Simulator or emulation (Corellium)** | The simulator is detected. Virtualised iOS can look stock. | App Attest is not available on virtual devices: no assertion, no trust. |
| **False positives** | Crash reporters (exception ports), MDM or enterprise re-signing (profile, team), SDKs that swizzle `UIApplication`, the app suspended in the background (`monitorIntervalStarved`). | Use `allowedExceptionPorts`, the distribution profiles, `weightOverrides` and `suppressedCodes`. |

Prologue decoding is a heuristic. Apple can change the instruction sequences in system stubs between releases, so `syscallStubAltered` has a moderate weight. Validate it on every new major release.

## Per-app hiding (RootHide Blacklist, Choicy, Shadow)

**Tested:** on Dopamine + RootHide (iPhone9,3, iOS 15.8.2), adding the app to RootHide's Blacklist made
both apps report a clean device with zero signals (see the [lab record](../Lab/results/2026-11-21_iphone9-3_ios15.8.2_dopamine-roothide.md)).
The latest 1.3.x runs ([screenshots](../README.md#evidence-dopamine--roothide-iphone93-ios-1582)) show the same:
JB Check *Not jailbroken* and Integrity Check *Trusted 0*. The residual signals below did not fire, and an
earlier *Suspicious* reading on 1.3.1 did not reproduce, so the hidden case is currently a miss.
This is expected for a well-designed hider, and no in-app check can promise to beat it.

Why it works: the hidden app gets **nothing injected** (no hooks to detect), the jailbreak root lives at a
**random path** the sandbox cannot list or guess, there is **no `/var/jb`**, and the package managers'
URL schemes are filtered by the system service that answers `canOpenURL`. The app runs in a near-stock
process on a jailbroken kernel.

What can still be observed from inside a hidden app, and how good each is:

| Residual | Kaisel check | Reliability |
|---|---|---|
| dyld patched or loaded from a non-system path (jailbreaks that hook dyld for every process) | `dyldModified` (110), compares in-memory `__text` with `/usr/lib/dyld` | Indicator only. Meaningful only where dyld runs from the file (iOS 15); skipped when dyld runs from the shared cache (iOS 16+). 1.3.0 wrongly treated it as conclusive and flagged a stock iOS 27 phone. Unverified on RootHide. |
| Userspace reboot after the exploit | `userspaceReboot` (111), `kern.userspacereboottime` | Indicator only. Stock iOS can also restart userspace; the sysctl may be unreadable on some versions. Unverified. |
| The device was seen jailbroken earlier | `previouslyJailbroken` (908), Keychain marker | Indicator. Only works if the app ran unhidden at least once; a user can delete it. Markers whose evidence is no longer conclusive (such as 1.3.0's dyld false positive) are deleted on read. |
| Same hardware key seen jailbroken before | Reference server per-key history | Strong for the "run once, then hide" pattern; resets on erase or if the key is lost. |
| Kernel patches, trust-cache changes, PPL/KTRR bypass state | none | **Not observable** from the app sandbox. |
| Random jailbreak root (`.jbroot-<random>`) | none | **Not guessable**; directory listing is denied by the sandbox. |
| Timing differences (syscall latency, path lookup) | none | Rejected: too noisy across devices and iOS versions to use without many false positives. |
| Processes, mach services, launchd jobs | none | Not visible: process listing and arbitrary `mach-lookup` are denied to apps. |

**Practical guidance:** treat "not jailbroken" as *no evidence*, not as *proof of a stock device*. For
high-value flows, combine the client report with server-side state:
- **App Attest** proves the genuine app on real hardware (not a stock OS).
- **DeviceCheck two bits** let your server mark a device as "seen jailbroken" in a way that survives
  reinstall and app hiding; set it the first time any of your apps reports conclusive evidence.
- **Per-key history** in the reference server does the same per Secure Enclave or App Attest key.
- Behavioural fraud signals on the backend.
