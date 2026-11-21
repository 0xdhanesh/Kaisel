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
