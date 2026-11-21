# Detection

How Kaisel decides whether a device is jailbroken or a process is instrumented, and how the evidence is scored.

## How a jailbreak is decided

A stock iPhone has a few hard guarantees. The system volume is a sealed, read-only snapshot. Every app runs in a sandbox that cannot write outside its container or call `fork()`. Only Apple-signed system libraries and the app's own frameworks are loaded into the app. A jailbreak has to break at least one of these guarantees to do anything useful, and `JailbreakDetector` tests each one directly.

**Jailbroken** means at least one conclusive finding, that is, something a stock, sealed iOS cannot produce:

- **Jailbreak files visible to the kernel.** The rootless jailbreak root `/var/jb` (Dopamine, palera1n), or bootstrap and package-manager files. These are looked up with raw kernel syscalls, so tweaks that hook libc to hide files do not affect the result.
- **The root volume has been altered.** It is writable or remounted, or system directories have been replaced with symlinks (rootful jailbreaks).
- **The app sandbox is broken.** The app can write outside its container, or `fork()` succeeds.
- **Tweak-injection libraries are loaded into the app.** Substrate, ElleKit, TweakInject, Dopamine's `systemhook` and similar.
- **Jailbreak-only environment variables or entitlements.** For example `JB_ROOT_PATH`, or `no-sandbox`/`platform-application`, which only a TrollStore or jailbreak install can grant.
- **A hiding tweak is caught lying.** libc says a file does not exist while the kernel says it does, or dyld's internal image list has more entries than the public dyld API reports.

**Suspicious** means only indirect evidence: package-manager URL schemes (Cydia, Sileo, Zebra, Filza), a path whose existence is inferred from `EPERM`, a library loaded from an unexpected location, hooks on file APIs, or a check that did not complete.

**Not jailbroken** means none of the above.

Build and signing facts (Xcode or ad hoc install, `get-task-allow`, provisioning profile, FairPlay encryption) and Developer Mode are **not** jailbreak evidence, and Kaisel JB Check ignores them.

## Detection techniques

None of the checks is a plain path lookup. Each one either uses a primitive that the usual hooks do not reach, or cross-checks two views of the same fact so that **a hook betrays itself**.

### Filesystem and jailbreak artefacts (`rasp_fs.c`)

| Technique | Detail |
|---|---|
| Raw syscalls | `stat64`, `lstat64`, `access`, `open`, `readlink` and `statfs64` are issued with inline `svc #0x80` (x16 = syscall number, carry flag = error). The helper is `always_inline`, so every check has its own trap instruction and there is no single wrapper to hook. fishhook, Substrate, ElleKit and Frida `Interceptor` hooks on libc never see these calls. |
| libc and kernel disagreement | Every artefact path is also looked up through libc. Kernel says "exists" and libc says `ENOENT` gives `libcSyscallMismatch`, a hard indicator of a hiding tweak (Shadow, A-Bypass, Liberty-style libc hooks). The reverse (libc reports a path the kernel denies) is reported as well. |
| Errno existence oracle | `EPERM`/`EACCES` from a sandboxed lookup means the path exists. To avoid false positives from opaque directories, the parent is first calibrated with a random, non-existent sibling: the result is only trusted when the sibling gives `ENOENT`. |
| Rootless root | `readlink("/var/jb")` resolving into `/private/preboot/<hash>/…` (Dopamine, palera1n rootless). |
| Signed System Volume | Since iOS 15 `/` is a sealed, read-only APFS snapshot (`com.apple.os.update-…`). If `/` is not read-only (`MNT_RDONLY` clear), or is not mounted from the sealed snapshot, that points to a rootful jailbreak or fakefs. |
| Stashing | System directories such as `/Applications` and `/usr/share` that have been replaced with symlinks (legacy rootful). |
| Obfuscated indicators | About 180 indicator strings are XOR-encoded with a key per string (`Scripts/gen_strings.py`). They are decoded to the stack for one comparison and then wiped, so `strings` on the binary shows none of them (verified). |

### Sandbox integrity (`rasp_fs.c`)

- An `O_CREAT|O_EXCL` write to `/private/.<random>` through a raw `open`. It always fails inside a stock sandbox.
- An `open(O_DIRECTORY)` on another domain's preferences directory.
- A `fork()` probe, resolved through `dlsym` so the binary has no `fork` import. The child exits through a raw `exit` syscall. The App Sandbox denies `fork`.

### Control probes (canaries)

- A positive control: the app's own executable must be visible through both the raw syscall and libc.
- A negative control: a random path in the container's tmp directory must give `ENOENT` through both.

A blanket hook that makes everything look absent, or everything look present, fails these probes and raises `canaryFailed` instead of quietly producing a "clean" result.

### Injection and loaded images (`rasp_images.c`)

| Technique | Detail |
|---|---|
| Two independent image lists | List A comes from `_dyld_image_count`/`_dyld_get_image_name`, which hiding tweaks hook. List B is dyld's own `dyld_all_image_infos->infoArray`, found through `task_info(TASK_DYLD_INFO)` and read directly from memory. If B has more entries than A, the dyld API is being filtered (`imageListMismatch`, hard). |
| Allow-list by location | Every image must come from `/System/`, `/usr/lib/`, `/private/preboot/Cryptexes/`, the Developer image paths or the app's own bundle. Any other location is unexpected, whatever its name. |
| Deny-list by name | A case-insensitive match on obfuscated markers: Frida, Gadget, Substrate, Substitute, libhooker, ElleKit, TweakInject, systemhook (Dopamine), rootlesshooks, Shadow, A-Bypass, FlyJB, SSL Kill Switch, Choicy, `/var/jb/` and others. |
| `__interpose` sections | A non-system image with `__DATA,__interpose` or `__DATA_CONST,__interpose` is a DYLD-interposing hook library. |
| Runtime monitor | A `_dyld_register_func_for_add_image` callback records every image loaded after start-up (for example a late `dlopen` of an agent). The ring buffer is drained on each evaluation. |

### Hook integrity (`rasp_hooks.c`)

For about 26 sensitive functions (`stat`, `lstat`, `access`, `csops`, `__sysctl`, `open`, `fopen`, `getenv`, `sysctl*`, `ptrace`, `fork`, `dlopen`, `dlsym`, `dladdr`, `_dyld_*`, `task_info`, `task_threads`, `objc_msgSend`, `SecItemCopyMatching` and others):

| Check | What it decodes |
|---|---|
| Inline trampolines | `LDR Xt, #lit ; BR Xt` (Substrate, Frida, ElleKit, Dobby), `ADRP Xd ; … ; BR Xd`, and the `BRAAZ`/`BRABZ` variants. |
| Far branch | A `B imm26` at entry is followed, and if the target lies outside the function's own image (or in anonymous memory) it is reported. A legitimate tail branch inside the same image is not. |
| Software breakpoints | `BRK #imm` at entry. |
| Syscall stub integrity | For raw stubs (`stat`, `lstat`, `access`, `csops`, `getppid`, `__sysctl`, `readlink`), `svc #0x80` must appear in the first eight instructions. |
| GOT rebinding (fishhook, interposing) | A function's address taken through our own GOT (`&stat`) is compared with `dlsym(RTLD_DEFAULT, "stat")`, and the resolved image must be a system image. |
| Objective-C swizzling | The IMP of `-[NSFileManager fileExistsAtPath:]`, `-[UIApplication canOpenURL:]`, `-[NSProcessInfo environment]`, `-[NSBundle bundleIdentifier]` and others must live in Foundation or UIKitCore, and its prologue must be clean. Frida's `ObjC.implementation` and `MSHookMessageEx` both move it. |
| Self-integrity | The RASP's own C entry points are checked for trampolines. If a check is hooked to return early, its "started" bit is never set (see [Tamper resistance](#tamper-resistance)). |

PAC is stripped with `ptrauth_strip` before decoding, where it applies.

### Debugger (`rasp_debug.c`)

| Check | Detail |
|---|---|
| `P_TRACED` | `KERN_PROC_PID` read through a **raw** `__sysctl` (the libc `sysctl` is a common hook target). |
| `CS_DEBUGGED` | `csops(CS_OPS_STATUS)` through a raw syscall. The kernel sets the flag once a debugger has attached, and it stays set for the life of the process, so it survives a detach. |
| Exception ports | `task_get_exception_ports` for breakpoint, bad access, bad instruction, software and arithmetic exceptions. LLDB and Frida register these. A crash reporter may too, so the expected count is configurable. |
| Parent process | A raw `getppid() != 1`: the app was spawned by debugserver or `frida -f` rather than by launchd. |
| Optional countermeasure | `IntegrityKit.denyDebuggerAttach()` calls `PT_DENY_ATTACH` through a raw syscall. It is compiled out in `DEBUG` builds. |

### Frida and instrumentation (`rasp_frida.c`)

| Check | Detail |
|---|---|
| Thread names | `task_threads` plus `thread_info(THREAD_EXTENDED_INFO)` looking for `gum-js-loop`, `gmain`, `gdbus`, `pool-frida` and similar. Short generic names must match exactly. This catches FridaGadget on non-jailbroken devices too. |
| D-Bus handshake | A loopback TCP connect to the configured ports (27042 and 27043 by default), then a D-Bus SASL `\0AUTH\r\n`. Frida answers `REJECTED`, an unrelated service does not. An open port alone is a weak signal; the handshake is a hard one. |
| Anonymous executable memory | Walks the top-level VM map with `vm_region_recurse_64`, without descending into the shared-cache submap (which avoids stub-island false positives). An executable region that belongs to no dyld image and has no backing file (`proc_regionfilename`) is flagged. Frida maps its agent with its own Mach-O loader and allocates r-x trampoline pages for `Interceptor`. File-backed remaps such as `libobjc-trampolines` are ignored. |
| Memory markers | Flagged regions (16 MiB at most) are scanned for agent markers such as `frida_agent_main`, `GumScript` and `frida:rpc`. |

### Code signing and binary integrity (`rasp_codesign.c`, `AppIntegrityChecks.swift`)

| Check | Detail |
|---|---|
| `CS_VALID` | Cleared means the code signature has been invalidated at runtime. |
| `CS_GET_TASK_ALLOW` | Set in a non-development build means a re-signed or development-signed binary. |
| Entitlements blob | `csops(CS_OPS_ENTITLEMENTS_BLOB)`, falling back to the DER blob on newer kernels. It is searched for entitlements no App Store app can hold: `no-sandbox`, `platform-application`, `skip-library-validation`, `task_for_pid-allow`, `persona-mgmt` and others. This is the TrollStore and "ldid on a jailbroken device" fingerprint. |
| FairPlay `cryptid` | App Store and TestFlight binaries have `cryptid=1`. A dumped and re-signed IPA has `cryptid=0`. |
| `embedded.mobileprovision` | Must not be present in an App Store build. The profile's `TeamIdentifier` is compared with `expectedTeamIdentifier`, and `ProvisionsAllDevices` is flagged outside enterprise builds. |
| `__TEXT,__text` SHA-256 | Computed from the mapped (decrypted) pages for comparison with a build-time value, preferably on the server. |
| Bundle location and ID | The app must run from `/private/var/containers/Bundle/Application/`, and the bundle ID must match. |
| URL schemes | Jailbreak package managers and tools (Cydia, Sileo, Zebra, Filza, unc0ver, Activator). This needs `LSApplicationQueriesSchemes` in the host app. **Audit rule:** a scheme is listed only if no stock Apple app can register it. TrollStore's `apple-magnifier` was removed after a false positive on a stock iOS 27 device, because the built-in Magnifier app owns that scheme. |

### Environment (`rasp_env.c`)

The environment block is read directly through `_NSGetEnviron()` and checked for `DYLD_INSERT_LIBRARIES` and other `DYLD_*` variables, and for jailbreak variables (`_MSSafeMode`, `_SafeMode`, `JB_ROOT_PATH`, `JB_SANDBOX_EXTENSIONS` and others). Each hit is then cross-checked with `getenv()`. A variable that is present in the block but hidden from `getenv` is a hard tamper indicator.

### Developer Mode (`rasp_debug.c`, `AppIntegrityChecks.swift`)

There is **no public API** for Developer Mode. The kit uses three proxies and reports each one separately:

1. The sysctl `security.mac.amfi.developer_mode_status`, resolved by name and read through a raw `__sysctl`. If it is unreadable it gives `-1` (unknown), not `0`.
2. Inference: on iOS 16 and later a `get-task-allow` app only launches when Developer Mode is on. If we are running with `CS_GET_TASK_ALLOW`, Developer Mode is on.
3. A mounted Developer Disk Image: `debugserver` under `/Developer` (iOS 16 and earlier) or `/System/Developer` (iOS 17 and later, personalised DDI).

Developer Mode is reported in `posture` and as informational signals. It never affects a score or verdict.

### dyld integrity (`rasp_images.c`)

dyld is not part of the shared cache and its `__TEXT` is never rebased, so its code in memory must match
`/usr/lib/dyld` on disk. The check finds dyld through `dyld_all_image_infos`, confirms the file has the
same `LC_UUID`, then compares `__TEXT,__text` byte for byte using raw `open`/`pread`. It also checks the
path dyld was loaded from (`dyldPath`, Apple-signed cryptex and `/System` locations allowed). Differences
that are only `brk` instructions (at most 8) are reported as a debugger breakpoint, because lldb sets
breakpoints inside dyld. Any other difference is `dyldModified` (conclusive), because a jailbreak that hooks
dyld affects every process, including ones hidden by a per-app hider.

### Userspace reboot (`rasp_fs.c`)

Dopamine restarts userspace after the kernel exploit. `kern.userspacereboottime` is then non-zero while
the kernel keeps its original boot time. Reported as the indicator `userspaceReboot` because stock iOS can
restart userspace too.

### Jailbreak memory (`JailbreakMemory.swift`)

When conclusive evidence is seen, a Keychain item records the first sighting. A later clean run reports
`previouslyJailbroken` as an indicator. Keychain items survive app deletion and per-app hiding, but not an
erase. The server-side per-key history is the tamper-resistant version.

### One jailbreak rule for both apps

`JailbreakEvidence` decides what is conclusive. `JailbreakDetector` uses it for the JB Check status, and
`IntegrityKit` uses it to set the **device** verdict to `compromised` when conclusive evidence appears in
any domain. A tweak injector such as `roothideinit.dylib` is scored in the runtime domain but proves the
device is jailbroken, so both apps now agree.

### Syscall stub check: reliability

`syscallStubAltered` (304) fires when a raw syscall wrapper (`csops`, `ptrace`, `stat` and others) has no
`svc #0x80` in its first 8 instructions. On a stock iOS 15 to 27 system these functions are direct stubs,
so a missing trap means someone rewrote the entry. In the RootHide lab run it fired only while tweaks were
injected and disappeared when the app was hidden, which is consistent with a real hook. It stays an
**indicator** (weight 0.70, confidence lowered to 60 in 1.3.0) and is not conclusive, because Apple can turn
a stub into a wrapper in a future release. Since 1.3.0 the check follows a same-image branch at the entry
before deciding, and records the first four instruction words in the detail so lab runs can be diagnosed.

## Risk scoring

Every signal belongs to one **domain**, and each domain gets its own score and verdict:

| Domain | Question | Examples | Scored? |
|---|---|---|---|
| `device` | Is the phone jailbroken, or its OS tampered with? | `/var/jb`, root volume writable, sandbox broken, jailbreak environment variables or entitlements, libc hiding | Always |
| `runtime` | Is this process being hooked, injected, instrumented or debugged? | Frida threads or D-Bus, inline hooks, injected libraries, `P_TRACED` | Always (debugger codes are informational when `debuggerExpected`) |
| `app` | Does this binary match the distribution you expect? | `cryptid=0`, provisioning profile, `get-task-allow`, team ID | Only when `expectedDistribution` is set; otherwise **informational** |
| `posture` | How is the phone configured? | Developer Mode, Developer Disk Image | **Never** (informational) |

`report.verdict` is the worst of the enforced domains. Within each domain:

```
effective weight  w = base_weight(code) × confidence / 100       (0 if informational)
per category      p_cat = 1 − Π_i (1 − w_i · 0.5^i)              (sorted by w, descending)
domain            p     = 1 − Π_cat (1 − p_cat),   score = round(100 · p)
```

- **Damping inside a category.** Forty jailbreak paths count as one strong piece of evidence, not forty.
- **Hard indicators.** One hard indicator at 75% confidence or more floors the verdict at `high`. Hard indicators in two categories make it `compromised`.
- **Corroboration.** Anonymous executable memory on its own is informational. It is scored only when Frida, hook or injection evidence appears in the same report (see the iOS 27 note under [Lab validation plan](LAB.md#lab-validation-plan)).
- **Verdicts.** `trusted` (below 15), `low` (below 35), `elevated` (below 60), `high` (below 85), `compromised` (85 or more).
- **Overrides.** `weightOverrides` and `suppressedCodes`.

## Tamper resistance

| Mechanism | Purpose |
|---|---|
| No boolean | There is no `isJailbroken()` to hook and force to `false`. The report is a list of signals plus a score. |
| Started and completed bitmask | Each C check sets a "started" bit on entry and a "completed" bit on exit. A check that was never entered (hooked or replaced) or that never finished raises `checkSuppressed` (hard). |
| Randomised order | Checks run in a shuffled order on each evaluation, so "patch the third call" does not work across runs. |
| Inlined syscalls | There is no shared syscall wrapper to hook. Each check has its own trap. |
| Self-prologue check | Trampolines on the RASP's own entry points are detected. |
| Obfuscated strings | There is no plaintext indicator list to harvest, and generic "hide these paths" lists do not line up with ours. |
| Control probes | Blanket hooks are detected instead of producing a clean result. |
| Sealing | `seal(_:serverNonce:)` hashes the canonical report JSON together with a server nonce. It then signs that hash with an **App Attest assertion** (which proves a genuine, unmodified app instance) and a **Secure Enclave P-256 key** (which proves device-key continuity). A modified report, a replayed report or a report from a re-signed app fails on the server. |
| Monitor | Jittered re-evaluation with `IntegrityMonitor`. A very long gap between runs is reported (`monitorIntervalStarved`). |

## iOS 15 to 27: what can be observed

| | 15.x | 16.x | 17.x | 18.x | 26 | 27 |
|---|---|---|---|---|---|---|
| Public jailbreaks (at time of writing) | Rootful: checkra1n/palera1n (A8–A11). Rootless: Dopamine (A12+), palera1n, XinaA15 | Dopamine up to 16.6.1 (A12+); palera1n (A8–A11) | palera1n on checkm8 devices that get 17; no public A12+ kernel jailbreak | checkm8-class iPads only | None known | None known |
| TrollStore | Yes (14.0–16.6.1, 16.7 RC, 17.0) | Up to 16.6.1 / 16.7 RC | 17.0 only | No | No | No |
| Developer Mode | Does not exist | Exists; sysctl readable (best effort); inference via get-task-allow | Same, and personalised DDI under `/System/Developer` | Same | Same | **Tested:** sysctl readable (`developer_mode_status=1` read on iPhone18,1) |
| Sealed root snapshot check | Applies | Applies | Applies | Applies | Applies | **Tested:** no false positive |
| Raw `svc` syscalls and libc cross-check | Work | Work | Work | Work | Validate on device | **Tested:** no false positive |
| `dyld_all_image_infos` and hook checks | dyld4 layout | Same | Same | Same | Validate on device | **Tested:** no false positive |
| Anonymous executable memory | Applies | Applies | Applies | Applies | Validate on device | One unexplained 48 KiB r-x region seen on a stock device, so this signal now needs corroboration |
| `apple-magnifier` URL scheme | Owned by the stock Magnifier app: removed from the probe list | | | | | |
| Realistic threat on non-jailbroken devices | Repackaged IPA + FridaGadget, Developer Mode debugging, enterprise and ad hoc re-signing | Same | Same | Same | Same | Same |

What a sandboxed app **cannot** observe on any version:

- Kernel patches. A kernel-level hider (for example a rootless jailbreak that filters vnode lookups for selected apps) defeats the raw-syscall checks, because the kernel itself lies. Only artefacts outside the filesystem (images, threads, hooks, entitlements, memory) and server-side attestation remain.
- Whether the bootloader or SEP has been exploited (checkm8) with no userland traces.
- Developer Mode with certainty. It is best effort on every version.
- Other processes. The app cannot list processes, so a frida-server on a non-default port with a clean injection is only visible through in-process artefacts.

`PlatformCapabilities.notes` is embedded in every report, so the server knows which absences of evidence mean something.
