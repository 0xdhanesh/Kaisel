#!/usr/bin/env python3
"""
Generates Sources/CIntegrityCore/rasp_strings_table.h

Every indicator string (paths, image names, thread names, env vars, URL schemes,
entitlement keys) is stored XOR-encoded with a per-string rolling key so the
compiled binary carries no plaintext indicator list for `strings`/`grep` or a
bypass tweak to harvest. Strings are decoded onto the stack only for the duration
of a single check and wiped afterwards.

This is obfuscation, not encryption: it raises the cost of static analysis and of
generic "hide these paths" tweaks, it does not stop a determined reverser.

Re-run after editing the lists:  python3 Scripts/gen_strings.py
"""
import os
import random

# ---------------------------------------------------------------------------
# Indicator lists. Keep generic and public: these are all well-known artefacts.
# ---------------------------------------------------------------------------
LISTS = {
    # Files and directories created by jailbreaks, package managers and tools.
    # Covers rootful (unc0ver, checkra1n, palera1n rootful, Taurine) and
    # rootless (Dopamine, palera1n rootless, XinaA15) layouts.
    "JB_PATHS": [
        "/Applications/Cydia.app",
        "/Applications/Sileo.app",
        "/Applications/Zebra.app",
        "/Applications/Filza.app",
        "/Library/MobileSubstrate/MobileSubstrate.dylib",
        "/Library/MobileSubstrate/DynamicLibraries",
        "/usr/lib/libsubstrate.dylib",
        "/usr/lib/substrate",
        "/usr/lib/TweakInject",
        "/usr/lib/libhooker.dylib",
        "/usr/lib/libsubstitute.dylib",
        "/usr/lib/ellekit",
        "/usr/libexec/cydia",
        "/usr/libexec/sftp-server",
        "/usr/sbin/sshd",
        "/usr/bin/ssh",
        "/usr/bin/apt",
        "/bin/bash",
        "/bin/sh",
        "/etc/apt",
        "/etc/ssh/sshd_config",
        "/var/lib/apt",
        "/var/lib/cydia",
        "/var/cache/apt",
        "/var/log/apt",
        "/private/var/lib/dpkg",
        "/.bootstrapped",
        "/.installed_unc0ver",
        "/.installed_dopamine",
        "/.procursus_strapped",
        "/.mount_rw",
        "/var/checkra1n.dmg",
        "/cores/binpack",
        "/cores/jbloader",
        "/var/binpack",
        "/var/jb",
        "/var/jb/basebin",
        "/var/jb/.installed_dopamine",
        "/var/jb/.procursus_strapped",
        "/var/jb/usr/bin/su",
        "/var/jb/usr/lib/TweakInject",
        "/var/jb/usr/lib/ellekit",
        "/var/jb/Library/MobileSubstrate",
        "/var/jb/Applications/Sileo.app",
        "/var/jb/Applications/Zebra.app",
        "/var/containers/Bundle/tweaksupport",
        "/private/preboot/jb",
        "/var/mobile/Library/palera1n",
        "/usr/share/jailbreak/injectme.plist",
    ],
    # Top-level system directories that rootful jailbreaks historically
    # relocated and replaced with symlinks (stashing).
    "SYMLINK_DIRS": [
        "/Applications",
        "/Library/Ringtones",
        "/Library/Wallpaper",
        "/usr/arm-apple-darwin9",
        "/usr/include",
        "/usr/libexec",
        "/usr/share",
    ],
    # Substrings matched (case-insensitive) against loaded image paths.
    "IMAGE_MARKERS": [
        "frida",
        "fridagadget",
        "gum-js",
        "cynject",
        "libcycript",
        "mobilesubstrate",
        "substrateloader",
        "substrateinserter",
        "substratebootstrap",
        "libsubstitute",
        "substitute-inserter",
        "libhooker",
        "tweakinject",
        "ellekit",
        "systemhook.dylib",
        "rootlesshooks",
        "libinjector",
        "libsandy",
        "shadow.dylib",
        "abypass",
        "flyjb",
        "liberty",
        "sslkillswitch",
        "choicy",
        "crane",
        "/var/jb/",
        "/.jbroot-",
        "roothide",
    ],
    # Thread names used by Frida's runtime (gum / GLib main loop / D-Bus).
    "FRIDA_THREADS": [
        "gum-js-loop",
        "gmain",
        "gdbus",
        "pool-frida",
        "frida",
        "pool-spawner",
        "linjector",
    ],
    # Byte markers searched in anonymous executable/readable regions.
    "FRIDA_MEM_MARKERS": [
        "frida_agent_main",
        "LIBFRIDA",
        "GumScript",
        "frida:rpc",
    ],
    # Environment variables.
    "ENV_INJECTION": [
        "DYLD_INSERT_LIBRARIES",
        "DYLD_LIBRARY_PATH",
        "DYLD_FRAMEWORK_PATH",
        "DYLD_FALLBACK_LIBRARY_PATH",
        "DYLD_IMAGE_SUFFIX",
    ],
    "ENV_JB": [
        "_MSSafeMode",
        "_SafeMode",
        "_SubstituteSafeMode",
        "JB_ROOT_PATH",
        "JB_SANDBOX_EXTENSIONS",
        "JB_BOOTSTRAP_PATH",
        "JBROOT",
    ],
    # Entitlements an App Store / enterprise app should never carry.
    # Their presence typically means sideloading via TrollStore or a re-sign
    # on a jailbroken device.
    "SUSPICIOUS_ENTITLEMENTS": [
        "com.apple.private.security.no-sandbox",
        "com.apple.private.security.container-required",
        "platform-application",
        "com.apple.private.skip-library-validation",
        "task_for_pid-allow",
        "com.apple.private.persona-mgmt",
        "com.apple.private.security.storage.AppDataContainers",
        "run-unsigned-code",
        "dynamic-codesigning",
        "com.apple.private.kernel.jetsam",
    ],
    # URL schemes registered by jailbreak package managers and tools.
    # The host app must list these under LSApplicationQueriesSchemes.
    # Audit rule: never list a scheme any stock Apple app can register.
    # "apple-magnifier" (used by TrollStore) was removed because the stock
    # Magnifier app owns it on current iOS, which caused a false positive.
    "URL_SCHEMES": [
        "cydia",
        "sileo",
        "zbra",
        "filza",
        "undecimus",
        "activator",
    ],
    # Developer disk image mount points (iOS <=16 and iOS 17+ personalised DDI).
    "DDI_PATHS": [
        "/Developer/usr/bin/debugserver",
        "/System/Developer/usr/bin/debugserver",
    ],
    # Misc single strings used by the C core.
    "MISC": [
        "security.mac.amfi.developer_mode_status",  # 0
        "com.apple.os.update-",                      # 1  sealed root snapshot prefix
        "/private/var/containers/Bundle/Application/",  # 2
        "/var/containers/Bundle/Application/",       # 3
        "libsystem_kernel.dylib",                    # 4
        "libsystem_c.dylib",                         # 5
        "libdyld.dylib",                             # 6
        "/usr/lib/system/",                          # 7
        "/System/",                                  # 8
        "/usr/lib/",                                 # 9
        "/private/preboot/Cryptexes/",               # 10
        "/Developer/",                               # 11
        "/System/Developer/",                        # 12
        "\0AUTH\r\n",                                # 13 D-Bus auth probe (length-prefixed)
        "REJECTED",                                  # 14 D-Bus reply
        "/private/",                                 # 15 sandbox write probe root
        "Foundation",                                # 16
        "UIKitCore",                                 # 17
        "libobjc.A.dylib",                           # 18
        "fork",                                      # 19
        "ptrace",                                    # 20
        "libdyld",                                   # 21 (dyld4 lives in /usr/lib/dyld)
        "/usr/lib/dyld",                             # 22
        "/private/var/mobile/Library/Preferences/",  # 23 sandbox read probe dir
        "/var/jb",                                   # 24 rootless jailbreak root symlink
    ],
    # Exported libc / libsystem functions whose prologue and binding we verify.
    # Prefixed "S:" means the function is a raw syscall stub that must contain
    # `svc #0x80` within its first instructions.
    "HOOK_TARGETS": [
        "S:stat",
        "S:lstat",
        "S:access",
        "S:csops",
        "S:getppid",
        "S:__sysctl",
        "S:readlink",
        "open",
        "fopen",
        "opendir",
        "getenv",
        "sysctl",
        "sysctlbyname",
        "ptrace",
        "fork",
        "dlopen",
        "dlsym",
        "dladdr",
        "_dyld_image_count",
        "_dyld_get_image_name",
        "_dyld_get_image_header",
        "task_info",
        "task_threads",
        "objc_msgSend",
        "NSClassFromString",
        "SecItemCopyMatching",
    ],
}

HEADER = """// GENERATED by Scripts/gen_strings.py - do not edit by hand.
#ifndef RASP_STRINGS_TABLE_H
#define RASP_STRINGS_TABLE_H
#include <stdint.h>

typedef struct { uint32_t offset; uint16_t length; uint8_t key; uint8_t step; } rasp_obf_entry_t;
"""


def encode(s: bytes, key: int, step: int) -> bytes:
    out = bytearray()
    k = key
    for b in s:
        out.append(b ^ k)
        k = (k + step) & 0xFF
    return bytes(out)


def main():
    seed = os.environ.get("RASP_SEED")
    rng = random.Random(int(seed) if seed else None)
    blob = bytearray()
    entries = []
    list_ranges = {}
    for name, items in LISTS.items():
        start = len(entries)
        for item in items:
            raw = item.encode("utf-8")
            key = rng.randrange(1, 256)
            step = rng.randrange(1, 256) | 1
            enc = encode(raw, key, step)
            entries.append((len(blob), len(raw), key, step))
            blob += enc
            # random padding so string boundaries are not obvious
            blob += bytes(rng.randrange(0, 256) for _ in range(rng.randrange(1, 5)))
        list_ranges[name] = (start, len(items))

    lines = [HEADER]
    for name, (start, count) in list_ranges.items():
        lines.append(f"#define RASP_LIST_{name}_START {start}")
        lines.append(f"#define RASP_LIST_{name}_COUNT {count}")
    lines.append(f"#define RASP_OBF_ENTRY_COUNT {len(entries)}")
    lines.append("")
    lines.append("static const uint8_t rasp_obf_blob[] = {")
    for i in range(0, len(blob), 16):
        lines.append("    " + ", ".join(f"0x{b:02x}" for b in blob[i:i + 16]) + ",")
    lines.append("};")
    lines.append("")
    lines.append("static const rasp_obf_entry_t rasp_obf_table[] = {")
    for off, ln, key, step in entries:
        lines.append(f"    {{{off}u, {ln}u, 0x{key:02x}u, 0x{step:02x}u}},")
    lines.append("};")
    lines.append("")
    lines.append("#endif")

    here = os.path.dirname(os.path.abspath(__file__))
    out = os.path.join(here, "..", "Sources", "CIntegrityCore", "rasp_strings_table.h")
    with open(out, "w") as f:
        f.write("\n".join(lines) + "\n")

    # Swift mirror of list ranges, so the Swift layer can decode URL schemes.
    swift_out = os.path.join(here, "..", "Sources", "KaiselKit", "ObfuscatedLists.swift")
    with open(swift_out, "w") as f:
        f.write("// GENERATED by Scripts/gen_strings.py - do not edit by hand.\n")
        f.write("enum ObfuscatedList {\n")
        for name, (start, count) in list_ranges.items():
            ident = "".join(p.capitalize() for p in name.lower().split("_"))
            ident = ident[0].lower() + ident[1:]
            f.write(f"    static let {ident}: Range<UInt16> = {start}..<{start + count}\n")
        f.write("}\n")
    print(f"wrote {len(entries)} strings, {len(blob)} bytes")


if __name__ == "__main__":
    main()
