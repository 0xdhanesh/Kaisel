// KaiselKit - low-level C core.
//
// All checks write `rasp_finding_t` records into a caller-owned buffer and set a
// bit in `checks_completed`. The Swift layer owns weighting and scoring; the C
// layer only reports evidence. Finding codes are mirrored in Finding.swift.

#ifndef RASP_CORE_H
#define RASP_CORE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RASP_MAX_FINDINGS 96
#define RASP_DETAIL_LEN   160

typedef struct {
    uint16_t code;        // RASP_F_* below
    uint8_t  confidence;  // 0-100, evidence quality as judged by the check
    uint8_t  _pad;
    char     detail[RASP_DETAIL_LEN];
} rasp_finding_t;

typedef struct {
    rasp_finding_t items[RASP_MAX_FINDINGS];
    uint32_t count;
    uint32_t checks_completed;   // bitmask of RASP_CHECK_*
    uint32_t checks_started;     // set on entry; started-but-not-completed => suppressed
    uint32_t dropped;            // findings lost because the buffer was full
} rasp_findings_t;

// ---- Check identifiers (bitmask) ---------------------------------------------
enum {
    RASP_CHECK_FILESYSTEM   = 1u << 0,
    RASP_CHECK_SANDBOX      = 1u << 1,
    RASP_CHECK_IMAGES       = 1u << 2,
    RASP_CHECK_HOOKS        = 1u << 3,
    RASP_CHECK_DEBUGGER     = 1u << 4,
    RASP_CHECK_FRIDA        = 1u << 5,
    RASP_CHECK_CODESIGN     = 1u << 6,
    RASP_CHECK_ENVIRONMENT  = 1u << 7,
    RASP_CHECK_DEVMODE      = 1u << 8,
    RASP_CHECK_CANARY       = 1u << 9,
    RASP_CHECK_SELF         = 1u << 10,
};

// ---- Finding codes ------------------------------------------------------------
enum {
    // Filesystem / jailbreak artefacts
    RASP_F_JB_PATH_PRESENT        = 100,
    RASP_F_JB_PATH_ERRNO_ORACLE   = 101,
    RASP_F_SYMLINKED_SYSTEM_DIR   = 102,
    RASP_F_ROOT_NOT_SEALED        = 103,
    RASP_F_ROOT_WRITABLE          = 104,
    RASP_F_JB_ROOT_SYMLINK        = 105,
    RASP_F_LIBC_SYSCALL_MISMATCH  = 108,
    RASP_F_CANARY_FAILED          = 109,
    RASP_F_DYLD_MODIFIED          = 110,
    RASP_F_USERSPACE_REBOOT       = 111,
    // Sandbox
    RASP_F_SANDBOX_WRITE          = 120,
    RASP_F_SANDBOX_FORK           = 121,
    RASP_F_SANDBOX_READ           = 122,
    // Loaded images / injection
    RASP_F_SUSPICIOUS_IMAGE       = 200,
    RASP_F_UNEXPECTED_IMAGE_PATH  = 201,
    RASP_F_IMAGE_LIST_MISMATCH    = 202,
    RASP_F_IMAGE_ADDED_RUNTIME    = 203,
    RASP_F_INTERPOSE_SECTION      = 204,
    // Hooks
    RASP_F_INLINE_HOOK            = 300,
    RASP_F_SYMBOL_REBOUND         = 301,
    RASP_F_BREAKPOINT_INSN        = 302,
    RASP_F_OBJC_SWIZZLED          = 303,
    RASP_F_SYSCALL_STUB_ALTERED   = 304,
    RASP_F_SYMBOL_FOREIGN_IMAGE   = 305,
    RASP_F_PROLOGUE_CHANGED       = 306,
    // Debugger
    RASP_F_PTRACED                = 400,
    RASP_F_CS_DEBUGGED            = 401,
    RASP_F_EXCEPTION_PORTS        = 402,
    RASP_F_PPID_UNEXPECTED        = 403,
    // Frida / instrumentation
    RASP_F_FRIDA_THREAD           = 500,
    RASP_F_FRIDA_PORT_OPEN        = 501,
    RASP_F_FRIDA_DBUS             = 502,
    RASP_F_ANON_EXEC_MEMORY       = 503,
    RASP_F_FRIDA_MEMORY_MARKER    = 504,
    // Code signing / binary integrity
    RASP_F_CS_INVALID             = 600,
    RASP_F_GET_TASK_ALLOW         = 601,
    RASP_F_SUSPICIOUS_ENTITLEMENT = 602,
    RASP_F_BINARY_DECRYPTED       = 603,
    RASP_F_TEXT_MODIFIED          = 610,
    // Environment
    RASP_F_ENV_INJECTION          = 700,
    RASP_F_ENV_JAILBREAK          = 701,
    RASP_F_ENV_GETENV_MISMATCH    = 702,
    // Developer mode
    RASP_F_DEVMODE_ENABLED        = 800,
    RASP_F_DDI_MOUNTED            = 802,
};

// ---- Context passed from Swift ------------------------------------------------
typedef struct {
    const char *bundle_path;       // Bundle.main.bundlePath (realpath'd by caller)
    const char *executable_path;   // Bundle.main.executablePath
    const char *container_tmp;     // NSTemporaryDirectory()
    const uint16_t *frida_ports;   // loopback TCP ports to probe
    uint32_t frida_port_count;
    uint32_t probe_timeout_ms;     // per-port connect timeout
    bool     allow_fork_probe;     // fork() probe (child _exit()s immediately)
    bool     scan_memory;          // walk VM regions for anonymous exec memory
} rasp_context_t;

// ---- Checks ---------------------------------------------------------------------
void rasp_check_filesystem(const rasp_context_t *ctx, rasp_findings_t *out);
void rasp_check_sandbox(const rasp_context_t *ctx, rasp_findings_t *out);
void rasp_check_images(const rasp_context_t *ctx, rasp_findings_t *out);
void rasp_check_hooks(const rasp_context_t *ctx, rasp_findings_t *out);
void rasp_check_debugger(const rasp_context_t *ctx, rasp_findings_t *out);
void rasp_check_frida(const rasp_context_t *ctx, rasp_findings_t *out);
void rasp_check_codesign(const rasp_context_t *ctx, rasp_findings_t *out);
void rasp_check_environment(const rasp_context_t *ctx, rasp_findings_t *out);
void rasp_check_devmode(const rasp_context_t *ctx, rasp_findings_t *out);
void rasp_check_canary(const rasp_context_t *ctx, rasp_findings_t *out);
// Compares the live main-image __text hash and the first bytes of sensitive
// functions (libsystem and the RASP core) with the baseline taken by
// rasp_integrity_baseline(). Detects code patched in memory after start-up.
void rasp_check_self(const rasp_context_t *ctx, rasp_findings_t *out);

// ---- Self-integrity baseline ------------------------------------------------------
// Call as early as possible (IntegrityKit/JailbreakDetector call it on init).
// Idempotent; the first call wins.
void rasp_integrity_baseline(void);

// ---- Remote rules (additive) -------------------------------------------------------
// Adds jailbreak paths and image-name markers on top of the compiled-in lists.
// Strings are copied. Passing new lists replaces the previous *extra* lists;
// the compiled-in lists can never be removed this way.
void rasp_rules_set(const char *const *paths, uint32_t path_count,
                    const char *const *markers, uint32_t marker_count);

// ---- Facts the Swift layer needs for policy decisions ------------------------------
typedef struct {
    uint32_t cs_flags;             // csops(CS_OPS_STATUS)
    int32_t  cs_status_errno;      // 0 on success
    int32_t  cryptid;              // LC_ENCRYPTION_INFO(_64) cryptid, -1 if absent
    int32_t  devmode_sysctl;       // 1 on, 0 off, -1 unavailable
    int32_t  exception_port_count; // task-level exception ports set
    char     text_sha256[65];      // hex SHA-256 of main image __TEXT,__text
} rasp_facts_t;

void rasp_collect_facts(rasp_facts_t *facts);

// ---- Runtime monitoring ----------------------------------------------------------
// Registers a dyld add-image callback. Images loaded after registration are
// queued; drain with rasp_drain_new_images(). Safe to call more than once.
void rasp_monitor_install(void);
// Copies up to `max` newly loaded image paths into `buf`, which holds `max`
// NUL-terminated slots of RASP_DETAIL_LEN bytes each. Returns the number copied.
// Classification is done by rasp_classify_image().
uint32_t rasp_drain_new_images(char *buf, uint32_t max);
// 0 = expected, RASP_F_SUSPICIOUS_IMAGE or RASP_F_UNEXPECTED_IMAGE_PATH otherwise.
uint16_t rasp_classify_image(const char *path, const char *bundle_path);

// ---- Active countermeasures (opt-in) ------------------------------------------------
// PT_DENY_ATTACH via raw syscall. Prevents later debugger attach on stock kernels;
// trivially bypassed on a jailbroken kernel. Never call this in debug builds.
int rasp_deny_debugger_attach(void);

// ---- Obfuscated strings ---------------------------------------------------------------
// Decodes entry `index` into `out` (NUL-terminated). Returns decoded length or 0.
size_t rasp_obf_decode(uint16_t index, char *out, size_t cap);
void   rasp_secure_zero(void *p, size_t n);

// ---- Inline quick guard ---------------------------------------------------------------
// Header-only, force-inlined check meant to be sprinkled at many call sites
// (before login, payment, key use) so there is no single function to hook.
// Uses raw syscalls only. Returns a bitmask of RASP_GUARD_* (0 = nothing seen).
enum { RASP_GUARD_TRACED = 1u << 0, RASP_GUARD_CS_DEBUGGED = 1u << 1, RASP_GUARD_JB_ROOT = 1u << 2 };

#if defined(__aarch64__) && defined(__APPLE__)
#include <sys/sysctl.h>
static inline __attribute__((always_inline))
long rasp_guard_svc(long num, long a0, long a1, long a2, long a3, long a4, long a5, int *failed) {
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    register long x2 __asm__("x2") = a2;
    register long x3 __asm__("x3") = a3;
    register long x4 __asm__("x4") = a4;
    register long x5 __asm__("x5") = a5;
    register long x16 __asm__("x16") = num;
    long carry;
    __asm__ volatile("svc #0x80\n\tcset %[c], cs\n\t"
                     : "+r"(x0), "+r"(x1), "+r"(x16), [c] "=&r"(carry)
                     : "r"(x2), "r"(x3), "r"(x4), "r"(x5)
                     : "memory", "cc");
    *failed = (int)carry;
    return x0;
}
#endif

static inline __attribute__((always_inline)) uint32_t rasp_quick_guard(void) {
    uint32_t flags = 0;
#if defined(__aarch64__) && defined(__APPLE__)
    int failed = 0;
    int pid = (int)rasp_guard_svc(20 /* getpid */, 0, 0, 0, 0, 0, 0, &failed);

    struct kinfo_proc kp;
    size_t len = sizeof kp;
    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, pid };
    __builtin_memset(&kp, 0, sizeof kp);
    rasp_guard_svc(202 /* __sysctl */, (long)mib, 4, (long)&kp, (long)&len, 0, 0, &failed);
    if (!failed && (kp.kp_proc.p_flag & 0x800 /* P_TRACED */)) flags |= RASP_GUARD_TRACED;

    uint32_t cs = 0;
    rasp_guard_svc(169 /* csops */, pid, 0 /* CS_OPS_STATUS */, (long)&cs, sizeof cs, 0, 0, &failed);
    if (!failed && (cs & 0x10000000u /* CS_DEBUGGED */)) flags |= RASP_GUARD_CS_DEBUGGED;

    // "/var/jb" assembled from XOR-ed bytes so it is not a plaintext literal.
    volatile unsigned char enc[8] = { 0x75, 0x2c, 0x3b, 0x28, 0x75, 0x30, 0x38, 0x5a };
    char path[8];
    for (int i = 0; i < 8; i++) path[i] = (char)(enc[i] ^ 0x5a);
    unsigned char st[256];   /* >= sizeof(struct stat) */
    rasp_guard_svc(340 /* lstat64 */, (long)path, (long)st, 0, 0, 0, 0, &failed);
    if (!failed) flags |= RASP_GUARD_JB_ROOT;
#endif
    return flags;
}

#ifdef __cplusplus
}
#endif
#endif
