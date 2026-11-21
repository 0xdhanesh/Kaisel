// Internal helpers shared by the C core. Not part of the module's public API.
#ifndef RASP_INTERNAL_H
#define RASP_INTERNAL_H

#include "rasp_core.h"
#include "rasp_strings_table.h"
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mount.h>

#define RASP_INLINE static inline __attribute__((always_inline))

// ---------------------------------------------------------------------------
// Raw Darwin syscalls.
//
// On arm64 the call number goes in x16, arguments in x0-x5, `svc #0x80` traps,
// and the kernel sets the carry flag on error with the errno in x0. Each call
// site is force-inlined so there is no single wrapper function for an attacker
// to hook: the `svc` instruction is emitted inside every check. A hook on the
// libc symbol (fishhook, Substrate, Frida Interceptor) does not see these calls.
//
// On x86_64 (Intel simulator) we fall back to libc's syscall(2); the simulator
// is not a security boundary anyway.
// ---------------------------------------------------------------------------
#define RASP_SYS_read        3
#define RASP_SYS_write       4
#define RASP_SYS_open        5
#define RASP_SYS_close       6
#define RASP_SYS_unlink      10
#define RASP_SYS_getpid      20
#define RASP_SYS_ptrace      26
#define RASP_SYS_access      33
#define RASP_SYS_getppid     39
#define RASP_SYS_readlink    58
#define RASP_SYS_csops       169
#define RASP_SYS___sysctl    202
#define RASP_SYS_stat64      338
#define RASP_SYS_lstat64     340
#define RASP_SYS_statfs64    345

#if defined(__aarch64__) && defined(__APPLE__)
RASP_INLINE long rasp_svc(long num, long a0, long a1, long a2, long a3, long a4, long a5, int *err) {
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    register long x2 __asm__("x2") = a2;
    register long x3 __asm__("x3") = a3;
    register long x4 __asm__("x4") = a4;
    register long x5 __asm__("x5") = a5;
    register long x16 __asm__("x16") = num;
    long carry;
    __asm__ volatile(
        "svc #0x80\n\t"
        "cset %[c], cs\n\t"
        : "+r"(x0), "+r"(x1), "+r"(x16), [c] "=&r"(carry)
        : "r"(x2), "r"(x3), "r"(x4), "r"(x5)
        : "memory", "cc");
    if (carry) {
        if (err) *err = (int)x0;
        return -1;
    }
    if (err) *err = 0;
    return x0;
}
#else
#include <unistd.h>
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
RASP_INLINE long rasp_svc(long num, long a0, long a1, long a2, long a3, long a4, long a5, int *err) {
    errno = 0;
    long r = syscall((int)num, a0, a1, a2, a3, a4, a5);
    if (err) *err = (r == -1) ? errno : 0;
    return r;
}
#pragma clang diagnostic pop
#endif

#define rasp_sys0(n, e)                 rasp_svc((n), 0, 0, 0, 0, 0, 0, (e))
#define rasp_sys1(n, a, e)              rasp_svc((n), (long)(a), 0, 0, 0, 0, 0, (e))
#define rasp_sys2(n, a, b, e)           rasp_svc((n), (long)(a), (long)(b), 0, 0, 0, 0, (e))
#define rasp_sys3(n, a, b, c, e)        rasp_svc((n), (long)(a), (long)(b), (long)(c), 0, 0, 0, (e))
#define rasp_sys4(n, a, b, c, d, e)     rasp_svc((n), (long)(a), (long)(b), (long)(c), (long)(d), 0, 0, (e))
#define rasp_sys6(n, a, b, c, d, f, g, e) rasp_svc((n), (long)(a), (long)(b), (long)(c), (long)(d), (long)(f), (long)(g), (e))

RASP_INLINE int rasp_raw_stat(const char *p, struct stat *st, int *err)  { return (int)rasp_sys2(RASP_SYS_stat64, p, st, err); }
RASP_INLINE int rasp_raw_lstat(const char *p, struct stat *st, int *err) { return (int)rasp_sys2(RASP_SYS_lstat64, p, st, err); }
RASP_INLINE int rasp_raw_access(const char *p, int mode, int *err)       { return (int)rasp_sys2(RASP_SYS_access, p, mode, err); }
RASP_INLINE int rasp_raw_open(const char *p, int flags, int mode, int *err) { return (int)rasp_sys3(RASP_SYS_open, p, flags, mode, err); }
RASP_INLINE int rasp_raw_close(int fd)                                   { int e; return (int)rasp_sys1(RASP_SYS_close, fd, &e); }
RASP_INLINE int rasp_raw_unlink(const char *p, int *err)                 { return (int)rasp_sys1(RASP_SYS_unlink, p, err); }
RASP_INLINE long rasp_raw_readlink(const char *p, char *buf, size_t n, int *err) { return rasp_sys3(RASP_SYS_readlink, p, buf, n, err); }
RASP_INLINE int rasp_raw_statfs(const char *p, struct statfs *s, int *err) { return (int)rasp_sys2(RASP_SYS_statfs64, p, s, err); }
RASP_INLINE int rasp_raw_getpid(void)  { int e; return (int)rasp_sys0(RASP_SYS_getpid, &e); }
RASP_INLINE int rasp_raw_getppid(void) { int e; return (int)rasp_sys0(RASP_SYS_getppid, &e); }
RASP_INLINE int rasp_raw_csops(int pid, unsigned ops, void *buf, size_t sz, int *err) {
    return (int)rasp_sys4(RASP_SYS_csops, pid, ops, buf, sz, err);
}
RASP_INLINE int rasp_raw_sysctl(int *mib, unsigned cnt, void *old, size_t *oldlen, void *nw, size_t nwlen, int *err) {
    return (int)rasp_sys6(RASP_SYS___sysctl, mib, cnt, old, oldlen, nw, nwlen, err);
}

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------
void rasp_add(rasp_findings_t *out, uint16_t code, uint8_t confidence, const char *fmt, ...)
    __attribute__((format(printf, 4, 5)));

#define RASP_BEGIN(out, bit)  do { (out)->checks_started |= (bit); } while (0)
#define RASP_END(out, bit)    do { (out)->checks_completed |= (bit); } while (0)

// ---------------------------------------------------------------------------
// Obfuscated strings
// ---------------------------------------------------------------------------
#define RASP_STR_MAX 256
#define RASP_MISC(i) ((uint16_t)(RASP_LIST_MISC_START + (i)))
enum {
    RASP_MISC_DEVMODE_SYSCTL = 0, RASP_MISC_SNAPSHOT_PREFIX, RASP_MISC_BUNDLE_ROOT_PRIVATE,
    RASP_MISC_BUNDLE_ROOT, RASP_MISC_LIBSYSTEM_KERNEL, RASP_MISC_LIBSYSTEM_C, RASP_MISC_LIBDYLD,
    RASP_MISC_USR_LIB_SYSTEM, RASP_MISC_SYSTEM, RASP_MISC_USR_LIB, RASP_MISC_CRYPTEXES,
    RASP_MISC_DEVELOPER, RASP_MISC_SYSTEM_DEVELOPER, RASP_MISC_DBUS_AUTH, RASP_MISC_DBUS_REJECTED,
    RASP_MISC_PRIVATE, RASP_MISC_FOUNDATION, RASP_MISC_UIKITCORE, RASP_MISC_LIBOBJC, RASP_MISC_FORK,
    RASP_MISC_PTRACE, RASP_MISC_LIBDYLD_SHORT, RASP_MISC_DYLD, RASP_MISC_PREFS_DIR, RASP_MISC_VAR_JB,
};

// Case-insensitive substring search.
const char *rasp_strcasestr(const char *hay, const char *needle);
// Remote rules (rasp_rules.c). copy_path returns the number of extra paths.
uint32_t rasp_rules_copy_path(uint32_t i, char *out, size_t cap);
bool rasp_rules_marker_match(const char *path);
// Fills `out` with 16 random hex chars (arc4random) + NUL.
void rasp_random_token(char out[17]);

// ---------------------------------------------------------------------------
// Image helpers (rasp_images.c)
// ---------------------------------------------------------------------------
#include <mach-o/loader.h>
// Returns the name of the image containing `addr`, or NULL. Uses dladdr.
const char *rasp_image_name_for(const void *addr);
// True if `addr` falls inside any loaded image's segments (incl. dyld itself).
bool rasp_addr_in_any_image(uintptr_t addr);
// Iterates load commands of a 64-bit Mach-O header.
typedef bool (*rasp_lc_visitor)(const struct load_command *lc, void *ctx);
void rasp_for_each_load_command(const struct mach_header_64 *mh, rasp_lc_visitor v, void *ctx);
// Main executable header and slide.
const struct mach_header_64 *rasp_main_header(intptr_t *slide);

#endif
