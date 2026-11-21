// Hook integrity: inline trampolines, symbol rebinding (fishhook / dyld
// interposing), syscall-stub tampering, software breakpoints and Objective-C
// method swizzling on the functions RASP checks depend on.
//
// AArch64 encodings used below:
//   LDR Xt, #lit     0x58000000 | imm19<<5 | Rt            mask 0xFF000000
//   ADRP Xd, #pg     0x90000000 | ...                       mask 0x9F000000
//   BR Xn            0xD61F0000 | Rn<<5                     mask 0xFFFFFC1F
//   BRAAZ/BRABZ Xn   0xD61F081F / 0xD61F0C1F | Rn<<5        mask 0xFFFFFC1F
//   B imm26          0x14000000                             mask 0xFC000000
//   BRK #imm16       0xD4200000                             mask 0xFFE0001F
//   SVC #0x80        0xD4001001

#include "rasp_internal.h"
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/sysctl.h>
#include <mach/mach.h>
#include <mach-o/dyld.h>
#include <objc/runtime.h>
#include <objc/message.h>
#if __has_include(<ptrauth.h>)
#include <ptrauth.h>
#endif

static inline const void *strip(const void *p) {
#if __has_feature(ptrauth_intrinsics)
    return ptrauth_strip(p, ptrauth_key_function_pointer);
#else
    return p;
#endif
}

#if defined(__aarch64__)
#define IS_LDR_LIT(i)   (((i) & 0xFF000000u) == 0x58000000u)
#define IS_ADRP(i)      (((i) & 0x9F000000u) == 0x90000000u)
#define IS_BR(i)        (((i) & 0xFFFFFC1Fu) == 0xD61F0000u || ((i) & 0xFFFFFC1Fu) == 0xD61F081Fu || \
                         ((i) & 0xFFFFFC1Fu) == 0xD61F0C1Fu)
#define BR_REG(i)       (((i) >> 5) & 0x1F)
#define IS_B(i)         (((i) & 0xFC000000u) == 0x14000000u)
#define IS_BRK(i)       (((i) & 0xFFE0001Fu) == 0xD4200000u)
#define IS_SVC80(i)     ((i) == 0xD4001001u)

typedef enum { PRO_OK = 0, PRO_TRAMPOLINE, PRO_FAR_BRANCH, PRO_BRK } prologue_t;

static prologue_t inspect_prologue(const void *fn, char *why, size_t whylen) {
    const uint32_t *p = (const uint32_t *)strip(fn);
    uint32_t w[6];
    memcpy(w, p, sizeof w);

    if (IS_BRK(w[0])) { snprintf(why, whylen, "brk at entry"); return PRO_BRK; }

    const char *src = rasp_image_name_for(p);

    // LDR Xt, #lit ; [..] ; BR Xt   (Substrate, Frida, ElleKit, Dobby absolute jumps)
    // The literal holds the jump target; it must not leave the function's image.
    for (int i = 0; i < 2; i++) {
        if (IS_LDR_LIT(w[i])) {
            uint32_t rt = w[i] & 0x1F;
            for (int j = i + 1; j < i + 3 && j < 6; j++)
                if (IS_BR(w[j]) && BR_REG(w[j]) == rt) {
                    int32_t imm19 = (int32_t)(w[i] << 8) >> 13;
                    const uint64_t *lit = (const uint64_t *)((uintptr_t)(p + i) + (intptr_t)imm19 * 4);
                    const void *target = strip((const void *)(uintptr_t)*lit);
                    const char *dst = rasp_image_name_for(target);
                    if (!src || !dst || strcmp(src, dst) != 0) {
                        snprintf(why, whylen, "ldr x%u,#lit; br x%u -> %s", rt, rt, dst ? dst : "anonymous memory");
                        return PRO_TRAMPOLINE;
                    }
                }
        }
    }
    // ADRP Xd ; ... ; BR Xd   (page-relative trampolines). dyld4's libdyld
    // forwards through a vtable with a similar shape, so only report when the
    // ADRP page lies outside the function's own image.
    if (IS_ADRP(w[0])) {
        uint32_t rd = w[0] & 0x1F;
        for (int j = 1; j < 4; j++)
            if (IS_BR(w[j]) && BR_REG(w[j]) == rd) {
                int64_t immlo = (w[0] >> 29) & 0x3, immhi = (w[0] >> 5) & 0x7FFFF;
                int64_t imm = (int64_t)((uint64_t)((immhi << 2) | immlo) << 43) >> 43;   // sign-extend 21 bits
                uintptr_t page = ((uintptr_t)p & ~(uintptr_t)0xFFF) + (uintptr_t)(imm << 12);
                const char *dst = rasp_image_name_for((const void *)page);
                if (!src || !dst || strcmp(src, dst) != 0) {
                    snprintf(why, whylen, "adrp x%u -> %s; br x%u", rd, dst ? dst : "anonymous memory", rd);
                    return PRO_TRAMPOLINE;
                }
            }
    }
    // B imm26 at entry whose target leaves the function's own image.
    if (IS_B(w[0])) {
        int32_t imm = (int32_t)(w[0] << 6) >> 6;
        uintptr_t target = (uintptr_t)p + (intptr_t)imm * 4;
        const char *dst = rasp_image_name_for((const void *)target);
        if (!dst || !src || strcmp(src, dst) != 0) {
            snprintf(why, whylen, "b -> %s", dst ? dst : "unmapped/anonymous");
            return PRO_FAR_BRANCH;
        }
    }
    return PRO_OK;
}

static bool stub_has_svc(const void *fn) {
    const uint32_t *p = (const uint32_t *)strip(fn);
    for (int i = 0; i < 8; i++) if (IS_SVC80(p[i])) return true;
    return false;
}
#endif

static bool is_system_image(const char *path) {
    if (!path) return false;
    char a[32], b[32];
    size_t na = rasp_obf_decode(RASP_MISC(RASP_MISC_USR_LIB), a, sizeof a);
    size_t nb = rasp_obf_decode(RASP_MISC(RASP_MISC_SYSTEM), b, sizeof b);
    bool r = (na && strncmp(path, a, na) == 0) || (nb && strncmp(path, b, nb) == 0);
    rasp_secure_zero(a, sizeof a); rasp_secure_zero(b, sizeof b);
    return r;
}

// Direct references resolved through *our own* GOT. fishhook and dyld
// interposing rewrite these pointers; dlsym() walks export tries instead.
typedef struct { const char *label; const void *bound; } bound_ref_t;

static void check_rebinding(rasp_findings_t *out) {
    const bound_ref_t refs[] = {
        { "stat",                  (const void *)&stat },
        { "lstat",                 (const void *)&lstat },
        { "access",                (const void *)&access },
        { "getenv",                (const void *)&getenv },
        { "fopen",                 (const void *)&fopen },
        { "sysctl",                (const void *)&sysctl },
        { "sysctlbyname",          (const void *)&sysctlbyname },
        { "_dyld_image_count",     (const void *)&_dyld_image_count },
        { "_dyld_get_image_name",  (const void *)&_dyld_get_image_name },
        { "task_info",             (const void *)&task_info },
    };
    for (size_t i = 0; i < sizeof refs / sizeof refs[0]; i++) {
        const void *viaGot = strip(refs[i].bound);
        const void *viaDlsym = strip(dlsym(RTLD_DEFAULT, refs[i].label));
        if (viaDlsym && viaGot != viaDlsym) {
            const char *img = rasp_image_name_for(viaGot);
            rasp_add(out, RASP_F_SYMBOL_REBOUND, 95, "%s bound to %s", refs[i].label, img ? img : "anonymous memory");
        }
        if (!is_system_image(rasp_image_name_for(viaGot))) {
            const char *img = rasp_image_name_for(viaGot);
            rasp_add(out, RASP_F_SYMBOL_FOREIGN_IMAGE, 90, "%s resolves into %s", refs[i].label, img ? img : "anonymous memory");
        }
    }
}

// Objective-C: the IMP of security-relevant methods must live in the framework
// that defines them. Frida's ObjC.implementation, Substrate MSHookMessageEx and
// plain method_exchangeImplementations all move it elsewhere.
typedef struct { const char *cls; const char *sel; int expected_misc; bool is_class_method; } objc_target_t;

static void check_objc(rasp_findings_t *out) {
    const objc_target_t targets[] = {
        { "NSFileManager", "fileExistsAtPath:",              RASP_MISC_FOUNDATION, false },
        { "NSFileManager", "fileExistsAtPath:isDirectory:",  RASP_MISC_FOUNDATION, false },
        { "NSFileManager", "isReadableFileAtPath:",          RASP_MISC_FOUNDATION, false },
        { "NSFileManager", "contentsOfDirectoryAtPath:error:", RASP_MISC_FOUNDATION, false },
        { "NSProcessInfo", "environment",                    RASP_MISC_FOUNDATION, false },
        { "NSBundle",      "bundleIdentifier",               RASP_MISC_FOUNDATION, false },
        { "NSBundle",      "infoDictionary",                 RASP_MISC_FOUNDATION, false },
        { "UIApplication", "canOpenURL:",                    RASP_MISC_UIKITCORE,  false },
        { "UIDevice",      "systemVersion",                  RASP_MISC_UIKITCORE,  false },
    };
    for (size_t i = 0; i < sizeof targets / sizeof targets[0]; i++) {
        Class c = (Class)objc_getClass(targets[i].cls);
        if (!c) continue;
        if (targets[i].is_class_method) c = object_getClass((id)c);
        Method m = class_getInstanceMethod(c, sel_registerName(targets[i].sel));
        if (!m) continue;
        IMP imp = method_getImplementation(m);
        const char *img = rasp_image_name_for(strip((const void *)imp));
        char expect[32];
        rasp_obf_decode(RASP_MISC(targets[i].expected_misc), expect, sizeof expect);
        if (!img || !strstr(img, expect))
            rasp_add(out, RASP_F_OBJC_SWIZZLED, 90, "-[%s %s] IMP in %s", targets[i].cls, targets[i].sel,
                     img ? img : "anonymous memory");
#if defined(__aarch64__)
        else {
            char why[64];
            if (inspect_prologue((const void *)imp, why, sizeof why) != PRO_OK)
                rasp_add(out, RASP_F_INLINE_HOOK, 85, "-[%s %s]: %s", targets[i].cls, targets[i].sel, why);
        }
#endif
        rasp_secure_zero(expect, sizeof expect);
    }
}

void rasp_check_hooks(const rasp_context_t *ctx, rasp_findings_t *out) {
    (void)ctx;
    RASP_BEGIN(out, RASP_CHECK_HOOKS);
    char name[64];

    for (uint16_t i = 0; i < RASP_LIST_HOOK_TARGETS_COUNT; i++) {
        size_t n = rasp_obf_decode(RASP_LIST_HOOK_TARGETS_START + i, name, sizeof name);
        if (!n) continue;
        bool syscall_stub = (n > 2 && name[0] == 'S' && name[1] == ':');
        const char *sym = syscall_stub ? name + 2 : name;
        const void *fn = dlsym(RTLD_DEFAULT, sym);
        if (!fn) { rasp_secure_zero(name, sizeof name); continue; }

        const char *img = rasp_image_name_for(strip(fn));
        if (!is_system_image(img))
            rasp_add(out, RASP_F_SYMBOL_FOREIGN_IMAGE, 90, "dlsym(%s) -> %s", sym, img ? img : "anonymous memory");

#if defined(__aarch64__)
        char why[96];
        switch (inspect_prologue(fn, why, sizeof why)) {
            case PRO_TRAMPOLINE: rasp_add(out, RASP_F_INLINE_HOOK, 95, "%s: %s", sym, why); break;
            case PRO_FAR_BRANCH: rasp_add(out, RASP_F_INLINE_HOOK, 90, "%s: %s", sym, why); break;
            case PRO_BRK:        rasp_add(out, RASP_F_BREAKPOINT_INSN, 80, "%s: %s", sym, why); break;
            case PRO_OK: break;
        }
        if (syscall_stub && !stub_has_svc(fn))
            rasp_add(out, RASP_F_SYSCALL_STUB_ALTERED, 70, "%s: no svc #0x80 in first 8 insns", sym);
#endif
        rasp_secure_zero(name, sizeof name);
    }

#if defined(__aarch64__)
    // Self-integrity: the RASP entry points themselves. Hooking a check to
    // return early also leaves its "started" bit unset, which Swift reports.
    const struct { const char *n; const void *f; } self_fns[] = {
        { "fs",       (const void *)&rasp_check_filesystem },
        { "sandbox",  (const void *)&rasp_check_sandbox },
        { "images",   (const void *)&rasp_check_images },
        { "debugger", (const void *)&rasp_check_debugger },
        { "frida",    (const void *)&rasp_check_frida },
        { "codesign", (const void *)&rasp_check_codesign },
        { "env",      (const void *)&rasp_check_environment },
        { "classify", (const void *)&rasp_classify_image },
    };
    for (size_t i = 0; i < sizeof self_fns / sizeof self_fns[0]; i++) {
        char why[96];
        prologue_t r = inspect_prologue(self_fns[i].f, why, sizeof why);
        if (r == PRO_TRAMPOLINE || r == PRO_FAR_BRANCH)
            rasp_add(out, RASP_F_INLINE_HOOK, 99, "RASP core [%s]: %s", self_fns[i].n, why);
        else if (r == PRO_BRK)
            rasp_add(out, RASP_F_BREAKPOINT_INSN, 90, "RASP core [%s]: %s", self_fns[i].n, why);
    }
#endif

    check_rebinding(out);
    check_objc(out);
    RASP_END(out, RASP_CHECK_HOOKS);
}
