// Self-integrity: detect code patched in memory after start-up.
//
// At baseline time we record
//   * SHA-256 of the main image's __TEXT,__text (where this core is linked);
//   * the first 32 bytes of every hook-target function and every RASP entry
//     point.
// rasp_check_self() recomputes both. Inline hooks installed after launch
// (Frida Interceptor, late Substrate/ElleKit hooks, debugger breakpoints)
// change these bytes even when the patch uses an encoding the prologue
// decoder does not recognise.
//
// Limitation: anything patched *before* the baseline (e.g. by a dylib
// constructor that runs before ours) is baked into the baseline. The static
// prologue decoder, the server-side __TEXT hash comparison and App Attest
// cover that case.

#include "rasp_internal.h"
#include <dlfcn.h>
#include <stdio.h>
#include <os/lock.h>
#include <CommonCrypto/CommonDigest.h>
#include <mach-o/getsect.h>
#if __has_include(<ptrauth.h>)
#include <ptrauth.h>
#endif

#define SNAP_BYTES 32
#define SNAP_MAX   48

typedef struct { const void *addr; uint8_t bytes[SNAP_BYTES]; char label[32]; } snap_t;

static os_unfair_lock g_self_lock = OS_UNFAIR_LOCK_INIT;
static int g_baselined;
static uint8_t g_text_hash[CC_SHA256_DIGEST_LENGTH];
static bool g_have_text_hash;
static snap_t g_snaps[SNAP_MAX];
static uint32_t g_snap_count;

static inline const void *strip_ptr(const void *p) {
#if __has_feature(ptrauth_intrinsics)
    return ptrauth_strip(p, ptrauth_key_function_pointer);
#else
    return p;
#endif
}

static bool hash_main_text(uint8_t out[CC_SHA256_DIGEST_LENGTH]) {
    intptr_t slide = 0;
    const struct mach_header_64 *mh = rasp_main_header(&slide);
    unsigned long size = 0;
    const uint8_t *text = mh ? getsectiondata(mh, SEG_TEXT, SECT_TEXT, &size) : NULL;
    if (!text || !size) return false;
    CC_SHA256(text, (CC_LONG)size, out);
    return true;
}

static void add_snap(const void *fn, const char *label) {
    if (!fn || g_snap_count >= SNAP_MAX) return;
    snap_t *s = &g_snaps[g_snap_count++];
    s->addr = strip_ptr(fn);
    memcpy(s->bytes, s->addr, SNAP_BYTES);
    strlcpy(s->label, label, sizeof s->label);
}

void rasp_integrity_baseline(void) {
    os_unfair_lock_lock(&g_self_lock);
    if (g_baselined) { os_unfair_lock_unlock(&g_self_lock); return; }
    g_have_text_hash = hash_main_text(g_text_hash);

    char name[64];
    for (uint16_t i = 0; i < RASP_LIST_HOOK_TARGETS_COUNT; i++) {
        size_t n = rasp_obf_decode(RASP_LIST_HOOK_TARGETS_START + i, name, sizeof name);
        if (!n) continue;
        const char *sym = (n > 2 && name[0] == 'S' && name[1] == ':') ? name + 2 : name;
        add_snap(dlsym(RTLD_DEFAULT, sym), sym);
        rasp_secure_zero(name, sizeof name);
    }
    add_snap((const void *)&rasp_check_filesystem, "core:fs");
    add_snap((const void *)&rasp_check_sandbox, "core:sandbox");
    add_snap((const void *)&rasp_check_images, "core:images");
    add_snap((const void *)&rasp_check_hooks, "core:hooks");
    add_snap((const void *)&rasp_check_debugger, "core:debugger");
    add_snap((const void *)&rasp_check_frida, "core:frida");
    add_snap((const void *)&rasp_check_codesign, "core:codesign");
    add_snap((const void *)&rasp_check_environment, "core:env");
    add_snap((const void *)&rasp_check_canary, "core:canary");
    add_snap((const void *)&rasp_classify_image, "core:classify");
    add_snap((const void *)&rasp_obf_decode, "core:decode");
    g_baselined = 1;
    os_unfair_lock_unlock(&g_self_lock);
}

void rasp_check_self(const rasp_context_t *ctx, rasp_findings_t *out) {
    (void)ctx;
    RASP_BEGIN(out, RASP_CHECK_SELF);
    rasp_integrity_baseline();   // no-op after the first call
    os_unfair_lock_lock(&g_self_lock);
    if (g_have_text_hash) {
        uint8_t now[CC_SHA256_DIGEST_LENGTH];
        if (hash_main_text(now) && memcmp(now, g_text_hash, sizeof now) != 0)
            rasp_add(out, RASP_F_TEXT_MODIFIED, 97, "main __text changed since start-up");
    }
    for (uint32_t i = 0; i < g_snap_count; i++) {
        if (memcmp(g_snaps[i].addr, g_snaps[i].bytes, SNAP_BYTES) != 0) {
            bool core = strncmp(g_snaps[i].label, "core:", 5) == 0;
            rasp_add(out, RASP_F_PROLOGUE_CHANGED, core ? 99 : 95, "%s patched after start-up", g_snaps[i].label);
        }
    }
    os_unfair_lock_unlock(&g_self_lock);
    RASP_END(out, RASP_CHECK_SELF);
}
