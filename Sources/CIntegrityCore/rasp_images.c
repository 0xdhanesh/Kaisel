// Loaded-image enumeration and injection detection.
//
// Two independent sources are compared:
//   A. the public dyld API (_dyld_image_count / _dyld_get_image_name), which
//      hiding tweaks commonly hook to drop their own entries;
//   B. dyld's own `dyld_all_image_infos` structure, located through
//      task_info(TASK_DYLD_INFO) and read directly from memory.
// If B lists more images than A, someone is filtering the dyld API.
// Every image path is classified by allow-listed location (system, cryptex,
// own bundle) rather than only by a deny-list of names.

#include "rasp_internal.h"
#include <TargetConditionals.h>
#include <dlfcn.h>
#include <mach/mach.h>
#include <mach-o/dyld.h>
#include <mach-o/dyld_images.h>
#include <mach-o/getsect.h>
#include <os/lock.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

// ---------------------------------------------------------------------------
// Mach-O helpers
// ---------------------------------------------------------------------------
void rasp_for_each_load_command(const struct mach_header_64 *mh, rasp_lc_visitor v, void *ctx) {
    if (!mh || mh->magic != MH_MAGIC_64) return;
    const uint8_t *p = (const uint8_t *)(mh + 1);
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)p;
        if (lc->cmdsize < sizeof *lc) return;
        if (!v(lc, ctx)) return;
        p += lc->cmdsize;
    }
}

const struct mach_header_64 *rasp_main_header(intptr_t *slide) {
    uint32_t n = _dyld_image_count();
    for (uint32_t i = 0; i < n; i++) {
        const struct mach_header *h = _dyld_get_image_header(i);
        if (h && h->filetype == MH_EXECUTE) {
            if (slide) *slide = _dyld_get_image_vmaddr_slide(i);
            return (const struct mach_header_64 *)h;
        }
    }
    return NULL;
}

const char *rasp_image_name_for(const void *addr) {
    Dl_info info;
    if (addr && dladdr(addr, &info) && info.dli_fname) return info.dli_fname;
    return NULL;
}

static const struct dyld_all_image_infos *all_image_infos(void) {
    struct task_dyld_info info;
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
    if (task_info(mach_task_self(), TASK_DYLD_INFO, (task_info_t)&info, &count) != KERN_SUCCESS)
        return NULL;
    return (const struct dyld_all_image_infos *)(uintptr_t)info.all_image_info_addr;
}

typedef struct { uintptr_t addr; uintptr_t load; intptr_t slide; bool hit; bool have_slide; } range_ctx_t;

static bool range_visitor(const struct load_command *lc, void *c) {
    range_ctx_t *r = (range_ctx_t *)c;
    if (lc->cmd != LC_SEGMENT_64) return true;
    const struct segment_command_64 *seg = (const struct segment_command_64 *)lc;
    if (!r->have_slide && strcmp(seg->segname, SEG_TEXT) == 0) {
        r->slide = (intptr_t)(r->load - seg->vmaddr);
        r->have_slide = true;
    }
    if (!r->have_slide || strcmp(seg->segname, SEG_PAGEZERO) == 0) return true;
    uintptr_t lo = (uintptr_t)(seg->vmaddr + r->slide);
    if (r->addr >= lo && r->addr < lo + seg->vmsize) { r->hit = true; return false; }
    return true;
}

static bool header_contains(const struct mach_header *h, uintptr_t addr) {
    if (!h) return false;
    range_ctx_t r = { .addr = addr, .load = (uintptr_t)h };
    rasp_for_each_load_command((const struct mach_header_64 *)h, range_visitor, &r);
    return r.hit;
}

bool rasp_addr_in_any_image(uintptr_t addr) {
    const struct dyld_all_image_infos *all = all_image_infos();
    if (all) {
        if (header_contains(all->dyldImageLoadAddress, addr)) return true;
        const struct dyld_image_info *arr = all->infoArray;
        if (arr) {
            for (uint32_t i = 0; i < all->infoArrayCount; i++)
                if (header_contains(arr[i].imageLoadAddress, addr)) return true;
        }
    }
    // Fallback to the public API.
    uint32_t n = _dyld_image_count();
    for (uint32_t i = 0; i < n; i++)
        if (header_contains(_dyld_get_image_header(i), addr)) return true;
    return false;
}

// ---------------------------------------------------------------------------
// Classification
// ---------------------------------------------------------------------------
static bool has_prefix_obf(const char *path, int misc) {
    char pre[64];
    size_t n = rasp_obf_decode(RASP_MISC(misc), pre, sizeof pre);
    bool r = n && strncmp(path, pre, n) == 0;
    rasp_secure_zero(pre, sizeof pre);
    return r;
}

static bool in_bundle(const char *path, const char *bundle) {
    if (!bundle || !*bundle) return false;
    size_t bl = strlen(bundle);
    if (strncmp(path, bundle, bl) == 0) return true;
    // dyld reports /private/var/... while NSBundle may report /var/...
    if (strncmp(path, "/private", 8) == 0 && strncmp(path + 8, bundle, bl) == 0) return true;
    if (strncmp(bundle, "/private", 8) == 0 && strncmp(path, bundle + 8, bl - 8) == 0) return true;
    return false;
}

uint16_t rasp_classify_image(const char *path, const char *bundle_path) {
    if (!path) return 0;
    char marker[RASP_STR_MAX];
    for (uint16_t i = 0; i < RASP_LIST_IMAGE_MARKERS_COUNT; i++) {
        if (!rasp_obf_decode(RASP_LIST_IMAGE_MARKERS_START + i, marker, sizeof marker)) continue;
        bool hit = rasp_strcasestr(path, marker) != NULL;
        rasp_secure_zero(marker, sizeof marker);
        if (hit) return RASP_F_SUSPICIOUS_IMAGE;
    }
    if (rasp_rules_marker_match(path)) return RASP_F_SUSPICIOUS_IMAGE;
#if TARGET_OS_SIMULATOR
    return 0;   // simulator images live under Xcode.app / CoreSimulator
#else
    if (has_prefix_obf(path, RASP_MISC_SYSTEM) || has_prefix_obf(path, RASP_MISC_USR_LIB) ||
        has_prefix_obf(path, RASP_MISC_CRYPTEXES) || has_prefix_obf(path, RASP_MISC_DEVELOPER) ||
        has_prefix_obf(path, RASP_MISC_SYSTEM_DEVELOPER) || in_bundle(path, bundle_path))
        return 0;
    return RASP_F_UNEXPECTED_IMAGE_PATH;
#endif
}

static bool already_reported(const rasp_findings_t *out, uint16_t code, const char *detail) {
    for (uint32_t i = 0; i < out->count; i++)
        if (out->items[i].code == code && strncmp(out->items[i].detail, detail, RASP_DETAIL_LEN - 1) == 0)
            return true;
    return false;
}

static void report_image(rasp_findings_t *out, const char *path, const char *bundle) {
    uint16_t c = rasp_classify_image(path, bundle);
    if (!c) return;
    char d[RASP_DETAIL_LEN];
    snprintf(d, sizeof d, "%s", path);
    if (!already_reported(out, c, d))
        rasp_add(out, c, c == RASP_F_SUSPICIOUS_IMAGE ? 95 : 70, "%s", d);
}

void rasp_check_images(const rasp_context_t *ctx, rasp_findings_t *out) {
    RASP_BEGIN(out, RASP_CHECK_IMAGES);
    const char *bundle = ctx ? ctx->bundle_path : NULL;

    // Source B: dyld_all_image_infos. infoArray is NULL while dyld is mutating
    // the list; retry briefly.
    uint32_t count_b = 0;
    const struct dyld_all_image_infos *all = all_image_infos();
    if (all) {
        const struct dyld_image_info *arr = NULL;
        for (int tries = 0; tries < 50 && !(arr = all->infoArray); tries++) usleep(200);
        if (arr) {
            count_b = all->infoArrayCount;
            for (uint32_t i = 0; i < count_b; i++) {
                const char *p = arr[i].imageFilePath;
                if (p) report_image(out, p, bundle);
                // __interpose in a non-system image = DYLD interposing hook library.
                const struct mach_header_64 *mh = (const struct mach_header_64 *)arr[i].imageLoadAddress;
                if (p && mh && !has_prefix_obf(p, RASP_MISC_SYSTEM) && !has_prefix_obf(p, RASP_MISC_USR_LIB)) {
                    unsigned long sz = 0;
                    if (getsectiondata(mh, "__DATA", "__interpose", &sz) ||
                        getsectiondata(mh, "__DATA_CONST", "__interpose", &sz))
                        rasp_add(out, RASP_F_INTERPOSE_SECTION, 75, "%s (%lu bytes)", p, sz);
                }
            }
        }
    }

    // Source A: public dyld API.
    uint32_t count_a = _dyld_image_count();
    for (uint32_t i = 0; i < count_a; i++) {
        const char *p = _dyld_get_image_name(i);
        if (p) report_image(out, p, bundle);
    }

    if (count_b && count_b > count_a)
        rasp_add(out, RASP_F_IMAGE_LIST_MISMATCH, 90, "dyld_all_image_infos=%u _dyld_image_count=%u", count_b, count_a);

    RASP_END(out, RASP_CHECK_IMAGES);
}

// ---------------------------------------------------------------------------
// Runtime monitor: dyld add-image callback.
// ---------------------------------------------------------------------------
#define MON_RING 32
static os_unfair_lock g_mon_lock = OS_UNFAIR_LOCK_INIT;
static char g_mon_ring[MON_RING][RASP_DETAIL_LEN];
static uint32_t g_mon_head, g_mon_count;
static volatile int g_mon_armed;     // 0 while dyld replays already-loaded images
static int g_mon_installed;

static void on_add_image(const struct mach_header *mh, intptr_t slide) {
    (void)slide;
    if (!__atomic_load_n(&g_mon_armed, __ATOMIC_ACQUIRE)) return;
    const char *name = rasp_image_name_for(mh);
    os_unfair_lock_lock(&g_mon_lock);
    strlcpy(g_mon_ring[g_mon_head], name ? name : "<anonymous image>", RASP_DETAIL_LEN);
    g_mon_head = (g_mon_head + 1) % MON_RING;
    if (g_mon_count < MON_RING) g_mon_count++;
    os_unfair_lock_unlock(&g_mon_lock);
}

void rasp_monitor_install(void) {
    if (__atomic_exchange_n(&g_mon_installed, 1, __ATOMIC_ACQ_REL)) return;
    _dyld_register_func_for_add_image(on_add_image);   // replays existing images synchronously
    __atomic_store_n(&g_mon_armed, 1, __ATOMIC_RELEASE);
}

uint32_t rasp_drain_new_images(char *buf, uint32_t max) {
    if (!buf) return 0;
    os_unfair_lock_lock(&g_mon_lock);
    uint32_t n = g_mon_count < max ? g_mon_count : max;
    uint32_t start = (g_mon_head + MON_RING - g_mon_count) % MON_RING;
    for (uint32_t i = 0; i < n; i++)
        strlcpy(buf + (size_t)i * RASP_DETAIL_LEN, g_mon_ring[(start + i) % MON_RING], RASP_DETAIL_LEN);
    g_mon_count -= n;
    os_unfair_lock_unlock(&g_mon_lock);
    return n;
}
