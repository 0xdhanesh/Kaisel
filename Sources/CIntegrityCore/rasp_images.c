// Loaded-image enumeration and injection detection.
//
// Two independent sources are compared:
//   A. the public dyld API (_dyld_image_count / _dyld_get_image_name), which
//      hiding tweaks commonly hook to drop their own entries;
//   B. dyld's own `dyld_all_image_infos` structure, located through
//      task_info(TASK_DYLD_INFO) and read directly from memory.
// If B lists more images than A, someone is filtering the dyld API.
// Every image path is classified by rasp_image_class() (rasp_classify.c):
// exact identities for injectors and instrumentation, allow-listed locations
// for system and bundle code, and broad markers only as indicators.

#include "rasp_internal.h"
#include <TargetConditionals.h>
#include <dlfcn.h>
#include <mach/mach.h>
#include <mach-o/dyld.h>
#include <mach-o/dyld_images.h>
#include <mach-o/getsect.h>
#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <fcntl.h>
#include <string.h>
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

// Image classification lives in rasp_classify.c (rasp_image_class).

static bool already_reported(const rasp_findings_t *out, uint16_t code, const char *detail) {
    for (uint32_t i = 0; i < out->count; i++)
        if (out->items[i].code == code && strncmp(out->items[i].detail, detail, RASP_DETAIL_LEN - 1) == 0)
            return true;
    return false;
}

// Detail is the image path. A path longer than the detail buffer keeps its
// tail, so the basename (what re-validation needs) survives truncation.
void rasp_image_detail(char d[RASP_DETAIL_LEN], const char *path) {
    size_t n = strlen(path);
    if (n < RASP_DETAIL_LEN) snprintf(d, RASP_DETAIL_LEN, "%s", path);
    else snprintf(d, RASP_DETAIL_LEN, "...%s", path + n - (RASP_DETAIL_LEN - 4));
}

static void report_image(rasp_findings_t *out, const char *path, const char *bundle) {
    rasp_image_class_t cls = rasp_image_class(path, bundle);
    uint16_t c = rasp_image_class_code(cls);
    if (!c) return;
    char d[RASP_DETAIL_LEN];
    rasp_image_detail(d, path);
    if (!already_reported(out, c, d))
        rasp_add(out, c, rasp_image_class_confidence(cls), "%s", d);
}

// ---------------------------------------------------------------------------
// dyld integrity
//
// Per-app hiding (RootHide's Blacklist, Choicy, Shadow) keeps tweaks out of the
// app, but a jailbreak that patches dyld affects every process it spawns.
//
// Only sound when dyld runs from /usr/lib/dyld itself. On iOS 16 and later
// dyld usually re-executes from its copy inside the dyld shared cache
// (MH_DYLIB_IN_CACHE): same LC_UUID, different code layout, so a byte compare
// with the file is meaningless. That case is skipped (it caused a false
// "Jailbroken" on a stock iPhone18,1 / iOS 27.2.1 in 1.3.0). A large diff is
// also treated as a layout mismatch, not a hook. Indicator only, never
// conclusive.
// ---------------------------------------------------------------------------
#if defined(__aarch64__)
typedef struct { const struct section_64 *text; uint64_t text_vmaddr; const uint8_t *uuid; } dyld_layout_t;

static bool dyld_lc_visit(const struct load_command *lc, void *vctx) {
    dyld_layout_t *L = (dyld_layout_t *)vctx;
    if (lc->cmd == LC_UUID) L->uuid = ((const struct uuid_command *)lc)->uuid;
    if (lc->cmd == LC_SEGMENT_64) {
        const struct segment_command_64 *seg = (const struct segment_command_64 *)lc;
        if (strncmp(seg->segname, "__TEXT", 16) == 0) {
            L->text_vmaddr = seg->vmaddr;
            const struct section_64 *s = (const struct section_64 *)(seg + 1);
            for (uint32_t i = 0; i < seg->nsects; i++)
                if (strncmp(s[i].sectname, "__text", 16) == 0) L->text = &s[i];
        }
    }
    return true;
}

static uint32_t be32(uint32_t v) { return __builtin_bswap32(v); }

// Finds the slice of `fd` matching cputype/subtype and its LC_UUID.
static bool dyld_file_slice(int fd, const struct mach_header_64 *mem, uint64_t *slice, uint8_t uuid[16]) {
    uint8_t hdr[4096]; int err = 0;
    if (rasp_raw_pread(fd, hdr, sizeof hdr, 0, &err) < (long)sizeof(struct mach_header_64)) return false;
    *slice = 0;
    uint32_t magic; memcpy(&magic, hdr, 4);
    if (magic == FAT_CIGAM) {
        uint32_t n = be32(((const struct fat_header *)hdr)->nfat_arch);
        const struct fat_arch *fa = (const struct fat_arch *)(hdr + sizeof(struct fat_header));
        bool found = false;
        for (uint32_t i = 0; i < n && (const uint8_t *)(fa + i + 1) <= hdr + sizeof hdr; i++) {
            if ((cpu_type_t)be32((uint32_t)fa[i].cputype) == mem->cputype &&
                ((cpu_subtype_t)be32((uint32_t)fa[i].cpusubtype) & ~CPU_SUBTYPE_MASK) ==
                    (mem->cpusubtype & ~CPU_SUBTYPE_MASK)) {
                *slice = be32(fa[i].offset); found = true; break;
            }
        }
        if (!found) return false;
        if (rasp_raw_pread(fd, hdr, sizeof hdr, (int64_t)*slice, &err) < (long)sizeof(struct mach_header_64)) return false;
    }
    const struct mach_header_64 *fh = (const struct mach_header_64 *)hdr;
    if (fh->magic != MH_MAGIC_64 || fh->sizeofcmds > sizeof hdr - sizeof *fh) return false;
    const uint8_t *p = (const uint8_t *)(fh + 1);
    for (uint32_t i = 0; i < fh->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)p;
        if (lc->cmdsize < sizeof *lc || p + lc->cmdsize > hdr + sizeof hdr) return false;
        if (lc->cmd == LC_UUID) { memcpy(uuid, ((const struct uuid_command *)lc)->uuid, 16); return true; }
        p += lc->cmdsize;
    }
    return false;
}

static void check_dyld(rasp_findings_t *out, const struct dyld_all_image_infos *all) {
    const struct mach_header_64 *mh = (const struct mach_header_64 *)all->dyldImageLoadAddress;
    if (!mh || mh->magic != MH_MAGIC_64) return;
    char path[32];
    if (!rasp_obf_decode(RASP_MISC(RASP_MISC_DYLD), path, sizeof path)) return;

    // dyld_all_image_infos v15+ records the file dyld was loaded from.
    // dyld running from the shared cache: nothing on disk to compare against.
    if (mh->flags & 0x80000000u /* MH_DYLIB_IN_CACHE */) goto done;

    // Cryptex and /System copies are Apple-signed locations, not evidence.
    if (all->version >= 15 && all->dyldPath && all->dyldPath[0] == '/' && strcmp(all->dyldPath, path) != 0 &&
        !has_prefix_obf(all->dyldPath, RASP_MISC_CRYPTEXES) && !has_prefix_obf(all->dyldPath, RASP_MISC_SYSTEM) &&
        !has_prefix_obf(all->dyldPath, RASP_MISC_USR_LIB))
        rasp_add(out, RASP_F_DYLD_MODIFIED, 60, "dyld loaded from %.160s", all->dyldPath);

    dyld_layout_t L = { NULL, 0, NULL };
    rasp_for_each_load_command(mh, dyld_lc_visit, &L);
    if (!L.text || !L.uuid || L.text->size == 0 || L.text->size > (64u << 20)) goto done;

    int err = 0;
    int fd = rasp_raw_open(path, O_RDONLY, 0, &err);
    if (fd < 0) goto done;                         // unreadable: no evidence either way
    uint64_t slice = 0; uint8_t fuuid[16];
    // A different build on disk (e.g. an OS that ships dyld elsewhere) is not
    // evidence; only compare bytes when the UUIDs match.
    if (dyld_file_slice(fd, mh, &slice, fuuid) && memcmp(fuuid, L.uuid, 16) == 0) {
        const uint8_t *mem = (const uint8_t *)mh + (L.text->addr - L.text_vmaddr);
        uint8_t buf[4096];
        uint64_t size = L.text->size, first = UINT64_MAX;
        uint32_t diff = 0, brk = 0;
        for (uint64_t off = 0; off < size; off += sizeof buf) {
            size_t n = (size_t)((size - off) < sizeof buf ? (size - off) : sizeof buf);
            if (rasp_raw_pread(fd, buf, n, (int64_t)(slice + L.text->offset + off), &err) != (long)n) { diff = 0; break; }
            if (memcmp(buf, mem + off, n) == 0) continue;
            for (size_t w = 0; w + 4 <= n; w += 4) {
                uint32_t a, b;
                memcpy(&a, buf + w, 4); memcpy(&b, mem + off + w, 4);
                if (a == b) continue;
                if (first == UINT64_MAX) first = off + w;
                diff++;
                if ((b & 0xFFE0001Fu) == 0xD4200000u) brk++;
            }
        }
        if (diff && diff == brk && brk <= 8)
            // A debugger (lldb sets breakpoints inside dyld for image events).
            rasp_add(out, RASP_F_BREAKPOINT_INSN, 80, "dyld: %u software breakpoint(s), first at +0x%llx",
                     brk, (unsigned long long)first);
        else if (diff && diff <= 64)
            // A handful of rewritten instructions looks like hooks. Hundreds or
            // thousands means we are not comparing the same code: no evidence.
            rasp_add(out, RASP_F_DYLD_MODIFIED, 70, "dyld __text differs from disk: %u words, first at +0x%llx",
                     diff, (unsigned long long)first);
    }
    rasp_raw_close(fd);
done:
    rasp_secure_zero(path, sizeof path);
}
#endif

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

#if defined(__aarch64__)
    if (all) check_dyld(out, all);
#endif
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
