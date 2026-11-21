// Frida and generic dynamic-instrumentation detection.
//
//  1. Thread names: Frida's runtime starts GLib/gum threads ("gum-js-loop",
//     "gmain", "gdbus", "pool-frida") inside the target. Read through
//     thread_info(THREAD_EXTENDED_INFO), not pthread APIs.
//  2. frida-server on loopback: TCP connect to configured ports, then a D-Bus
//     SASL "AUTH" probe. Frida speaks D-Bus and answers "REJECTED ..."; an
//     arbitrary service on the same port will not.
//  3. Memory map: executable regions at the top level of the address space that
//     belong to no dyld image and are not file-backed. Frida's agent is mapped
//     by its own Mach-O loader (no dyld record) and Interceptor allocates r-x
//     trampoline pages. Those regions are then scanned for agent markers.

#include "rasp_internal.h"
#include <dlfcn.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <mach/mach.h>
#include <mach/vm_map.h>
#include <mach-o/dyld.h>

static void check_threads(rasp_findings_t *out) {
    thread_act_array_t threads = NULL;
    mach_msg_type_number_t count = 0;
    if (task_threads(mach_task_self(), &threads, &count) != KERN_SUCCESS) return;

    char marker[64];
    for (mach_msg_type_number_t t = 0; t < count; t++) {
        thread_extended_info_data_t info;
        mach_msg_type_number_t ic = THREAD_EXTENDED_INFO_COUNT;
        if (thread_info(threads[t], THREAD_EXTENDED_INFO, (thread_info_t)&info, &ic) == KERN_SUCCESS &&
            info.pth_name[0]) {
            for (uint16_t i = 0; i < RASP_LIST_FRIDA_THREADS_COUNT; i++) {
                size_t ml = rasp_obf_decode(RASP_LIST_FRIDA_THREADS_START + i, marker, sizeof marker);
                if (!ml) continue;
                // Short generic names must match exactly; longer ones as substrings.
                bool hit = (strcmp(info.pth_name, marker) == 0) ||
                           (ml > 5 && strstr(info.pth_name, marker) != NULL);
                rasp_secure_zero(marker, sizeof marker);
                if (hit) {
                    rasp_add(out, RASP_F_FRIDA_THREAD, 95, "thread \"%.48s\"", info.pth_name);
                    break;
                }
            }
        }
        mach_port_deallocate(mach_task_self(), threads[t]);
    }
    vm_deallocate(mach_task_self(), (vm_address_t)threads, count * sizeof(thread_act_t));
}

static int connect_loopback(uint16_t port, uint32_t timeout_ms) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_len = sizeof sa;
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int rc = connect(fd, (struct sockaddr *)&sa, sizeof sa);
    if (rc != 0 && errno != EINPROGRESS) { close(fd); return -1; }
    if (rc != 0) {
        struct pollfd p = { .fd = fd, .events = POLLOUT };
        if (poll(&p, 1, (int)timeout_ms) != 1) { close(fd); return -1; }
        int soerr = 0; socklen_t sl = sizeof soerr;
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &sl) != 0 || soerr != 0) { close(fd); return -1; }
    }
    return fd;
}

static void check_ports(const rasp_context_t *ctx, rasp_findings_t *out) {
    if (!ctx || !ctx->frida_ports) return;
    uint32_t timeout = ctx->probe_timeout_ms ? ctx->probe_timeout_ms : 150;
    char auth[16], rejected[16];
    size_t al = rasp_obf_decode(RASP_MISC(RASP_MISC_DBUS_AUTH), auth, sizeof auth);
    size_t rl = rasp_obf_decode(RASP_MISC(RASP_MISC_DBUS_REJECTED), rejected, sizeof rejected);

    for (uint32_t i = 0; i < ctx->frida_port_count; i++) {
        uint16_t port = ctx->frida_ports[i];
        int fd = connect_loopback(port, timeout);
        if (fd < 0) continue;
        rasp_add(out, RASP_F_FRIDA_PORT_OPEN, 60, "127.0.0.1:%u accepts connections", port);
        if (al && send(fd, auth, al, 0) == (ssize_t)al) {
            struct pollfd p = { .fd = fd, .events = POLLIN };
            if (poll(&p, 1, (int)timeout) == 1) {
                char reply[64] = {0};
                ssize_t n = recv(fd, reply, sizeof reply - 1, 0);
                if (n >= (ssize_t)rl && rl && memcmp(reply, rejected, rl) == 0)
                    rasp_add(out, RASP_F_FRIDA_DBUS, 97, "D-Bus endpoint on 127.0.0.1:%u", port);
            }
        }
        close(fd);
    }
    rasp_secure_zero(auth, sizeof auth);
    rasp_secure_zero(rejected, sizeof rejected);
}

typedef int (*proc_regionfilename_fn)(int, uint64_t, void *, uint32_t);

static bool region_contains_marker(vm_address_t addr, vm_size_t size) {
    char marker[64];
    bool hit = false;
    const uint8_t *base = (const uint8_t *)addr;
    for (uint16_t m = 0; m < RASP_LIST_FRIDA_MEM_MARKERS_COUNT && !hit; m++) {
        size_t ml = rasp_obf_decode(RASP_LIST_FRIDA_MEM_MARKERS_START + m, marker, sizeof marker);
        if (!ml || ml > size) continue;
        for (vm_size_t i = 0; i + ml <= size; i++)
            if (base[i] == (uint8_t)marker[0] && memcmp(base + i, marker, ml) == 0) { hit = true; break; }
        rasp_secure_zero(marker, sizeof marker);
    }
    return hit;
}

// Some executable regions are legitimate copies of image pages that are not
// in any image's address range: libobjc-trampolines remaps its trampoline
// page for imp_implementationWithBlock(), and other runtimes do similar
// remaps. If the region's first page is byte-identical to a page of a loaded
// image's __TEXT, it is a remap of signed code, not injected code.
// Only images outside the dyld shared cache, plus libobjc-trampolines, are
// compared, which keeps the cost small.
#define RASP_MH_DYLIB_IN_CACHE 0x80000000u

typedef struct { uintptr_t lo; uint64_t size; intptr_t slide; } text_ctx_t;
static bool text_visitor(const struct load_command *lc, void *c) {
    if (lc->cmd != LC_SEGMENT_64) return true;
    const struct segment_command_64 *seg = (const struct segment_command_64 *)lc;
    if (strcmp(seg->segname, SEG_TEXT) != 0) return true;
    text_ctx_t *t = (text_ctx_t *)c;
    t->lo = (uintptr_t)(seg->vmaddr + t->slide);
    t->size = seg->vmsize;
    return false;
}

static bool is_remap_of_image_text(vm_address_t addr, vm_size_t size) {
    const vm_size_t pg = vm_page_size;
    if (size < pg) return false;
    uint32_t n = _dyld_image_count();
    for (uint32_t i = 0; i < n; i++) {
        const struct mach_header_64 *mh = (const struct mach_header_64 *)_dyld_get_image_header(i);
        const char *name = _dyld_get_image_name(i);
        if (!mh || !name) continue;
        bool in_cache = (mh->flags & RASP_MH_DYLIB_IN_CACHE) != 0;
        if (in_cache && !strstr(name, "libobjc-trampolines")) continue;
        text_ctx_t t = { .slide = _dyld_get_image_vmaddr_slide(i) };
        rasp_for_each_load_command(mh, text_visitor, &t);
        if (!t.lo || t.size > 64u * 1024 * 1024) continue;
        for (uint64_t off = 0; off + pg <= t.size; off += pg)
            if (memcmp((const void *)addr, (const void *)(t.lo + off), pg) == 0) return true;
    }
    return false;
}

static void check_memory(const rasp_context_t *ctx, rasp_findings_t *out) {
    proc_regionfilename_fn regionfilename =
        (proc_regionfilename_fn)dlsym(RTLD_DEFAULT, "proc_regionfilename");
    int pid = rasp_raw_getpid();
    vm_address_t addr = 0;
    uint32_t reported = 0;
    const vm_size_t kScanCap = 16u * 1024 * 1024;

    for (;;) {
        vm_size_t size = 0;
        natural_t depth = 0;
        struct vm_region_submap_info_64 info;
        mach_msg_type_number_t cnt = VM_REGION_SUBMAP_INFO_COUNT_64;
        kern_return_t kr = vm_region_recurse_64(mach_task_self(), &addr, &size, &depth,
                                                (vm_region_recurse_info_t)&info, &cnt);
        if (kr != KERN_SUCCESS) break;

        // Do not descend into submaps: the dyld shared cache lives there and
        // contains stub islands that belong to no individual image.
        if (!info.is_submap && (info.protection & VM_PROT_EXECUTE)) {
            // Skip the commpage window.
            bool commpage = addr >= 0x0000000FFFFF0000ull && addr < 0x0000001000000000ull;
            if (!commpage && !rasp_addr_in_any_image((uintptr_t)addr)) {
                char file[RASP_DETAIL_LEN] = {0};
                int fl = regionfilename ? regionfilename(pid, (uint64_t)addr, file, sizeof file - 1) : 0;
                if (fl > 0) {
                    // File-backed remap (e.g. libobjc-trampolines). Only report
                    // if the backing file itself is suspicious.
                    uint16_t c = rasp_classify_image(file, ctx ? ctx->bundle_path : NULL);
                    if (c == RASP_F_SUSPICIOUS_IMAGE)
                        rasp_add(out, RASP_F_SUSPICIOUS_IMAGE, 90, "exec mapping of %s", file);
                } else if (reported < 8 && (info.protection & VM_PROT_READ) && is_remap_of_image_text(addr, size)) {
                    // Remapped signed code (e.g. objc block trampolines): benign.
                } else if (reported < 8) {
                    reported++;
                    bool marker = (info.protection & VM_PROT_READ) && size <= kScanCap && region_contains_marker(addr, size);
                    // On its own this is a weak signal: runtimes and future OS
                    // releases can legitimately create such regions. It becomes
                    // strong only with an agent marker or other instrumentation
                    // evidence in the same report.
                    rasp_add(out, RASP_F_ANON_EXEC_MEMORY, 55,
                             "anonymous r%sx region 0x%lx+0x%lx tag=%u share=%u maxprot=0x%x",
                             (info.protection & VM_PROT_WRITE) ? "w" : "-", (unsigned long)addr, (unsigned long)size,
                             (unsigned)info.user_tag, (unsigned)info.share_mode, (unsigned)info.max_protection);
                    if (marker)
                        rasp_add(out, RASP_F_FRIDA_MEMORY_MARKER, 97, "agent marker at 0x%lx", (unsigned long)addr);
                }
            }
        }
        if (addr + size < addr) break;  // wrapped
        addr += size;
    }
}

void rasp_check_frida(const rasp_context_t *ctx, rasp_findings_t *out) {
    RASP_BEGIN(out, RASP_CHECK_FRIDA);
    check_threads(out);
    check_ports(ctx, out);
    if (!ctx || ctx->scan_memory) check_memory(ctx, out);
    RASP_END(out, RASP_CHECK_FRIDA);
}
