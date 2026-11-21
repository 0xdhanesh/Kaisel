// Debugger and developer-mode checks.

#include "rasp_internal.h"
#include <stdio.h>
#include <sys/sysctl.h>
#include <mach/mach.h>

#ifndef P_TRACED
#define P_TRACED 0x00000800
#endif
#define RASP_CS_OPS_STATUS 0
#define RASP_CS_DEBUGGED   0x10000000u
#define RASP_PT_DENY_ATTACH 31

static const exception_mask_t kDebugMasks =
    EXC_MASK_BREAKPOINT | EXC_MASK_BAD_ACCESS | EXC_MASK_BAD_INSTRUCTION |
    EXC_MASK_SOFTWARE | EXC_MASK_ARITHMETIC;

int32_t rasp_exception_port_count(void);
int32_t rasp_exception_port_count(void) {
    exception_mask_t masks[EXC_TYPES_COUNT];
    mach_port_t ports[EXC_TYPES_COUNT];
    exception_behavior_t behaviours[EXC_TYPES_COUNT];
    thread_state_flavor_t flavours[EXC_TYPES_COUNT];
    mach_msg_type_number_t count = EXC_TYPES_COUNT;
    if (task_get_exception_ports(mach_task_self(), kDebugMasks, masks, &count, ports, behaviours, flavours) != KERN_SUCCESS)
        return -1;
    int32_t n = 0;
    for (mach_msg_type_number_t i = 0; i < count; i++) {
        if (MACH_PORT_VALID(ports[i])) {
            n++;
            mach_port_deallocate(mach_task_self(), ports[i]);
        }
    }
    return n;
}

void rasp_check_debugger(const rasp_context_t *ctx, rasp_findings_t *out) {
    (void)ctx;
    RASP_BEGIN(out, RASP_CHECK_DEBUGGER);
    int pid = rasp_raw_getpid();

    // 1. P_TRACED via raw __sysctl (libc sysctl is a favourite hook target).
    {
        int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, pid };
        struct kinfo_proc kp;
        size_t len = sizeof kp;
        memset(&kp, 0, sizeof kp);
        int err = 0;
        if (rasp_raw_sysctl(mib, 4, &kp, &len, NULL, 0, &err) == 0 && (kp.kp_proc.p_flag & P_TRACED))
            rasp_add(out, RASP_F_PTRACED, 95, "P_TRACED set (p_flag 0x%x)", (unsigned)kp.kp_proc.p_flag);
    }

    // 2. Code-signing status: the kernel sets CS_DEBUGGED once a debugger has
    //    been attached or invalid pages have been allowed (e.g. by a debugger
    //    writing breakpoints). It is sticky for the life of the process.
    {
        uint32_t flags = 0; int err = 0;
        if (rasp_raw_csops(pid, RASP_CS_OPS_STATUS, &flags, sizeof flags, &err) == 0 && (flags & RASP_CS_DEBUGGED))
            rasp_add(out, RASP_F_CS_DEBUGGED, 85, "CS_DEBUGGED (cs_flags 0x%08x)", flags);
    }

    // 3. Task-level exception ports. LLDB/debugserver and Frida register these;
    //    so do some crash reporters, hence medium confidence and a Swift-side
    //    allowance (Configuration.allowedExceptionPorts).
    {
        int32_t n = rasp_exception_port_count();
        if (n > 0) rasp_add(out, RASP_F_EXCEPTION_PORTS, 60, "%d task exception port(s) set", n);
    }

    // 4. Parent process. Apps are spawned by launchd (pid 1). A debugger or
    //    `frida -f` spawn makes the parent debugserver/frida-server.
    {
        int ppid = rasp_raw_getppid();
        if (ppid != 1) rasp_add(out, RASP_F_PPID_UNEXPECTED, 70, "ppid %d", ppid);
    }
    RASP_END(out, RASP_CHECK_DEBUGGER);
}

int rasp_deny_debugger_attach(void) {
    int err = 0;
    long r = rasp_sys4(RASP_SYS_ptrace, RASP_PT_DENY_ATTACH, 0, 0, 0, &err);
    return r == 0 ? 0 : err;
}

// ---------------------------------------------------------------------------
// Developer Mode (iOS 16+).
// There is no public API. Two observable proxies:
//   * sysctl "security.mac.amfi.developer_mode_status" (int). Readable from the
//     app sandbox on the iOS versions we have seen; may become unavailable.
//   * A mounted Developer Disk Image exposes debugserver at /Developer (<=16)
//     or /System/Developer (17+, personalised DDI).
// A third, inferential proxy (get-task-allow set and running on 16+ implies
// Developer Mode is on) is applied in Swift.
// ---------------------------------------------------------------------------
int32_t rasp_devmode_sysctl(void);
int32_t rasp_devmode_sysctl(void) {
    char name[64];
    if (!rasp_obf_decode(RASP_MISC(RASP_MISC_DEVMODE_SYSCTL), name, sizeof name)) return -1;
    int mib[CTL_MAXNAME];
    size_t miblen = CTL_MAXNAME;
    int rc = sysctlnametomib(name, mib, &miblen);
    rasp_secure_zero(name, sizeof name);
    if (rc != 0) return -1;
    int32_t value = -1;
    size_t len = sizeof value;
    int err = 0;
    if (rasp_raw_sysctl(mib, (unsigned)miblen, &value, &len, NULL, 0, &err) != 0) return -1;
    return value ? 1 : 0;
}

void rasp_check_devmode(const rasp_context_t *ctx, rasp_findings_t *out) {
    (void)ctx;
    RASP_BEGIN(out, RASP_CHECK_DEVMODE);
    int32_t dm = rasp_devmode_sysctl();
    if (dm == 1) rasp_add(out, RASP_F_DEVMODE_ENABLED, 95, "amfi developer_mode_status=1");

    char path[RASP_STR_MAX];
    for (uint16_t i = 0; i < RASP_LIST_DDI_PATHS_COUNT; i++) {
        if (!rasp_obf_decode(RASP_LIST_DDI_PATHS_START + i, path, sizeof path)) continue;
        struct stat st; int err = 0;
        if (rasp_raw_lstat(path, &st, &err) == 0)
            rasp_add(out, RASP_F_DDI_MOUNTED, 85, "%s", path);
        rasp_secure_zero(path, sizeof path);
    }
    RASP_END(out, RASP_CHECK_DEVMODE);
}
