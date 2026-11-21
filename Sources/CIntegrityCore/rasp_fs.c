// Filesystem, sandbox and canary checks.
//
// Not a path grep: every lookup is performed twice, once through a force-inlined
// raw `svc #0x80` and once through libc, and the *disagreement* is itself a
// signal (hiding tweaks such as Shadow/ABypass/vnodebypass-style libc hooks make
// libc lie while the raw syscall tells the truth). EPERM/EACCES is treated as an
// existence oracle only after calibrating the parent directory with a random
// non-existent sibling, which removes false positives from opaque directories.

#include "rasp_internal.h"
#include <dlfcn.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>

// ---------------------------------------------------------------------------
// Parent-directory calibration cache for the errno oracle.
// ---------------------------------------------------------------------------
typedef struct { char dir[RASP_STR_MAX]; int probe_errno; } calib_t;
#define CALIB_MAX 24

static int calibrate_parent(calib_t *cache, int *n, const char *path) {
    char dir[RASP_STR_MAX];
    strlcpy(dir, path, sizeof dir);
    char *slash = strrchr(dir, '/');
    if (!slash) return -1;
    if (slash == dir) slash[1] = '\0'; else *slash = '\0';

    for (int i = 0; i < *n; i++)
        if (strcmp(cache[i].dir, dir) == 0) return cache[i].probe_errno;

    char token[17], probe[RASP_STR_MAX];
    rasp_random_token(token);
    snprintf(probe, sizeof probe, "%s%s.%s", dir, (dir[1] == '\0') ? "" : "/", token);
    struct stat st; int err = 0;
    if (rasp_raw_lstat(probe, &st, &err) == 0) err = 0;   // random name exists?! treat as uninformative
    if (*n < CALIB_MAX) {
        strlcpy(cache[*n].dir, dir, sizeof cache[*n].dir);
        cache[*n].probe_errno = err;
        (*n)++;
    }
    return err;
}

static void probe_path(rasp_findings_t *out, const char *path, calib_t *cache, int *ncache) {
    struct stat st; int raw_err = 0;
    int raw = rasp_raw_lstat(path, &st, &raw_err);

    errno = 0;
    struct stat st2;
    int lib = lstat(path, &st2);
    int lib_err = (lib == 0) ? 0 : errno;

    if (raw == 0) {
        rasp_add(out, RASP_F_JB_PATH_PRESENT, 95, "%s", path);
        if (lib != 0 && lib_err == ENOENT)
            rasp_add(out, RASP_F_LIBC_SYSCALL_MISMATCH, 95, "lstat hidden: %s", path);
    } else if (raw_err == EPERM || raw_err == EACCES) {
        int probe = calibrate_parent(cache, ncache, path);
        if (probe == ENOENT) {
            rasp_add(out, RASP_F_JB_PATH_ERRNO_ORACLE, 75, "%s (errno %d)", path, raw_err);
            if (lib_err == ENOENT)
                rasp_add(out, RASP_F_LIBC_SYSCALL_MISMATCH, 85, "errno masked: %s", path);
        }
    } else if (raw_err == ENOENT && lib == 0) {
        // libc claims existence the kernel denies: a hook returning fake data.
        rasp_add(out, RASP_F_LIBC_SYSCALL_MISMATCH, 70, "libc phantom: %s", path);
    }
}

void rasp_check_filesystem(const rasp_context_t *ctx, rasp_findings_t *out) {
    (void)ctx;
    RASP_BEGIN(out, RASP_CHECK_FILESYSTEM);
    char path[RASP_STR_MAX];
    calib_t cache[CALIB_MAX];
    int ncache = 0;

    // 1. Artefact paths, raw vs libc, plus errno oracle. Compiled-in list
    //    first, then any extra paths from signed remote rules.
    for (uint16_t i = 0; i < RASP_LIST_JB_PATHS_COUNT; i++) {
        if (!rasp_obf_decode(RASP_LIST_JB_PATHS_START + i, path, sizeof path)) continue;
        probe_path(out, path, cache, &ncache);
        rasp_secure_zero(path, sizeof path);
    }
    for (uint32_t i = 0, n = 1; i < n; i++) {
        n = rasp_rules_copy_path(i, path, sizeof path);
        if (i >= n) break;
        probe_path(out, path, cache, &ncache);
        rasp_secure_zero(path, sizeof path);
    }

    // 2. Rootless jailbreak root: /var/jb -> /private/preboot/<hash>/<jb>-<rand>/procursus
    {
        char jb[32], target[RASP_STR_MAX];
        if (!rasp_obf_decode(RASP_MISC(RASP_MISC_VAR_JB), jb, sizeof jb)) jb[0] = '\0';
        if (jb[0]) {
            int err = 0;
            long n = rasp_raw_readlink(jb, target, sizeof target - 1, &err);
            if (n > 0) {
                target[n] = '\0';
                rasp_add(out, RASP_F_JB_ROOT_SYMLINK, 99, "%s -> %s", jb, target);
            }
        }
        rasp_secure_zero(jb, sizeof jb);
    }

    // 3. Rootful "stashing": system directories replaced with symlinks.
    for (uint16_t i = 0; i < RASP_LIST_SYMLINK_DIRS_COUNT; i++) {
        if (!rasp_obf_decode(RASP_LIST_SYMLINK_DIRS_START + i, path, sizeof path)) continue;
        struct stat st; int err = 0;
        if (rasp_raw_lstat(path, &st, &err) == 0 && S_ISLNK(st.st_mode))
            rasp_add(out, RASP_F_SYMLINKED_SYSTEM_DIR, 90, "%s", path);
        rasp_secure_zero(path, sizeof path);
    }

    // 4. Signed System Volume: since iOS 15 the root FS is a sealed, read-only
    //    APFS snapshot ("com.apple.os.update-<hash>@/dev/diskXsY"). Rootful
    //    jailbreaks remount it read-write or boot from a non-sealed snapshot/fakefs.
    {
        struct statfs sfs; int err = 0;
        if (rasp_raw_statfs("/", &sfs, &err) == 0) {
            if (!(sfs.f_flags & MNT_RDONLY))
                rasp_add(out, RASP_F_ROOT_WRITABLE, 90, "/ mounted rw (flags 0x%x)", (unsigned)sfs.f_flags);
            char prefix[64];
            size_t pl = rasp_obf_decode(RASP_MISC(RASP_MISC_SNAPSHOT_PREFIX), prefix, sizeof prefix);
            if (pl && strncmp(sfs.f_mntfromname, prefix, pl) != 0)
                rasp_add(out, RASP_F_ROOT_NOT_SEALED, 60, "/ from %.96s", sfs.f_mntfromname);
            rasp_secure_zero(prefix, sizeof prefix);
        }
    }
    RASP_END(out, RASP_CHECK_FILESYSTEM);
}

// ---------------------------------------------------------------------------
// Sandbox integrity: a stock App Sandbox forbids writes outside the container,
// forbids fork(), and denies reading other domains' preference directories.
// ---------------------------------------------------------------------------
void rasp_check_sandbox(const rasp_context_t *ctx, rasp_findings_t *out) {
    RASP_BEGIN(out, RASP_CHECK_SANDBOX);
    char root[32], probe[RASP_STR_MAX], token[17];

    // Write outside the container.
    if (rasp_obf_decode(RASP_MISC(RASP_MISC_PRIVATE), root, sizeof root)) {
        rasp_random_token(token);
        snprintf(probe, sizeof probe, "%s.%s", root, token);
        int err = 0;
        int fd = rasp_raw_open(probe, O_CREAT | O_EXCL | O_WRONLY, 0600, &err);
        if (fd >= 0) {
            rasp_raw_close(fd);
            rasp_raw_unlink(probe, &err);
            rasp_add(out, RASP_F_SANDBOX_WRITE, 98, "created %s", probe);
        }
    }

    // Read another domain's directory.
    if (rasp_obf_decode(RASP_MISC(RASP_MISC_PREFS_DIR), probe, sizeof probe)) {
        int err = 0;
        int fd = rasp_raw_open(probe, O_RDONLY | O_DIRECTORY, 0, &err);
        if (fd >= 0) {
            rasp_raw_close(fd);
            rasp_add(out, RASP_F_SANDBOX_READ, 60, "opened %s", probe);
        }
    }

    // fork(): resolved dynamically so the binary has no fork import. The child
    // performs nothing but a raw exit syscall.
    if (ctx && ctx->allow_fork_probe) {
        char name[16];
        if (rasp_obf_decode(RASP_MISC(RASP_MISC_FORK), name, sizeof name)) {
            pid_t (*fk)(void) = (pid_t (*)(void))dlsym(RTLD_DEFAULT, name);
            if (fk) {
                pid_t pid = fk();
                if (pid == 0) {
                    int e; rasp_sys1(1 /* SYS_exit */, 0, &e);
                    _exit(0);
                } else if (pid > 0) {
                    int status;
                    waitpid(pid, &status, 0);
                    rasp_add(out, RASP_F_SANDBOX_FORK, 95, "fork() returned %d", (int)pid);
                }
            }
        }
        rasp_secure_zero(name, sizeof name);
    }
    rasp_secure_zero(root, sizeof root);
    rasp_secure_zero(probe, sizeof probe);
    RASP_END(out, RASP_CHECK_SANDBOX);
}

// ---------------------------------------------------------------------------
// Canary: positive and negative controls. If a blanket hook makes *everything*
// look absent (or present), the controls fail and we say so instead of
// silently reporting "clean".
// ---------------------------------------------------------------------------
void rasp_check_canary(const rasp_context_t *ctx, rasp_findings_t *out) {
    RASP_BEGIN(out, RASP_CHECK_CANARY);
    struct stat st; int err = 0;

    if (ctx && ctx->executable_path) {
        int raw = rasp_raw_lstat(ctx->executable_path, &st, &err);
        errno = 0;
        int lib = lstat(ctx->executable_path, &st);
        if (raw != 0)
            rasp_add(out, RASP_F_CANARY_FAILED, 70, "raw lstat(own executable) errno %d", err);
        if (lib != 0)
            rasp_add(out, RASP_F_CANARY_FAILED, 85, "libc lstat(own executable) errno %d", errno);
    }

    if (ctx && ctx->container_tmp) {
        char token[17], probe[RASP_STR_MAX];
        rasp_random_token(token);
        snprintf(probe, sizeof probe, "%s/.%s", ctx->container_tmp, token);
        int raw = rasp_raw_lstat(probe, &st, &err);
        int raw_err = err;
        errno = 0;
        int lib = lstat(probe, &st);
        if (raw == 0 || raw_err != ENOENT)
            rasp_add(out, RASP_F_CANARY_FAILED, 70, "raw negative control errno %d", raw_err);
        if (lib == 0)
            rasp_add(out, RASP_F_CANARY_FAILED, 85, "libc reports a random path exists");
    }
    RASP_END(out, RASP_CHECK_CANARY);
}
