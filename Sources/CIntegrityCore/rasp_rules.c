// Extra indicators supplied by signed remote rules. Additive only: they are
// consulted *in addition to* the compiled-in obfuscated lists.

#include "rasp_internal.h"
#include <stdlib.h>
#include <os/lock.h>

#define RULES_MAX 256

static os_unfair_lock g_rules_lock = OS_UNFAIR_LOCK_INIT;
static char *g_paths[RULES_MAX];
static uint32_t g_path_count;
static char *g_markers[RULES_MAX];
static uint32_t g_marker_count;

static void replace(char **dst, uint32_t *count, const char *const *src, uint32_t n) {
    for (uint32_t i = 0; i < *count; i++) { free(dst[i]); dst[i] = NULL; }
    *count = 0;
    for (uint32_t i = 0; i < n && i < RULES_MAX; i++) {
        if (!src[i] || !src[i][0] || strlen(src[i]) >= RASP_STR_MAX) continue;
        dst[(*count)++] = strdup(src[i]);
    }
}

void rasp_rules_set(const char *const *paths, uint32_t path_count,
                    const char *const *markers, uint32_t marker_count) {
    os_unfair_lock_lock(&g_rules_lock);
    replace(g_paths, &g_path_count, paths, paths ? path_count : 0);
    replace(g_markers, &g_marker_count, markers, markers ? marker_count : 0);
    os_unfair_lock_unlock(&g_rules_lock);
}

uint32_t rasp_rules_copy_path(uint32_t i, char *out, size_t cap) {
    os_unfair_lock_lock(&g_rules_lock);
    uint32_t n = g_path_count;
    if (i < n) strlcpy(out, g_paths[i], cap);
    os_unfair_lock_unlock(&g_rules_lock);
    return n;
}

bool rasp_rules_marker_match(const char *path) {
    bool hit = false;
    os_unfair_lock_lock(&g_rules_lock);
    for (uint32_t i = 0; i < g_marker_count && !hit; i++)
        hit = rasp_strcasestr(path, g_markers[i]) != NULL;
    os_unfair_lock_unlock(&g_rules_lock);
    return hit;
}
