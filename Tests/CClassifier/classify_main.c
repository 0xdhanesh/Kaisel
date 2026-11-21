// Host-side driver for the C image classifier (rasp_classify.c).
// Reads tab-separated lines: simulator(0/1) TAB bundle(or -) TAB markers(comma list or -) TAB path
// and prints one class name per line. Driven by run_tests.py; builds on Linux and macOS.
#include "rasp_internal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Stand-in for rasp_rules.c (which needs os_unfair_lock): same matching rule.
static char g_markers[16][RASP_STR_MAX];
static unsigned g_marker_count;

bool rasp_rules_marker_match(const char *path) {
    for (unsigned i = 0; i < g_marker_count; i++)
        if (rasp_strcasestr(path, g_markers[i])) return true;
    return false;
}

static const char *name(rasp_image_class_t c) {
    switch (c) {
    case RASP_IMG_TRUSTED: return "trusted";
    case RASP_IMG_JAILBREAK_INJECTOR: return "jailbreakInjector";
    case RASP_IMG_INSTRUMENTATION: return "instrumentation";
    case RASP_IMG_MARKER: return "marker";
    case RASP_IMG_UNKNOWN_EXTERNAL: return "unknownExternal";
    default: return "unknown";
    }
}

int main(void) {
    char line[4096];
    while (fgets(line, sizeof line, stdin)) {
        line[strcspn(line, "\n")] = 0;
        char *f[4] = {0};
        char *save = NULL, *tok = strtok_r(line, "\t", &save);
        for (int i = 0; i < 4 && tok; i++, tok = strtok_r(NULL, "\t", &save)) f[i] = tok;
        if (!f[2]) { puts("bad-input"); continue; }
        g_marker_count = 0;
        if (strcmp(f[2], "-") != 0) {
            char *s2 = NULL;
            for (char *m = strtok_r(f[2], ",", &s2); m && g_marker_count < 16; m = strtok_r(NULL, ",", &s2))
                snprintf(g_markers[g_marker_count++], RASP_STR_MAX, "%s", m);
        }
        const char *bundle = strcmp(f[1], "-") == 0 ? NULL : f[1];
        const char *path = f[3] ? f[3] : "";
        rasp_image_class_t c = rasp_image_class_ex(path, bundle, f[0][0] == '1');
        printf("%s\t%u\n", name(c), rasp_image_class_code(c));
    }
    return 0;
}
