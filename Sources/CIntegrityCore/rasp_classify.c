// Loaded-image classification (1.4.0).
//
// Pure string logic with no Mach-O or dyld dependency, so the same code runs
// in the image scan, in the runtime image monitor, when the Swift layer
// re-validates stored evidence, and in the host-side C regression tests
// (Tests/CClassifier).
//
// Classes, in order of evaluation:
//   1. instrumentation      exact Frida/Cycript basenames (or structured
//                           frida-agent-* prefixes), or a jailbreak injector
//                           basename found *inside* the app bundle (a re-signed
//                           app with injected tweaks runs on a stock phone).
//                           Runtime risk; never proof of a jailbreak.
//   2. jailbreak injector   exact injector basename outside the app bundle, or
//                           an image under a structured jailbreak root
//                           (/var/jb/, MobileSubstrate DynamicLibraries,
//                           TweakInject, or a RootHide .jbroot-* component).
//                           The only image class that is conclusive.
//   3. trusted              system locations, and images inside the app bundle.
//                           In-bundle code is classified by identity only:
//                           telling the app's own frameworks from code added
//                           by a re-signer needs a build manifest (roadmap).
//   4. marker               a broad substring (built-in list or signed remote
//                           rules) in the basename of an image outside the
//                           system and the bundle. Indicator only.
//   5. unknown external     any other image outside the system and the bundle.
//
// Broad markers are never applied to the full path or to in-bundle images, so
// CraneBank.framework, LibertyFinance.framework or ChoicyAnalytics.framework
// in an app's own bundle are not evidence of anything.

#include "rasp_internal.h"
#ifdef __APPLE__
#include <TargetConditionals.h>
#endif
#include <ctype.h>
#include <string.h>

#define CLS_PATH_MAX 1024

static bool ieq(const char *a, const char *b) {
    for (; *a && *b; a++, b++)
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) return false;
    return *a == *b;
}

static bool istarts(const char *s, const char *pre) {
    for (; *pre; s++, pre++)
        if (!*s || tolower((unsigned char)*s) != tolower((unsigned char)*pre)) return false;
    return true;
}

// /private/var/... -> /var/..., /private/preboot/... -> /preboot/...
// Other /private/... paths are left alone.
const char *rasp_path_normalise(const char *path) {
    if (!path) return NULL;
    if (strncmp(path, "/private/var/", 13) == 0 || strncmp(path, "/private/preboot/", 17) == 0)
        return path + 8;
    return path;
}

// Directory-boundary prefix test on normalised paths: "/var/App.app" contains
// "/var/App.app/x" and itself, but not "/var/App.app2/x".
bool rasp_path_within(const char *path, const char *dir) {
    if (!path || !dir || !*dir) return false;
    const char *p = rasp_path_normalise(path), *d = rasp_path_normalise(dir);
    size_t dl = strlen(d);
    while (dl > 1 && d[dl - 1] == '/') dl--;          // tolerate a trailing slash
    if (strncmp(p, d, dl) != 0) return false;
    return p[dl] == '\0' || p[dl] == '/';
}

// Without a known bundle path (re-validation of stored evidence), an image is
// treated as in-bundle when any path component ends in ".app".
static bool has_app_component(const char *p) {
    const char *c = p;
    while (*c) {
        const char *slash = strchr(c, '/');
        size_t n = slash ? (size_t)(slash - c) : strlen(c);
        if (n > 4 && slash) {          // a directory component, not the file name
            const char *e = c + n - 4;
            if (tolower((unsigned char)e[0]) == '.' && tolower((unsigned char)e[1]) == 'a' &&
                tolower((unsigned char)e[2]) == 'p' && tolower((unsigned char)e[3]) == 'p')
                return true;
        }
        if (!slash) break;
        c = slash + 1;
    }
    return false;
}

static bool in_app(const char *p, const char *bundle) {
    if (bundle && *bundle) return rasp_path_within(p, bundle);
    return has_app_component(p);
}

static const char *base_name(const char *p) {
    const char *b = strrchr(p, '/');
    return b ? b + 1 : p;
}

typedef bool (*str_pred)(const char *subject, const char *item);

static bool list_any(uint16_t start, uint16_t count, const char *subject, str_pred pred) {
    char item[RASP_STR_MAX];
    bool hit = false;
    for (uint16_t i = 0; i < count && !hit; i++) {
        if (!rasp_obf_decode((uint16_t)(start + i), item, sizeof item)) continue;
        hit = pred(subject, item);
        rasp_secure_zero(item, sizeof item);
    }
    return hit;
}

static bool pred_ieq(const char *s, const char *item) { return ieq(s, item); }
static bool pred_istarts(const char *s, const char *item) { return istarts(s, item); }
static bool pred_icontains(const char *s, const char *item) { return rasp_strcasestr(s, item) != NULL; }
static bool pred_within(const char *s, const char *item) { return rasp_path_within(s, item); }

// True when a path component starts with `item` (".jbroot-" matches
// "/.../Application/.jbroot-7351422000C774F3/usr/lib/x.dylib").
static bool pred_component(const char *s, const char *item) {
    for (const char *c = s; c && *c; ) {
        if (istarts(c, item)) return true;
        c = strchr(c, '/');
        if (c) c++;
    }
    return false;
}

rasp_image_class_t rasp_image_class_ex(const char *raw_path, const char *bundle_path, bool simulator) {
    if (!raw_path || !*raw_path) return RASP_IMG_UNKNOWN;
    // Stored details may carry a prefix such as "exec mapping of /x/y.dylib".
    const char *slash = strchr(raw_path, '/');
    if (!slash) return RASP_IMG_UNKNOWN;
    const char *p = rasp_path_normalise(slash);
    const char *base = base_name(p);
    if (!*base || strlen(p) >= CLS_PATH_MAX) return RASP_IMG_UNKNOWN;
    bool inside = in_app(p, bundle_path);

    if (list_any(RASP_LIST_IMAGE_INSTR_BASENAMES_START, RASP_LIST_IMAGE_INSTR_BASENAMES_COUNT, base, pred_ieq) ||
        list_any(RASP_LIST_IMAGE_INSTR_PREFIXES_START, RASP_LIST_IMAGE_INSTR_PREFIXES_COUNT, base, pred_istarts))
        return RASP_IMG_INSTRUMENTATION;

    bool injector = list_any(RASP_LIST_IMAGE_INJECTOR_BASENAMES_START, RASP_LIST_IMAGE_INJECTOR_BASENAMES_COUNT,
                             base, pred_ieq);
    if (injector && inside) return RASP_IMG_INSTRUMENTATION;   // re-signed app with injected tweaks
    if (!inside && (injector ||
        list_any(RASP_LIST_IMAGE_JB_ROOT_PREFIXES_START, RASP_LIST_IMAGE_JB_ROOT_PREFIXES_COUNT, p, pred_within) ||
        list_any(RASP_LIST_IMAGE_JB_ROOT_COMPONENTS_START, RASP_LIST_IMAGE_JB_ROOT_COMPONENTS_COUNT, p, pred_component)))
        return RASP_IMG_JAILBREAK_INJECTOR;

    if (inside) return RASP_IMG_TRUSTED;
    if (simulator) return RASP_IMG_TRUSTED;   // simulator images live under Xcode.app / CoreSimulator
    if (list_any(RASP_LIST_IMAGE_TRUSTED_PREFIXES_START, RASP_LIST_IMAGE_TRUSTED_PREFIXES_COUNT, p, pred_within))
        return RASP_IMG_TRUSTED;

    if (list_any(RASP_LIST_IMAGE_BROAD_MARKERS_START, RASP_LIST_IMAGE_BROAD_MARKERS_COUNT, base, pred_icontains) ||
        rasp_rules_marker_match(base))
        return RASP_IMG_MARKER;
    return RASP_IMG_UNKNOWN_EXTERNAL;
}

rasp_image_class_t rasp_image_class(const char *path, const char *bundle_path) {
#if defined(TARGET_OS_SIMULATOR) && TARGET_OS_SIMULATOR
    return rasp_image_class_ex(path, bundle_path, true);
#else
    return rasp_image_class_ex(path, bundle_path, false);
#endif
}

uint16_t rasp_image_class_code(rasp_image_class_t c) {
    switch (c) {
    case RASP_IMG_JAILBREAK_INJECTOR: return RASP_F_SUSPICIOUS_IMAGE;
    case RASP_IMG_INSTRUMENTATION:    return RASP_F_INSTRUMENTATION_IMAGE;
    case RASP_IMG_MARKER:             return RASP_F_IMAGE_MARKER_MATCH;
    case RASP_IMG_UNKNOWN_EXTERNAL:   return RASP_F_UNEXPECTED_IMAGE_PATH;
    case RASP_IMG_TRUSTED:
    case RASP_IMG_UNKNOWN:
    default:                          return 0;
    }
}

uint8_t rasp_image_class_confidence(rasp_image_class_t c) {
    switch (c) {
    case RASP_IMG_JAILBREAK_INJECTOR: return 95;
    case RASP_IMG_INSTRUMENTATION:    return 95;
    case RASP_IMG_UNKNOWN_EXTERNAL:   return 70;
    case RASP_IMG_MARKER:             return 60;
    default:                          return 0;
    }
}

uint16_t rasp_classify_image(const char *path, const char *bundle_path) {
    return rasp_image_class_code(rasp_image_class(path, bundle_path));
}
