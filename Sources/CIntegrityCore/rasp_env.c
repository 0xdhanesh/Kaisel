// Environment checks. The environment block is walked directly through
// _NSGetEnviron() and then cross-checked against getenv(): a tweak that hooks
// getenv to hide DYLD_INSERT_LIBRARIES produces a disagreement.

#include "rasp_internal.h"
#include <stdlib.h>
#if __has_include(<crt_externs.h>)
#include <crt_externs.h>
#define RASP_ENVIRON() (_NSGetEnviron() ? *_NSGetEnviron() : NULL)
#else
extern char **environ;
#define RASP_ENVIRON() (environ)
#endif

static void scan_list(rasp_findings_t *out, char **env, uint16_t start, uint16_t count, uint16_t code) {
    char name[RASP_STR_MAX];
    for (uint16_t i = 0; i < count; i++) {
        size_t nl = rasp_obf_decode(start + i, name, sizeof name);
        if (!nl) continue;
        for (char **e = env; e && *e; e++) {
            if (strncmp(*e, name, nl) == 0 && (*e)[nl] == '=') {
                rasp_add(out, code, 95, "%s", name);
                if (getenv(name) == NULL)
                    rasp_add(out, RASP_F_ENV_GETENV_MISMATCH, 95, "getenv hides %s", name);
                break;
            }
        }
        rasp_secure_zero(name, sizeof name);
    }
}

void rasp_check_environment(const rasp_context_t *ctx, rasp_findings_t *out) {
    (void)ctx;
    RASP_BEGIN(out, RASP_CHECK_ENVIRONMENT);
    char **env = RASP_ENVIRON();
    scan_list(out, env, RASP_LIST_ENV_INJECTION_START, RASP_LIST_ENV_INJECTION_COUNT, RASP_F_ENV_INJECTION);
    scan_list(out, env, RASP_LIST_ENV_JB_START, RASP_LIST_ENV_JB_COUNT, RASP_F_ENV_JAILBREAK);
    RASP_END(out, RASP_CHECK_ENVIRONMENT);
}
