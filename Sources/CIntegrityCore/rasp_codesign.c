// Code-signing, entitlement and binary-integrity checks, plus fact collection.

#include "rasp_internal.h"
#include <stdio.h>
#include <CommonCrypto/CommonDigest.h>
#include <mach-o/getsect.h>

#define RASP_CS_OPS_STATUS               0
#define RASP_CS_OPS_ENTITLEMENTS_BLOB    7
#define RASP_CS_OPS_DER_ENTITLEMENTS_BLOB 16
#define RASP_CS_VALID          0x00000001u
#define RASP_CS_GET_TASK_ALLOW 0x00000004u

int32_t rasp_exception_port_count(void);
int32_t rasp_devmode_sysctl(void);

// csops entitlement blobs are prefixed with an 8-byte big-endian header.
static uint8_t g_ent_buf[64 * 1024];

static size_t read_entitlements(int pid) {
    int err = 0;
    memset(g_ent_buf, 0, sizeof g_ent_buf);
    if (rasp_raw_csops(pid, RASP_CS_OPS_ENTITLEMENTS_BLOB, g_ent_buf, sizeof g_ent_buf, &err) == 0) {
        uint32_t len = ((uint32_t)g_ent_buf[4] << 24) | ((uint32_t)g_ent_buf[5] << 16) |
                       ((uint32_t)g_ent_buf[6] << 8) | g_ent_buf[7];
        if (len > 8 && len <= sizeof g_ent_buf) return len;
    }
    memset(g_ent_buf, 0, sizeof g_ent_buf);
    if (rasp_raw_csops(pid, RASP_CS_OPS_DER_ENTITLEMENTS_BLOB, g_ent_buf, sizeof g_ent_buf, &err) == 0) {
        uint32_t len = ((uint32_t)g_ent_buf[4] << 24) | ((uint32_t)g_ent_buf[5] << 16) |
                       ((uint32_t)g_ent_buf[6] << 8) | g_ent_buf[7];
        if (len > 8 && len <= sizeof g_ent_buf) return len;
    }
    return 0;
}

static bool mem_contains(const uint8_t *hay, size_t hl, const char *needle) {
    size_t nl = strlen(needle);
    if (nl == 0 || nl > hl) return false;
    for (size_t i = 0; i + nl <= hl; i++)
        if (hay[i] == (uint8_t)needle[0] && memcmp(hay + i, needle, nl) == 0) return true;
    return false;
}

void rasp_check_codesign(const rasp_context_t *ctx, rasp_findings_t *out) {
    (void)ctx;
    RASP_BEGIN(out, RASP_CHECK_CODESIGN);
    int pid = rasp_raw_getpid();
    uint32_t flags = 0; int err = 0;
    if (rasp_raw_csops(pid, RASP_CS_OPS_STATUS, &flags, sizeof flags, &err) == 0) {
        if (!(flags & RASP_CS_VALID))
            rasp_add(out, RASP_F_CS_INVALID, 90, "CS_VALID clear (cs_flags 0x%08x)", flags);
        if (flags & RASP_CS_GET_TASK_ALLOW)
            rasp_add(out, RASP_F_GET_TASK_ALLOW, 90, "get-task-allow (cs_flags 0x%08x)", flags);
    }

    size_t len = read_entitlements(pid);
    if (len) {
        char key[RASP_STR_MAX];
        for (uint16_t i = 0; i < RASP_LIST_SUSPICIOUS_ENTITLEMENTS_COUNT; i++) {
            if (!rasp_obf_decode(RASP_LIST_SUSPICIOUS_ENTITLEMENTS_START + i, key, sizeof key)) continue;
            if (mem_contains(g_ent_buf + 8, len - 8, key))
                rasp_add(out, RASP_F_SUSPICIOUS_ENTITLEMENT, 90, "%s", key);
            rasp_secure_zero(key, sizeof key);
        }
    }
    RASP_END(out, RASP_CHECK_CODESIGN);
}

typedef struct { int32_t cryptid; } crypt_ctx_t;

static bool crypt_visitor(const struct load_command *lc, void *c) {
    crypt_ctx_t *cc = (crypt_ctx_t *)c;
    if (lc->cmd == LC_ENCRYPTION_INFO_64) {
        cc->cryptid = (int32_t)((const struct encryption_info_command_64 *)lc)->cryptid;
        return false;
    }
    if (lc->cmd == LC_ENCRYPTION_INFO) {
        cc->cryptid = (int32_t)((const struct encryption_info_command *)lc)->cryptid;
        return false;
    }
    return true;
}

void rasp_collect_facts(rasp_facts_t *facts) {
    if (!facts) return;
    memset(facts, 0, sizeof *facts);
    int pid = rasp_raw_getpid();
    int err = 0;
    uint32_t flags = 0;
    facts->cs_status_errno = rasp_raw_csops(pid, RASP_CS_OPS_STATUS, &flags, sizeof flags, &err) == 0 ? 0 : err;
    facts->cs_flags = flags;
    facts->exception_port_count = rasp_exception_port_count();
    facts->devmode_sysctl = rasp_devmode_sysctl();

    intptr_t slide = 0;
    const struct mach_header_64 *mh = rasp_main_header(&slide);
    crypt_ctx_t cc = { .cryptid = -1 };
    rasp_for_each_load_command(mh, crypt_visitor, &cc);
    facts->cryptid = cc.cryptid;

    // SHA-256 of the main executable's __TEXT,__text as mapped (post-decryption).
    // Compare server-side against the value recorded at build time.
    unsigned long size = 0;
    const uint8_t *text = mh ? getsectiondata(mh, SEG_TEXT, SECT_TEXT, &size) : NULL;
    if (text && size) {
        unsigned char digest[CC_SHA256_DIGEST_LENGTH];
        CC_SHA256(text, (CC_LONG)size, digest);
        static const char hex[] = "0123456789abcdef";
        for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
            facts->text_sha256[i * 2] = hex[digest[i] >> 4];
            facts->text_sha256[i * 2 + 1] = hex[digest[i] & 0xF];
        }
        facts->text_sha256[64] = '\0';
    }
}
