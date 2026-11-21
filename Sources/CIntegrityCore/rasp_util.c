#include "rasp_internal.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

void rasp_add(rasp_findings_t *out, uint16_t code, uint8_t confidence, const char *fmt, ...) {
    if (!out) return;
    if (out->count >= RASP_MAX_FINDINGS) { out->dropped++; return; }
    rasp_finding_t *f = &out->items[out->count++];
    f->code = code;
    f->confidence = confidence > 100 ? 100 : confidence;
    f->_pad = 0;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(f->detail, sizeof f->detail, fmt, ap);
    va_end(ap);
}

size_t rasp_obf_decode(uint16_t index, char *out, size_t cap) {
    if (!out || cap == 0 || index >= RASP_OBF_ENTRY_COUNT) return 0;
    const rasp_obf_entry_t *e = &rasp_obf_table[index];
    size_t n = e->length;
    if (n + 1 > cap) return 0;
    uint8_t k = e->key;
    for (size_t i = 0; i < n; i++) {
        out[i] = (char)(rasp_obf_blob[e->offset + i] ^ k);
        k = (uint8_t)(k + e->step);
    }
    out[n] = '\0';
    return n;
}

void rasp_secure_zero(void *p, size_t n) {
    volatile uint8_t *v = (volatile uint8_t *)p;
    while (n--) *v++ = 0;
}

const char *rasp_strcasestr(const char *hay, const char *needle) {
    if (!hay || !needle) return NULL;
    size_t nl = strlen(needle);
    if (nl == 0) return hay;
    for (; *hay; hay++) {
        size_t i = 0;
        while (i < nl && hay[i] && tolower((unsigned char)hay[i]) == tolower((unsigned char)needle[i])) i++;
        if (i == nl) return hay;
    }
    return NULL;
}

void rasp_random_token(char out[17]) {
    static const char hex[] = "0123456789abcdef";
    uint8_t b[8];
    arc4random_buf(b, sizeof b);
    for (int i = 0; i < 8; i++) {
        out[i * 2] = hex[b[i] >> 4];
        out[i * 2 + 1] = hex[b[i] & 0xF];
    }
    out[16] = '\0';
}
