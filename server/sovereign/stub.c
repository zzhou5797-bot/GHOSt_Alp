/*
 * Stub implementation of the sovereign interface.
 * Used when libgp_sovereign.a is not present (open-source builds).
 * Both functions unconditionally reject all input — zero attack surface.
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>

typedef struct {
    uint32_t action_id;
    uint32_t u32_param;
    uint8_t  bytes_param[32];
    uint32_t str_len;
    uint8_t  str_param[64];
} SovereignResult;

int32_t gp_probe(const uint8_t *buf, size_t len, uint64_t ts_ns) {
    (void)buf; (void)len; (void)ts_ns;
    return -1;
}

int32_t gp_seal(const uint8_t *buf, size_t len, SovereignResult *out) {
    (void)buf; (void)len;
    memset(out, 0, sizeof(*out));
    return -1;
}
