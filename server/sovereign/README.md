# Sovereign Layer — Interface Specification

## Overview

The sovereign layer is a closed-source static library (`libgp_sovereign.a`) that
implements the constitutional governance floor for the GhostPTY network.

It is intentionally not part of the open-source distribution. Open-source builds
automatically fall back to `stub.c`, which always returns `-1` (unconditional
reject), making the sovereign channel a no-op.

## C ABI (public interface)

```c
/**
 * gp_probe — Screen an inbound sovereign packet.
 *
 * @param buf    Packet payload bytes
 * @param len    Payload length
 * @param ts_ns  Current UNIX time in nanoseconds
 *
 * Returns 0 if the packet passes screening; non-zero to reject and discard.
 */
int gp_probe(const uint8_t *buf, size_t len, uint64_t ts_ns);

/**
 * gp_seal — Decode a screened sovereign packet into a governance action.
 *
 * Must only be called after gp_probe returns 0.
 *
 * @param buf  Packet payload bytes
 * @param len  Payload length
 * @param out  Caller-allocated SovereignResult to populate
 *
 * Returns 0 on success; non-zero if decoding fails.
 */
int gp_seal(const uint8_t *buf, size_t len, SovereignResult *out);
```

```c
typedef struct {
    uint32_t action_id;
    uint32_t u32_param;
    uint8_t  bytes_param[32];
    uint32_t str_len;
    uint8_t  str_param[64];
} SovereignResult;
```

## Installation (closed-source build)

1. Obtain `libgp_sovereign.a` from the private distribution channel.
2. Copy it to this directory: `server/sovereign/libgp_sovereign.a`
3. Rebuild: `cargo build -p server`

`build.rs` detects the `.a` at compile time and links it in place of `stub.c`.
No source changes are needed.

## Stub behaviour

Without `libgp_sovereign.a`, both `gp_probe` and `gp_seal` return `-1`.
The sovereign ring-buffer task in `main.rs` becomes a permanent no-op.
All other functionality (SPA, QUIC, PTY, quota, BFT slash) is unaffected.
