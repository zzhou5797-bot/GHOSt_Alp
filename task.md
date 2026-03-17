# GhostPTY v2.5: Phase 2.1 - Cryptographic Meter

- [x] Fetch the current quota assigned to the established QUIC connection.
- [x] Implement SYNC_THRESHOLD (64KB) counting logic for bytes sent and received within the QUIC data streams.
- [x] Connect the async QUIC connection loops (`recv.read` and `send.write_all`) to a shared local atomic counter for tracking `consumed_bytes`.
- [x] Introduce periodic downward eBPF Map writes (`bpf_map_update_elem`) when `consumed_bytes` surpasses `SYNC_THRESHOLD`.
- [x] Implement M2.2 (The Guillotine): Trigger `break` and immediate Socket closure accompanied by eBPF `ALLOW_LIST_MAP` eviction when `consumed_bytes > local_quota`.
- [x] M2.4 (DID Parsing): Extract `client_subject` from the `rustls` Certificate `CN` field instead of passing a hardcoded `1` in `handle_connection`.
- [ ] Commit all changes to the remote GhostPTY_V2 branch.

