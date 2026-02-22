# GhostPTY v2.5: Phase 2.1 - Cryptographic Meter

- [ ] Fetch the current quota assigned to the established QUIC connection.
- [ ] Implement SYNC_THRESHOLD (64KB) counting logic for bytes sent and received within the QUIC data streams.
- [ ] Connect the async QUIC connection loops (`recv.read` and `send.write_all`) to a shared local atomic counter for tracking `consumed_bytes`.
- [ ] Introduce periodic downward eBPF Map writes (`bpf_map_update_elem`) when `consumed_bytes` surpasses `SYNC_THRESHOLD`.
- [ ] Implement M2.2 (The Guillotine): Trigger `break` and immediate Socket closure accompanied by eBPF `ALLOW_LIST_MAP` eviction when `consumed_bytes > local_quota`.
- [ ] M2.4 (DID Parsing): Extract `client_subject` from the `rustls` Certificate `CN` field instead of passing a hardcoded `1` in `handle_connection`.
- [ ] Commit all changes to the remote GhostPTY_V2 branch.

