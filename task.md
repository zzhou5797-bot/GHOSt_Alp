# GhostPTY v3.0: 当前状态与测试计划

## ✅ 协议核心（全部完成）

- [x] Phase 1: SPA v1/v2 哈希链、XDP Token Bucket、eBPF GC、Map Pinning
- [x] Phase 2: QUIC 字节计量（SYNC_THRESHOLD 64KB）、Guillotine 断线、DID CN 解析
- [x] Phase 3: GossipSub 控制面、mDNS + `--bootstrap-peers` 发现、Genesis VC、BFT Slash 3/N、execve 白名单
- [x] Phase 6-7: `last_seen_quota_seq` 防过期投票、`slash_pubkey_for_did()` DID/index 解耦、nonce OOM 修复

## 🎯 当前工作：集成测试

### 测试层次 1 — 纯逻辑单元测试（无需 root）
- [ ] `cargo test -p ghost-chain-tests` 全绿

### 测试层次 2 — 单节点集成测试（需要 Linux root + eBPF）
- [ ] `cargo xtask build-ebpf --release` 编译成功
- [ ] `sudo ./test_local.sh` 启动节点 + 健康检查通过
- [ ] 客户端连接成功，PTY 会话可交互
- [ ] quota 扣减可观测（查 /sys/fs/bpf/ghostpty）
- [ ] Guillotine：配置小 quota，验证超限后连接被强断

### 测试层次 3 — 双节点跨机测试（组网后）
- [ ] 两节点 `--bootstrap-peers` 互连，gossipsub 连通
- [ ] quota gossip 双向同步可观测
- [ ] 跨机 slash 一个 DID，两节点均拒绝该 DID 连接


