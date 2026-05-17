# GhostPTY v3.0: 分阶段开发执行计划书 (Execution Roadmap)

为了将"无时域密码学状态机"的宏大架构安全且稳妥地落地，并向最终的"分布式安全 L1"及"AI 网格总线"演进，GhostPTY v3.0 的开发被严密地拆分为 **四个核心阶段 (Phases)** 和 **若干关键里程碑 (Milestones)**。

**最后更新：2026-05-17**

---

## 🟢 Phase 1: 引擎淬火 (The Engine Forging) - [✅ 已完成]

**目标**: 彻底剥离 eBPF 层的物理时间依赖，完成基于哈希链 ($O(1)$) 的防丢包敲门机制与硬件级防 DDoS 模块。将系统的地基打得坚如磐石。

### Milestone 1.1: 哈希链验证器原型 (eBPF)

* **状态**: ✅ 已完成 (代码见 `gateway-ebpf/src/main.rs`)。
  * 在 XDP 层实现带序号的 $O(1)$ 查找：`[Seq: N-x, Hash: H_N-x]`。
  * 利用 `#pragma unroll 10` 在内核执行受界有向循环，容忍最大 10 个 UDP 丢包的乱序快进，维护因果链韧性。

### Milestone 1.2: 软限流模块注入 (XDP Token Bucket)

* **状态**: ✅ 已完成。
  * 在现有的 `ALLOW_LIST_MAP` 中扩展值结构，加入并发突发计流字段 (`bucket_tokens` / `last_refill_ns`)。对于源 IP 在白名单中的海量垃圾突发流，直接在网卡层拦截。

### Milestone 1.3: 物理层垃圾回收绑定 (eBPF GC)

* **状态**: ✅ 已完成。
  * 用户态守护线程轮询 `AUTH_STATE_MAP`。当配额耗尽或长时间无响应时，同步清除 `ALLOW_LIST_MAP` 拔线。

---

## 🟢 Phase 2: 核算结界与断头台 (The Settlement Ward) - [✅ 已完成]

**目标**: 在不依赖外部区块链的情况下，于本地节点实现极速、防白嫖的流量核算与物理拔线闭环。

### Milestone 2.1: 密码学双向水表 ✅

QUIC recv/send 循环接入原子计数器，每 SYNC_THRESHOLD（64KB）批量写入 eBPF `quota_bytes`，避免锁竞争风暴。

### Milestone 2.2: 物理级熔断器 (The Guillotine) ✅

配额燃尽时硬 `break` 跳过 QUIC 四次挥手，直接销毁套接字并从 `ALLOW_LIST_MAP` 即时驱逐该 IP。

### Milestone 2.4: 身份凭证动态装载 (DID Parsing) ✅

从 mTLS 证书 X.509 CN 字段解析 `client_subject`（u32），取代硬编码值 `1`，解锁真·多租户。

---

## 🟢 Phase 3: 深渊网格与全息共识 (The Abyssal Grid) - [✅ 已完成]

**目标**: 将全球孤立的 Ghost 节点连成一张具备自我愈合、光速同步和 0-Day 免疫的去中心化 L1 网络。

### Milestone 3.1: 混合 Gossip 控制面 ✅

libp2p GossipSub，双 topic（`ghost_grid_quota` + `ghost_grid_slash`），Ed25519 消息鉴权，mDNS 局域网发现，`--bootstrap-peers` 跨网络节点发现（逗号分隔 multiaddr 列表）。

### Milestone 3.2: 创世证书与冷启动自举 ✅

Ed25519 genesis root key 数组，`GenesisCredential` VC 签名验证。DID→pubkey 映射与 genesis key 数组索引已解耦（`slash_pubkey_for_did()` match 注册表），新增 DID 节点无需重新编号。

### Milestone 3.3: 零日漏洞瞬间免疫网络 ✅

`audit_execve` Tracepoint + execve 白名单 + `cgroup_id → DID` 反查。异常即触发 BFT Slash 广播，无需人工介入。

### Milestone 3.4: 门限签名 SLASH 绝杀 (BFT Slash) ✅

3/N 门限 + Ed25519 签名验证 + `last_seen_quota_seq` 防过期 slash 投票滥用（Phase 7 Timeless Paradox 修复）。

---

## 🎯 当前焦点：集成测试与组网验证

协议核心已完整。当前工作是在真实多节点环境中验证。

### 测试层次 1：纯逻辑单元测试（无需 root）

```
cargo test -p ghost-chain-tests
```

覆盖：SPA 哈希链验证、Token Bucket 速率限制、重放拒绝、垃圾预像拒绝、State Fast-Forward。

### 测试层次 2：单节点集成测试（需要 Linux root + eBPF）

```
cargo xtask build-ebpf --release
sudo ./test_local.sh
```

验证：SPA knock → QUIC 握手 → PTY 会话 → quota 扣减 → Guillotine 断线。

### 测试层次 3：双节点跨机测试（组网后进行）

```
sudo server --bootstrap-peers /ip4/<B_IP>/tcp/<PORT>/p2p/<B_PEER_ID>
```

验证：quota gossip 双向同步，跨机 slash 一致生效。

---

## ⚫ Phase 4: 黑暗森林与价值收割 (The Dark Forest)

**目标**: 技术底座大成，开启基于密码学和物理法则的降维打击商业变现。

### Milestone 4.1: AI 智能体专属暗网通道 (Agentic Substrate)

专注 AI 间（M2M）的原生高频控制总线。结合 M2.1 水表计费，与 GhostBridge quota token 经济层对接（外挂，不修改协议内部）。

### Milestone 4.2: 零日漏洞套利暗池 (0-Day Arbitrage)

节点网络化身武器级蜜罐。eBPF 捕获的未知热 0-Day Payload 签名，通过加密 API 高频竞价拍卖给传统安全厂商。

### Milestone 4.3: 算力大逃杀与全网放逐 (Cyber Excommunication)

- **呼吸税**: 拥堵期要求在 QUIC 流中烧 Token，出价垫底的 IP 由 XDP 物理淘汰。
- **赏金通缉**: 任何人可发布加密赏金，Gossip 核实后目标全网进入 XDP 黑洞。
