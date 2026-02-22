# GhostPTY v2.5: 分阶段开发执行计划书 (Execution Roadmap)

为了将“无时域密码学状态机”的宏大架构安全且稳妥地落地，并向最终的“分布式安全 L1”及“AI 网格总线”演进，GhostPTY v2.5 的开发将被严密地拆分为 **四个核心阶段 (Phases)** 和 **十四个关键里程碑 (Milestones)**。

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

## 🟡 Phase 2.5: 核算结界与断头台 (The Settlement Ward) - [🎯 当前开发阶段]

**目标**: 在不依赖外部区块链的情况下，于本地节点实现极速、防白嫖的流量核算与物理拔线闭环。

### Milestone 2.1: 密码学双向水表 (The Cryptographic Meter)

* **任务**:
  * 拦截 `server/src/main.rs` 中 QUIC (quinn) `recv.read()` 和 `send.write_all()`。
  * 只对 TLS 1.3 AEAD 成功解密的**纯有效载荷**进行字节统计，过滤垃圾耗散包。
  * **内存聚合机制**: 引入 `SYNC_THRESHOLD` (如 64KB)，单连接在内存中高频累加。达阈值后低频原子扣减 eBPF Map 中的 `quota_bytes`，避免锁竞争。
* **验收**: 发送 10Gbps 伪造 IP 垃圾流压测，配额仪表读数零波动；跑满 1GB 有效载荷时，内核 `quota_bytes` 误差 < 64KB。

### Milestone 2.2: 物理级熔断器 (The Guillotine)

* **任务**:
  * 每次累加字节后实时判定：如果 `local_quota < consumed` 或 eBPF 查得 `quota_bytes == 0`，激活熔断。
  * 不走正常的 QUIC `close()` 或 PTY 终止流程。直接 `break` 循环，强行销毁 Socket，并向 eBPF 发送即时拔线令。
* **验收**: 配置 10MB 配额，传输 11MB 文件。连接必须在传输恰好越界时由于内核网卡级丢包瞬间假死，进程随之回收。

### Milestone 2.3: 密码学心跳质询 (Causal Heartbeat)

* **任务**:
  * 通过 QUIC 的单向 Control Stream 不定期下发随机 Nonce。
  * 客户端必须返回基于其 DID 私钥（如 Ed25519）签署的验证盲注。
  * 若多次质询超时未签或错签，直接调用 eBPF GC 抹除状态。
* **验收**: 阻断客户端 Control Stream 发送能力但保持心跳，服务器主动剿杀“占坑死会话”成功。

### Milestone 2.4: 身份凭证动态装载 (DID Parsing)

* **任务**:
  * 消除现存的硬编码 `client_subject = 1`。
  * 从 `quinn` 获取的 `rustls::Certificate` 中解析基于 DID 的 CN，动态换算为 `u32` 唯一标识符供内核使用。

---

## 🔴 Phase 3: 深渊网格与全息共识 (The Abyssal Grid)

**目标**: 将全球孤立的 Ghost 节点连成一张具备自我愈合、光速同步和 0-Day 免疫的去中心化 L1 网络。

### Milestone 3.1: 混合 Gossip 控制面 (Hybrid Control Plane)

* **任务**: 集成 `rust-libp2p`。通过 GossipSub 协议作为网格神经，利用 CRDT 的 `G-Counter` 在全网无锁最终同步用户的流量配额与消耗。

### Milestone 3.2: 创世证书与冷启动自举 (Genesis Bootstrap)

* **任务**: 硬编码 3 把 Root Key 于守护进程中。新入网用户提供基于该信任链签发的 VC（可验证凭证）。单点首验通过即全网背书。

### Milestone 3.3: 零日漏洞瞬间免疫网络 (0-Day Immunity Sync)

* **任务**: 将既有的 eBPF `audit_execve` 捕获组件升级。一旦在某单点主机探测到供应链投毒或高危异常 Shell：
  * 1. 提取包上下文。
  * 1. 0.5s 内通过 GossipSub 泛洪全球。
  * 1. 各节点瞬间下发规则入 XDP 黑名单。
* **效果**: 全网瞬间获得 0-Day 永久抗体。

### Milestone 3.4: 门限签名 SLASH 绝杀 (BFT Slash)

* **任务**: 处理网络脑裂时的恶意吊销。只有集齐 `m-of-n` (如 3 个) 不同节点的联合签名确认，针对某 DID 的全网物理封杀令 (`SLASH` 指令) 方可在 eBPF 中生效。

---

## ⚫ Phase 4: 黑暗森林与价值收割 (The Dark Forest)

**目标**: 技术底座大成，开启基于密码学和物理法则的降维打击商业变现。

### Milestone 4.1: AI 智能体专属暗网通道 (Agentic Substrate)

* **商业化**: 摒弃为人类做跳板机，专注 AI 间 (Devin, AutoGPT 等) 的原生高频控制总线。
* **技术支撑**: 结合 M2.1 的水表计费，调用智能合约收取“指令穿透费（Gas）”。

### Milestone 4.2: 零日漏洞套利暗池 (0-Day Arbitrage)

* **变现手段**: 节点网络天然化身武器级蜜罐。将 eBPF (M3.3) 第一时间捕获到且被成功拦截的未知热 0-Day Payload 签名，通过加密 API 高频竞价拍卖给传统安全厂商。

### Milestone 4.3: 算力大逃杀与全网放逐 (Cyber Excommunication)

* **变现手段**:
  * **呼吸税**: 拥堵期不按先来后到放行，要求在 QUIC 流中烧 Token，出价垫底的 10% IP 由 XDP 物理淘汰。
  * **赏金通缉**: 任何人可发布加密赏金。待 Gossip 查明行为无误后，目标被全网拉入 XDP 黑洞，与现代服务彻底隔离。

---

> **下一步核心研发行动点 (Action Item):**
> 开发资源在此刻全量压入 **Phase 2.5 `M 2.1 密码学双向水表`**。打开 `server/src/main.rs` 注入。

---

## 🏴 Phase Dark: 绞肉机与主动防御 (The Meat Grinder)
**目标**: 放弃“被动拦截”，将系统升级为自带套利、反噬、降维打击能力的主动赛博防御武器。实施六大侵略性物理与协议级反制。

### Milestone D.1: 焦油坑与薛定谔雷暴 (Tarpit & Schrödinger)
*   **任务 (Phase 1 基础延展)**:
    *   扩展 `gateway-ebpf/src/main.rs`。针对高频 TCP SYN 扫描，不执行 `XDP_DROP`，改为 `XDP_TX` 反射。伪造 `SYN-ACK` 并锁定极小 Window Size，死锁攻击者。
    *   在未鉴权拦截前，随机吐出混淆性协议指纹（如假 SSH 头或大容量随机伪数据流）。
*   **验收**: 运行 Nmap 满速扫描本机，验证攻击端 Nmap 内存暴涨、文件描述符耗尽或发生超时崩溃；本机 CPU 几乎无波动。

### Milestone D.2: 算力吸星术 (Cryptographic Retaliation)
*   **任务 (Phase 2 全新拦截)**:
    *   当非信任海量 UDP 涌入，内核触发动态 PoW 下发。
    *   应用端需针对特定 `Nonce` 计算并返回有效 Hash 盲注。
*   **验收**: 利用 UDP 压力工具洪泛，网关不记录不计费，且成功要求攻击端出卖高强度 CPU 时间用于解题。攻击流量剧减。

### Milestone D.3: 楚门沙箱与镜像劫持 (Honeypot & Mirror)
*   **任务 (Phase 3 关联增强)**:
    *   在 `audit_execve` 侦测到（M 3.3）高危 0-Day 或投毒行为时，不 Kill 进程。
    *   通过 `bpf_redirect` 将其会话的网络包物理重定向至预先布好的“高价值假库 (Honeypot)” Cgroup/Namespace 中。
    *   对于暴力破解阵列，用 NAT 改写包头，促发黑客源头 A 与黑客源头 B 的“狗咬狗”流量闭环。
*   **验收**: 利用提权 Exploit 或已知恶意木马侵入，系统未报警但透明转入沙箱。全景记录其 C2 服务器通讯，并自动生成免杀特征码。

### Milestone D.4: 放射性数据投毒 (Data Poisoning)
*   **任务 (Phase 4 结合应用)**:
    *   识别爬虫/恶意抓取器特征流。在 `server/src/main.rs` 的 HTTP/数据响应出口处。
    *   动态植入对抗性样本（如针对 AI 的异常扰动像素、恶意诱导 Prompt），或导致常见 JSON 解析器栈溢出的畸形负荷。
*   **验收**: 模拟已知恶意爬虫请求，捕获其因吞下含毒 Payload 导致的内存报错或崩溃。
