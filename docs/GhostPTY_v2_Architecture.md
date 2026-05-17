# 📜 Ghost Grid 创世蓝图 (v3.0)：从工具到物理法则

**代号:** Timeless Aegis (无时域之盾)
**修订时间:** 2026-05-17
**定位终极愿景:** Ghost Grid 不对标任何 VPN 或传统堡垒机产品，它的终极坐标是**"去中心化安全基础设施（DeSec）"**与**"AI 时代的原生跨机总线"**——在内核物理层执行因果律，在协议层实现 0-Day 天然免疫，在经济层吞噬黑暗森林的每一分价值。

---

## ⚠️ 核心定位变更说明

| 维度 | V1 设计 | V2.5 升维方向 |
|---|---|---|
| **产品定位** | 去中心化 Tailscale / 堡垒机 | **去中心化安全基础设施 L1 (DeSec)** |
| **服务对象** | 人类运维工程师 | **AI 智能体 (M2M) 为主，人类为辅** |
| **计费模型** | 连接时长 / 包月 | **QUIC AEAD 解密字节级密码学计量** |
| **安全理念** | 防外部攻击 (XDP) | **纵深防御 + 0-Day 套利 (XDP + eBPF Tracepoint)** |
| **共识机制** | 全局慢速区块链账本 | **混合架构：控制面 libp2p/CRDT + 数据面 Ring-0 XDP** |

---

## 技术哲学核心 (Timeless Design Philosophy)

GhostPTY v2 的根基是彻底摒弃"物理时间"这一易被攻击的系统依赖，转而构建一个纯粹的**密码学状态机（Cryptographic State Machine）**：

1. **无时域防重放**：用单调递降的哈希链序列号（因果律）替代时间戳，免疫所有 NTP 攻击与时钟漂移。
2. **非对称双层防御**：廉价的 XDP 在网卡驱动层软限流，昂贵的 QUIC AEAD 精确结算，两者永不越权。
3. **去中心化授权网格**：Gossip + CRDT 实现全球秒级策略共识，eBPF 在内核执行最终物理判决。

---

## 当前代码库快照 (v3.0 实现状态)

### ✅ Phase 1 (已完成): 引擎淬火

| 模块 | 实现位置 | 状态 |
|---|---|---|
| SPA v2 哈希链验证器（10次有界循环，State Fast-Forward） | `gateway-ebpf/src/main.rs` | ✅ |
| SPA v1 时间戳兼容层（双栈过渡期） | `gateway-ebpf/src/main.rs` | ✅ |
| XDP Token Bucket 软限流（防伪造 IP 洪泛） | `gateway-ebpf/src/main.rs` | ✅ |
| `AUTH_STATE_MAP`, `ALLOW_LIST_MAP`, `AUDIT_CGROUP_MAP` | `gateway-ebpf-common/src/lib.rs` | ✅ |
| eBPF GC 守护进程（10s 轮询，配额燃尽/死会话 tombstone） | `server/src/main.rs` | ✅ |
| `audit_execve` Tracepoint（cgroup 过滤，5 argv 捕获） | `gateway-ebpf/src/main.rs` | ✅ |
| eBPF Map Pinning（`/sys/fs/bpf/ghostpty`，重启持久化） | `server/src/main.rs` | ✅ |

### ✅ Phase 2 (已完成): 核算结界

| 模块 | 实现位置 | 状态 |
|---|---|---|
| QUIC mTLS 双向认证（rustls CA + 客户端证书） | `server/src/main.rs` | ✅ |
| QUIC AEAD 字节级精确计费（SYNC_THRESHOLD 64KB） | `server/src/main.rs` | ✅ |
| The Guillotine：配额燃尽硬断线 + ALLOW_LIST 即时驱逐 | `server/src/main.rs` | ✅ |
| DID Subject 从 mTLS cert CN 解析（X.509 CN → u32） | `server/src/main.rs` | ✅ |

### ✅ Phase 3 (已完成): 深渊网格与全息共识

| 模块 | 实现位置 | 状态 |
|---|---|---|
| libp2p GossipSub 控制面（quota + slash 双 topic） | `server/src/p2p.rs` | ✅ |
| mDNS 局域网节点发现 | `server/src/p2p.rs` | ✅ |
| `--bootstrap-peers` 跨网络节点发现（逗号分隔 multiaddr） | `server/src/main.rs`, `p2p.rs` | ✅ |
| 创世证书 Genesis VC（Ed25519 签名 + pubkey_index） | `server/src/genesis.rs` | ✅ |
| 0-Day Immunity：execve 白名单 + BFT slash 广播 | `server/src/main.rs` | ✅ |
| BFT Slash 共识（3/N 门限 + Ed25519 签名验证） | `server/src/p2p.rs`, `genesis.rs` | ✅ |

### ✅ Phase 6-7 (已完成): 因果律强化

| 模块 | 实现位置 | 状态 |
|---|---|---|
| `last_seen_quota_seq` 防过期 slash 投票 | `server/src/p2p.rs` | ✅ |
| DID→pubkey 映射解耦（不再用数组索引当 DID） | `server/src/genesis.rs` | ✅ |
| `slash_pubkey_for_did()` 可扩展注册表 | `server/src/genesis.rs` | ✅ |
| cgroup_id → DID 反查（audit anomaly 溯源） | `server/src/main.rs` | ✅ |
| `nonce_cache` OOM 漏洞修复（Phase 7.3 eradicated） | `server/src/main.rs` | ✅ |

### 🎯 下一里程碑：跨节点集成测试

协议核心已完整。当前焦点是验证多节点网络：

1. **层次 1**：`cargo test -p ghost-chain-tests`（纯逻辑，无需 root）
2. **层次 2**：单节点集成测试（需要 Linux root + eBPF）
3. **层次 3**：双节点 `--bootstrap-peers` 跨机测试（组网后进行）

---

## 📋 四阶段路线图

### Phase 2.5 — 核算结界与断头台 (🎯 当前焦点)

**目标**：在单节点内闭环实现极速防白嫖流量核算与物理拔线机制。

#### M2.1 密码学双向水表 (Cryptographic Meter)

- 在 QUIC `recv.read()` 后，只对 TLS 1.3 AEAD 成功解密的**纯净净荷字节**计账。
- 引入 `SYNC_THRESHOLD`（64KB）内存聚合，达阈值后批量写入 eBPF Map，规避锁互斥风暴。
- **验收**：垃圾包洪泛压测，配额仪表读数零波动。

#### M2.2 物理级熔断器 (The Guillotine)

- 配额燃尽时，跳过 QUIC 优雅四次挥手，硬 `break` 直接销毁套接字与 PTY 进程树。
- **验收**：1MB 配额下，脚本下载 1MB+1 文件，验证精确字节截断位置。

#### M2.3 幽灵清道夫（M2.3 已有 GC 框架，增强为 Reaper）

- 强化现有 GC 守护进程：连接断开后立即同步清除 `ALLOW_LIST_MAP`，使目标 IP 回归"端口不存在"虚无状态，而非等待 10s GC 轮询。

#### M2.4 DID Subject 解析（解锁真·多租户）

- 从 mTLS 证书的 `CN`（通用名称）字段解析 `client_subject`，取代硬编码 `1`。
- 为后续 Phase 3 的 DID 全网同步奠定基础。

---

### Phase 3 — 深渊网格与全息共识

**目标**：将孤立节点连成自愈、光速同步、具备 0-Day 免疫能力的去中心化 L1 网络。

#### M3.1 混合 Gossip 控制面 (Hybrid Control Plane)

- 引入 `rust-libp2p` + GossipSub v1.1，节点间 Ed25519 身份验证，建立 DHT 网络。
- CRDT G-Counter 全网同步配额消耗，实现高并发无锁对账。

#### M3.2 创世证书与冷启动自举 (Bootstrap)

- 多签 Root Key 硬编码于节点守护进程，作为信任根。
- 新成员携带 VC（可验证凭证）入网，经信任树逐级背书后，由第一个认证节点通过 Gossip 向全网扩散。

#### M3.3 零日漏洞瞬间免疫网络 (0-Day Immunity Sync)

- `audit_execve` 捕获异常 Syscall → 提取攻击特征码 → Protobuf 打包 → GossipSub < 500ms 全网广播 → 各节点用户态接收情报后写入 XDP Map。
- **结果**：黑客打出一发 0-Day，全网瞬间获得永久抗体。

#### M3.4 门限签名 SLASH 共识 (BFT Slash)

- 高危指令（SLASH/REVOKE）须收集 `m-of-n` 节点联合签名才触发 eBPF 封杀。
- CRDT Fail-Safe 规则：同序列号冲突时，REVOKE > GRANT。

---

### Phase 4 — 黑暗森林与价值收割 (终极商业形态)

**目标**：技术底座大成，协议代码转化为金融引擎。

#### M4.1 AI 智能体专属暗网通道 (The Agentic Web Substrate)

- 全面拥抱 AI（Devin, AutoGPT 等跨节点任务调度）。
- 基于 M2.1 字节水表 + 智能合约，向 AI 算力网络实时收取微厘级指令穿透费（Gas）。
- Ghost Grid 成为 AI 时代的**跨节点神经总线**。

#### M4.2 零日漏洞套利暗池 (Zero-Day Arbitrage Pool)

- Ghost Grid 节点构成武器化蜜罐，eBPF 在纳秒级捕获但不执行 0-Day Payload。
- 系统自动将热腾腾的攻击签名通过加密 API 实时拍卖给微软、CrowdStrike 等传统安全大厂。
- 黑客沦为网格的**免费漏洞矿工**。

#### M4.3 算力大逃杀与赛博放逐令 (Cyber Excommunication as a Service)

- **呼吸税**：网络拥堵时，竞价行钱包出价垫底 IP 直接被 XDP 物理拔线。
- **赛博通缉**：任何人支付赏金通缉特定 DID，经 Gossip 多签共识后，目标被全网数千节点拉入 XDP 永久黑洞，直至缴纳赎金。

---

## 愿景结语 (Architectural Statement)

时间不过是人类用来测量熵增的幻象。真正的去中心化安全基础设施，不应相信时钟，而应信仰**因果、密码学承诺与客观物理定律**。

Ghost Grid 的终局，是让每一次网络访问都成为一次密码学宣誓，让每一个恶意字节都成为永久的链上耻辱，让每一把 0-Day 都成为价值收割的猎物。

**这不是产品，这是物理法则。**

---

## 🏴 Phase Dark: 绞肉机与主动防御 (The Meat Grinder) - 专属魔改扩展架构

**本阶段目标**：彻底颠覆传统的“被动防守（Drop/Reject）”理念。将 Ghost Grid 升级为一台具备侵略性的**主动防御武器（Active Retaliation System）**。不再是被动挨打的防火墙，而是深渊凝视的赛博绞肉机。针对每一种典型的攻击模式，赋予其致命的物理与计算反噬。

### D1. 焦油坑陷阱 (The Abyssal Tarpit) — 反向 OOM 打击
*   **适用场景**: 未授权的恶意大面积端口扫描（如 Nmap, ZMap）及 TCP SYN Flood 盲打。
*   **攻击引擎 (XDP层)**: 摒弃传统的 `XDP_DROP`。当 XDP 嗅探到特定特征的恶意 SYN 包时，触发 `XDP_TX`，就地篡改包头并伪造 `SYN-ACK` 反射，同时将 TCP 接收窗口 (`Window Size`) 锁死为极小值（如 0 或 1）。
*   **敌方损伤**: 黑客的扫描器被迫建立无数僵死的 Socket，卡在无限的重传与死锁等待中。耗尽攻击者的文件描述符 (FD) 和并发线程，引发敌方服务端 OOM 物理崩溃。

### D2. 算力吸星大法 (PoW Cryptographic Retaliation) — “免费暖宝宝”机制
*   **适用场景**: 海量源 IP 的应用层或传输层 DDoS 洪泛攻击。
*   **攻击引擎 (XDP + QUIC)**: 当网关判定攻击烈度超载时，XDP 不做业务处理，而是下发一个包含哈希解谜（Hashcash Challenge）指令的反射包给攻击源。不解开高难度谜题，一切后击包均被 `XDP_DROP` 物理拒收。
*   **敌方损伤**: 以 1 纳秒的轻量级内核判断，强制换取黑客僵尸网络 100% 的极重度 CPU 满载解谜燃烧。将恶意算力据为己有，转化为消耗攻击者电费与主板寿命的武器。

### D3. 楚门的世界 (The Matrix Honeypot) — 动态流放与套利养殖
*   **适用场景**: 利用高价值 0-Day 漏洞或通过泄漏的合法凭证潜入的 APT 级高级黑客。
*   **攻击引擎 (eBPF + 用户态)**: 如果 `audit_execve` 捕捉到高危或反常理操作，系统不急于击杀。XDP 驱动 `bpf_redirect` 神技，在毫秒级物理串改网络流向，将该 Session 神不知鬼不觉地路由入充盈虚假高价值数据的全探针沙箱容器里。
*   **敌方损伤 (及我方套利)**: 监控并记录他执行的所有 Exploit 与后续落地的 C2 地址。既可以抽取全新的免杀 0-Day / Payload 特征向安全大厂套现，也能借此暴露幕后黑手的实体 IP 证据，实现钓鱼执法。

### D4. 薛定谔的端口与雷暴 (Schrödinger's Port & Protocol Thunder) — 情报致盲
*   **适用场景**: 常规情报收集、指纹识别扫描。
*   **攻击引擎 (纯 eBPF 动态伪装)**: 令 eBPF 依照时钟或者源 IP，伪造完全精神分裂的回包。一秒是以往弱点满盈的 IIS；下一刻是洞门大开但也布满垃圾的无限读流 (`/dev/urandom` 协议流打雷)。
*   **敌方损伤**: 不需要入侵，纯靠协议层的数学迷宫与垃圾数据洪流，令攻击方自动扫网或解析引擎报错、幻觉、或内存耗尽。直接摧毁其中枢态势感知能力。

### D5. 递归镜像迷宫 (Recursive Mirror Labyrinth) — 杀人诛心
*   **适用场景**: 针对性的暴力破解、渗透测试脚本群轰炸。
*   **攻击引擎 (XDP 镜像劫持)**: 把来袭攻击流，通过 eBPF `redirect` 与 NAT 瞬间混淆重定向，反射指向攻击者身后的同一 C段网段，或直接将其牵引（嫁接）与同时间正在扫描该系统的另外一支黑客流相对接。
*   **敌方损伤**: 让两路素不相识的黑客攻击集群，在对目标毫无损伤的情况下，在你的虚拟迷宫中“互殴”。真正的坐山观虎斗。

### D6. 放射性数据投毒 (Radioactive Data Poisoning) — 吃饵烂肚
*   **适用场景**: 非法商业爬虫、AI 语料偷窃者、自动化资产抓取器。
*   **攻击引擎 (Rust 业务层下毒)**: 针对已知白嫖特征或不怀好意的扫描流，伪装系统门洞大开并成功吐出关键“机密数据”。但在数据集内悄悄封装入大模型对抗样本（Adversarial Example）、SQL/解析器触发雷、或逻辑死循环炸弹。
*   **敌方损伤**: 白嫖者辛辛苦苦偷走的数据，会直接引发其模型训练崩塌，或者摧毁他们自己的后端图计算引发雪崩。

---

## 🏴 Phase Dark: 绞肉机与主动防御 (The Meat Grinder)
**目标**: 放弃“被动拦截”，将系统升级为自带套利、反噬、降维打击能力的主动赛博防御武器。实施六大侵略性物理与协议级反制。

### D1. 焦油坑陷阱 (The Abyssal Tarpit) — 反向 OOM 打击
*   **适用场景**: 未授权的恶意大面积端口扫描（如 Nmap, ZMap）及 TCP SYN Flood 盲打。
*   **攻击引擎 (XDP层)**: 摒弃传统的 `XDP_DROP`。当 XDP 嗅探到特定特征的恶意 SYN 包时，触发 `XDP_TX`，就地篡改包头并伪造 `SYN-ACK` 反射，同时将 TCP 接收窗口 (`Window Size`) 锁死为极小值（如 0 或 1）。
*   **敌方损伤**: 黑客的扫描器被迫建立无数僵死的 Socket，卡在无限的重传与死锁等待中。耗尽攻击者的文件描述符 (FD) 和并发线程，引发敌方服务端 OOM 物理崩溃。

### D2. 算力吸星大法 (PoW Cryptographic Retaliation) — “免费暖宝宝”机制
*   **适用场景**: 海量源 IP 的应用层或传输层 DDoS 洪泛攻击。
*   **攻击引擎 (XDP + QUIC)**: 当网关判定攻击烈度超载时，XDP 不做业务处理，而是下发一个包含哈希解谜（Hashcash Challenge）指令的反射包给攻击源。不解开高难度谜题，一切后击包均被 `XDP_DROP` 物理拒收。
*   **敌方损伤**: 以 1 纳秒的轻量级内核判断，强制换取黑客僵尸网络 100% 的极重度 CPU 满载解谜燃烧。将恶意算力据为己有，转化为消耗攻击者电费与主板寿命的武器。

### D3. 楚门的世界 (The Matrix Honeypot) — 动态流放与套利养殖
*   **适用场景**: 利用高价值 0-Day 漏洞或通过泄漏的合法凭证潜入的 APT 级高级黑客。
*   **攻击引擎 (eBPF + 用户态)**: 如果 `audit_execve` 捕捉到高危或反常理操作，系统不急于击杀。XDP 驱动 `bpf_redirect` 神技，在毫秒级物理串改网络流向，将该 Session 神不知鬼不觉地路由入充盈虚假高价值数据的全探针沙箱容器里。
*   **敌方损伤 (及我方套利)**: 监控并记录他执行的所有 Exploit 与后续落地的 C2 地址。既可以抽取全新的免杀 0-Day / Payload 特征向安全大厂套现，也能借此暴露幕后黑手的实体 IP 证据，实现钓鱼执法。

### D4. 薛定谔的端口与雷暴 (Schrödinger's Port & Protocol Thunder) — 情报致盲
*   **适用场景**: 常规情报收集、指纹识别扫描。
*   **攻击引擎 (纯 eBPF 动态伪装)**: 令 eBPF 依照时钟或者源 IP，伪造完全精神分裂的回包。一秒是以往弱点满盈的 IIS；下一刻是洞门大开但也布满垃圾的无限读流 (`/dev/urandom` 协议流打雷)。
*   **敌方损伤**: 不需要入侵，纯靠协议层的数学迷宫与垃圾数据洪流，令攻击方自动扫网或解析引擎报错、幻觉、或内存耗尽。直接摧毁其中枢态势感知能力。

### D5. 递归镜像迷宫 (Recursive Mirror Labyrinth) — 杀人诛心
*   **适用场景**: 针对性的暴力破解、渗透测试脚本群轰炸。
*   **攻击引擎 (XDP 镜像劫持)**: 把来袭攻击流，通过 eBPF `redirect` 与 NAT 瞬间混淆重定向，反射指向攻击者身后的同一 C段网段，或直接将其牵引（嫁接）与同时间正在扫描该系统的另外一支黑客流相对接。
*   **敌方损伤**: 让两路素不相识的黑客攻击集群，在对目标毫无损伤的情况下，在你的虚拟迷宫中“互殴”。真正的坐山观虎斗。

### D6. 放射性数据投毒 (Radioactive Data Poisoning) — 吃饵烂肚
*   **适用场景**: 非法商业爬虫、AI 语料偷窃者、自动化资产抓取器。
*   **攻击引擎 (Rust 业务层下毒)**: 针对已知白嫖特征或不怀好意的扫描流，伪装系统门洞大开并成功吐出关键“机密数据”。但在数据集内悄悄封装入大模型对抗样本（Adversarial Example）、SQL/解析器触发雷、或逻辑死循环炸弹。
*   **敌方损伤**: 白嫖者辛辛苦苦偷走的数据，会直接引发其模型训练崩塌，或者摧毁他们自己的后端图计算引发雪崩。
