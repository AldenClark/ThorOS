# RTL9617C 硬件卸载支持范围

适用范围：ThorOS 的 RTL9617C/77C 原生驱动与 Linux 6.18 bridge、switchdev、nft flowtable 集成。最后更新：2026-11-16。

本文说明当前源码的行为和限制，不是实机验收证书。**当前实现不满足“所有 L2/L3 硬件能力均已完整启用”。** 软件转发可用、控制面已实现、硬件路径已准入、板卡已验证是不同状态，不能相互替代。

## 支持矩阵

| 能力 | 当前实现 | 未完成或有条件的范围 |
| --- | --- | --- |
| VLAN 与 FDB 硬件交换 | 单个合格 SVL 网桥的无标签单播；硬件学习反馈、静态 FDB、CPU 保护条目、所有权与失效处理；VLAN 控制面、域规划及表事务已接入 | 完整 IVL/PVID、VID 0、入口/出口标签编辑、多域同 MAC 的物理路径尚未准入；`ivl-parser-consumer-unverified` 仍会拒绝启用。存在 CPU-owned 动态 FDB 时，该 native 域回退软件，不能宣称所有动态 MAC 均硬件交换 |
| BUM 硬件复制 | 复制组、动作、端口集合、CPU 副本代次和撤销链路已实现 | MCE 冷接管与继承的 L3 生产者状态尚无完整完成契约，生产路径仍拒绝启用；广播、未知单播和未知组播保留 CPU 转发 |
| MDB/组播 | 无标签 VID 0 的 TCP/UDP 数据报精确 IPv4/IPv6 组、ASM/SSM、动态成员/源/路由器端口、逐组回退和容量处理已接入实际 bridge snapshot → MCE → classifier | 与 BUM 相同的物理冷接管门禁仍在；跨策略代次重新发布仍缺 pre-classifier 排空证明。IGMP/MLD 控制报文、标签、其他协议和特殊保留组仍走 CPU；不能宣称动态组播已持续硬件运行 |
| STP、隔离、多桥 | STP 和端口策略同步关闭不再获授权的路径；逐物理端口检查路由输入/输出；受限端口不拖停其他合格端口的独立路由 | 受限 native 端口保留 CPU 路径；完整多桥硬件隔离依赖未准入的 VLAN/IVL 数据面。软件回退不等于多桥硬件支持 |
| PON、L2 与 L3 共存 | 共享资源所有者、端口准入、地址重写引用、PON 变更撤销和普通停启复用；三层仅接受已授权的 flowtable 流 | 不允许未知 PON 继承状态被普通 LAN 初始化覆盖；PON 同口反射、复制引擎重接管及全部业务组合不在已验证范围 |
| 资源和缓冲管理 | 有界表项/队列/描述符、共享引用、初始化回滚、超时隔离、补充 credit、接收公平性和可观测计数 | 完整 L3/DDR/AXI/MCE 退役、热复位后的全量回收与重新绑定尚未闭合；超时不是取消，不能释放可能仍被硬件引用的内存 |

### 三层流量范围

- 经 nft flowtable 授权的受支持 IPv4/IPv6 单播流量使用精确匹配和当前端口代次。
- IPv4 单侧 SNAT/DNAT 保留。扩展模式增加 IPv6 单侧地址、端口及地址与端口同时转换；仅改部分 IPv6 地址字时保留其余地址字。
- 同一物理 LAN UNI 上的 routed 流量可以卸载，包括输入/输出为不同逻辑 VLAN 的路由流量。这不是 bridge hairpin，也不表示已启用 native VLAN 交换。
- 输入和输出均按实际 netdevice 身份验证。STP 非 forwarding、隔离或 learning-off 的受限端口不能通过同口路由绕过检查。
- 双侧 NAT、PON 同口反射、bridge hairpin、未能精确表达的匹配/动作/封装继续由内核处理；本实现不承诺任意隧道、ACL、QoS 或所有硬件模块卸载。

### 动态组播与部分回退

动态成员以 Linux 已物化的转发状态为准。报告或到期操作在改变该状态前同步撤销旧硬件授权，不把计时器已经从队列移除等同于成员已经从转发集合移除。当前要求本机有效 querier 且 query-delay 未生效；仅依赖外部 querier 的组仍走 CPU。

相同目的组中，只有所有对应 `S,G` 都可支持、且有效 LAN 集合与 `*,G` 相同时，才将其折叠为一个 wildcard。集合不相同时，精确 `S,G` 可保留，wildcard 留给 CPU；空源条目、BLOCKED 和不支持的源条目也参与遮蔽判断。容量不足按完整逻辑条目回退，不发布半条规则。

这些控制面能力已经连接实际生产函数，但不能越过支持矩阵中的 MCE 冷接管和跨代次退役门禁。

若该路径未来通过冷接管准入，已硬件复制的包仍保留原包 CPU 副本供 bridge 判定本机接收，代次核验后禁止向 LAN 再次泛洪；未安装或未命中的组则由普通 CPU 路径完整转发。当前物理门禁未开放，且策略变化后的新 epoch 不会自行重新发布。

### CPU 与硬件 FDB 学习的权威性

首次 CPU 学习、MAC 移动、外部学习条目首次被 CPU 接管（包括同端口接管）在发布前同步撤销旧代次。首次无锁查询未命中后，还会在桥 hash 锁内重新查询，避免硬件抢先插入导致 CPU 的新端口观测丢失。

硬件扫描不会覆盖或刷新 CPU-owned 动态条目；这是明确的未拥有条目，不作为 I/O 错误反复触发全域重建。普通 CPU-owned 同端口刷新不每包关闭硬件。

当前 SPB 的部分 CPU trap 不执行硬件源学习。只给 CPU-owned MAC 安装目的 CPU16 保护条目仍不足以观测该源 MAC 后续移动，另一块 ingress classifier 的源 trap 与 FDB/SPB/CF 之间也尚缺本芯片的组合仲裁契约。因此，出现此类动态条目时关闭该 native 域，保留独立 L3 路由许可。这个限制会影响常见的 ARP、DHCP 等先由 CPU 学习的拓扑，不能把默认请求开启解读为这些拓扑已经实现二层硬件加速。

## 默认配置与容量

| 驱动参数 | 默认值 | 作用 |
| --- | --- | --- |
| `native_l2` | `true` | 启动时请求已支持的 native LAN 交换；不强制打开入口。设为 `false` 可保留原先的默认不请求行为 |
| `native_l2_ivl` | `false` | 冷阶段 VLAN 模式选择；改为 `true` 不会解除未验证的 VLAN 数据面门禁 |
| `naptv6` | `true` | 启动时选择 321-bit 有效动作和扩展内部缓存模式；设为 `false` 使用原有普通动作模式并拒绝 IPv6 NAT |

这些参数为启动时只读参数，不提供运行时改写动作格式的入口。普通接口关闭/重开沿用原模式，并核验主表、溢出表、动作 profile 和缓存配置；发现漂移后关闭准入，不在线重建仍可能被硬件引用的表。

| 资源 | 普通模式：`naptv6=false` | 扩展模式：`naptv6=true` |
| --- | --- | --- |
| 主流表索引数 | 65,536 | 65,536 |
| DDR 动作槽步长 | 48 字节 | 48 字节 |
| 使用的动作有效位 | 224 | 321 |
| 内部动作缓存条目 | 2,048 | 1,024 |
| IPv6 单侧 NAT | 不支持，回退内核 | 支持编码与发布，待板卡数据面验收 |

缓存条目数下降不等于主流表容量减半。扩展模式按照固定厂商源码使用配对 SRAM 读取和 384-bit DDR 动作配置；尚未完成两种模式的实机吞吐、突发或时延对比。

运行时 `l2_switch` 仍只表示请求：`1` 请求准入，`0` 同步撤销；重启恢复 `native_l2` 指定的初值。实际状态必须结合 `l2_state` 的 active、reason、error、端口掩码及资源状态判断。原始 `rx_bypass` 保持只读。

## 诊断和故障处理

- `l2_state` 保留一页内的简要状态；详细资源、准入和逐流证据分别位于只读 `l2_resources`、`l3_admission`、`l3_flows`。完整状态采集必须同时读取这些接口，不能继续依赖旧版 `l2_state` 的全部字段。格式上界回归按满宽计数器验证，避免长时间运行后尾部拒绝原因被截断。
- `l2_resources` 输出共享表容量、租约、日志、MCE 与 MDB 状态；`cached=1` 表示仅读取驱动缓存，不触发表扫描。`l2_state` 中的 owner 存在并不表示资源已接管或复制引擎已启用。
- `l2_evidence` 区分上一笔完整事务的 `l2_completed_*` 与当前 `l2_worker_busy` / `l2_pending_*`。原始 preflight 字段与 completed 原因来自同一事务；`l2_preflight_done=0`、`l2_hw_valid=0` 或 `not-sampled` 不是硬件检查通过。direct-CSR preflight 即使遇到 CPU-owned FDB 拒绝也会运行，不创建表项或接管 PON。
- R13 `mce_inherited` 是仅 root 可读的独立实时观测：即使冷接管在 PON 阶段被拒绝，也能在 FE 引擎就绪时连续只读五个直接映射的 FE CSR。`sample_valid` 只代表该字并非全 1，**并不证明时钟就绪或寄存器语义有效**；它不会访问 DMALSO/DDR、间接表或触发写入；`scope=runtime_direct`、`atomic_snapshot=0`、`clock_verified=0`、`handoff_verified=0`、`retirement_verified=0` 和 `missing_contracts=0x1f` 明确禁止用其作为 MCE 冷接管或包退役证据。锁定 SDK 中这五个字为引擎配置，而非直接的 IP/MAC 地址；其原始内部状态仍应在分享前审查和按需脱敏。
- `l3_admission` 按解析原因、安装阶段及实际 errno 计数。其他物理入口的回调单列为 `reject_other_ingress`，非哈希阶段的 `-EOPNOTSUPP` 单列为 unsupported；不能再把所有该 errno 都解释为哈希冲突。请求数、安装数和失败数都是规则操作计数，不是包数或硬件命中数。
- R13 `l3_admission` 增加 `fdb_mode` 阶段及 `fdb_mode_*` 原因计数。路由目的 FDB 的共享 CMD_MODE/所有者预检必须在 Hash、CAM、计数器分配前只读完成；命令提交点仍会重查模式。`cmd_disabled`、`info_init` 等拒绝是硬件安装未被允许的证据，而非启用 CMD_MODE 的授权。旧版本未包含这些字段的采样在离线摘要中仍可区分。
- R14 `l3_admission` 进一步显式分开 `route_policy_admitted`（策略接受）、`route_fabric_ready`、`route_fdb_owner_present/sealed/quarantined`（缓存的安装前提）及 `route_live_cmd_mode_rechecked=0`（本次诊断**未重新读取**共享 FDB CSR）。只有实际安装路径的独立预检才能判断当前 CMD_MODE；策略准入为 `1`、owner 存在或一次历史 CONTROL 采样均不证明硬件已安装流。
- R14 `cold_bootstrap` 增加 `cold_timebase=boottime_ns`、`cold_started_ns`、`cold_finished_ns`、`cold_elapsed_ns` 与 `cold_retry_permitted=0`，都是发布前冻结的历史记录。PON 设备新增**仅缓存**的 `serdes_timing`，输出首次/最近一次 SerDes 初始化的开始、完成时间、次数和配置事务最终 errno，且不触发 PSDS MMIO。它区别于原有 `serdes` 实时状态接口，后者读取硬件寄存器。R14.1 将配置事务的最终 errno 与后续 XGPON warm recovery 更新的运行态 `serdes_error` 分离；读者拿不到互斥锁时立即返回 `available=0 reason=busy retryable=1`，而非阻塞在硬件配置上。尚未完成的时间段在离线解析中标记 `in_progress`，不能据此开放冷接管、IVL 或 MCE。
- `l3_flows` 最多输出 16 条有界、无地址的缓存观测。身份由同一 boot、FE `instance_ns` 与不复用的 `lease` 共同确定；不能仅按可复用的 hash/counter 槽相减。`truncated=1` 明确表示不是全表；`age_hits` 是正的老化采样次数，不是包数；`sample_age_ms` 是最近一次 stats 尝试的年龄，不是最近一次包转发时间。安装成功也不是数据面验收通过。
- `l2_route_eligible_ports` 是逐端口路由许可；`l2_native_route_policy_allowed` 是 native 共享策略许可。二者不能互相替代。
- `mdb_cpu_entries`、`mdb_folded_entries`、`mdb_overlap_cpu`、`mdb_capacity_cpu`、`mdb_dynamic_rows` 表示有界控制面结果，不是硬件命中或已经完成冷接管的证明。
- `naptv6_configured`、`action_bits`、`cache_entries` 和 `cache_action_bits` 显示当前所有者选择的动作/缓存模式。
- `cache_snapshot` 是有截止时间的主动只读诊断，不是转发控制。扩展缓存可观察的签名缺少完整 CRC16 身份信息；稳定候选返回 `identity_ambiguous`、`complete=0` 和 `candidate_*` 差异，不将其报告成目标流命中或失配。普通缓存模式沿用已验证的 set 索引规则。
- 不支持的业务正常留在 Linux；无法确认的共享硬件写入、命令完成或回滚进入隔离状态。此时可能需要设备重启，不支持强制驱动卸载再绑定恢复。

### 冷接管、重试与资源失败路径

CPU 动态 FDB 在 bridge offload/replay 之前只读预检。没有策略、代数、引擎或恢复状态变化的已完成事务，不重复撤销和重放；显式 FE 生命周期变化及最后一笔延迟撤销完成会强制重新协调，不会被普通重复通知去重吞掉。

MCE 在获取 lease 或进行 MMIO 前检查完整组所需的 vector/POL token 容量。部分发布失败时，未曾对硬件公开的尾部资源可以立即撤销；曾经公开的依赖仍受退役契约保护。回滚保留真实的超时或 I/O 错误，不能将其降为普通不支持并重新开放入口。

PON 冷阶段不在 RMW 中重放继承的 PMAC reset/TCONT flush 命令位。接收门禁读回、FIFO 排空和最终 GLOBAL 状态均需核验；PSDS/PDC 与门禁变化的新增缓存快照用于定位拒绝，不是新的写权限或排空 ACK。R13 对 XGPON 冷阶段新增零写入的 PSDS RX/TX/MPCP CKRDY 前置拒绝和 `pon_clock_*` 历史诊断；时钟未准备好时不进入 MAC gate/FIFO，也不在 O5 之后重新尝试所谓的冷接管。即使三个 CKRDY 均已就绪，也不等于门禁写入已有 ACK。XGPON 接收门无法关闭时仍应拒绝接管，不能用经验延时或更大缓冲代替证明。

R14 提供同一 boottime 下的 NI 冷接管尝试与 SerDes 配置历史时间，方便定位启动阶段的依赖关系。该记录仅证明函数执行先后，不代表 PSDS CKRDY、接收门禁 ACK 或 FDB/MCE 完成契约已经满足；未改变冷阶段顺序、接管协议、硬件写入或非授权重试。

MCE 继承状态诊断给出逐寄存器有效位与 `missing_contracts`：CPU XRAM、DMALSO、继承 classifier roots、DDR retirement、MCE packet retirement 分别占 bit 0–4。配置可读、flush 请求已置位或计数暂时不变，均不证明这些消费者已停止。当前缺失的物理契约仍保持阻断。

流量计数发现字节/包差分不相容时，记录 `-ERANGE` 并重建私有采样基线，不把无符号下溢后的巨量字节记到 conntrack。该处理不重置硬件表或改变流的转发授权。

### 实机采集工具

兼容镜像包含 `ip-full` 与 `ip-bridge`，用于获得完整的链路、FDB、MDB 和 VLAN 控制面证据。采集脚本仍兼容工具缺失，使用整数秒等待，保留原始失败、空读取与截断标记；只对明确列出的只读缓存/direct-CSR 接口进行有界重试，主动表读取不重复执行。根权限 `mce_inherited` 的原始配置仅在 `--details` 显式启用时采集；默认保留跳过标记，避免无意公开芯片内部配置。读取失败的半截 FE 状态不得授权后续主动流表遍历。

R14 采集工具额外读取 PON 的 `pon_serdes_timing`（只读驱动缓存），离线摘要产生 `cold_serdes_order`：如 `serdes_after_ni_cold=true` 与有符号的 `start_minus_cold_finish_ns`。对缺失字段、溢出、前后不一致的时间戳保持无效记录；旧版镜像缺少该字段时仅标记不可用，不误判成硬件接管失败。原始采集仍需同一启动周期，不允许把不同重启的时间戳拿来比较。

R14.1 离线工具 `scripts/summarize_tyfza1_datapath.py --redacted-boot-ids <capture>` 仅供复核已脱敏的实验室导出：它会将严格形如 `<BOOT_ID_N>` 的占位符映射为确定性的**虚构 UUID**，保留同/不同启动身份关系，输出 `redacted_boot_identity_replayed=true`；默认模式依旧拒绝占位符。此转换不恢复或验证原始 boot ID，不得当作冷启动连续性或 ASIC 转发的独立证明。新的 R14.1 事务、SerDes sync 用例进入 PR 回归门禁，FDB/MCE 故障变体必须由指定语义断言拒绝，异常退出不能算作通过。

离线摘要始终保留 `hardware_forwarding_proven=false`。它可定位控制面变化与缓存观测增量，但不会自动把这些诊断解释为六项硬件能力已通过实机验收。

## 验证要求

仓库的 PR 检查覆盖三类证据：

1. 执行生产 C 函数的 host 回归、ASan/UBSan 和语义故障变体；模型结果不代表芯片时序。
2. 固定版本厂商源码的真实动作转换器、寄存器字段及缓存访问契约；不从其他芯片位域或空 DAL 接口推导本芯片能力。
3. 实际 ARM64 内核对象、DTB，以及同一完整补丁内核中的 bridge/flowtable 端到端契约。

完整硬件交付还需要隔离测试环境中的冷启动、PON 共存、VLAN 标签矩阵、BUM/MDB 副本、策略变更、异常恢复和压力测试。一次队列空读数、有限包通过或主机测试通过都不能替代全域 drain/退役契约。

固定来源和早期取证见 [厂商契约](rtl9617c-sdk-contracts-20261113.md) 与 [二层证据矩阵](rtl9617c-full-l2-evidence-20261114.md)。历史记录中的默认值和实现进度以本文及当前代码为准。
