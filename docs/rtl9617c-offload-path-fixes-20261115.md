# RTL9617C 硬件卸载路径整改与验证

日期：2026-11-15（北京时间）。基于 PR #20 已合并的远端 `main`：
`81216b82485e970a12b37ab4101e2481d88685e8`，tree
`d66107be2f9666c596927a6085c6f5560ea2a668`。

## 结论

本轮针对“开启硬件卸载反而比软件卸载慢”的上一轮审计，修复已经能够从生产代码或宿主反例确认的问题：下行误拒、规则编译放大、EIF 配方容量、L2/L3 准入耦合、无关/no-op 配置撤流、清理失败的全局阻塞、废弃 Hash 模板，以及 DIRECT 路由/下一跳、同接口 PPP 会话失效和 PPP 内部策略被绕过的问题。

**这不是对约 400 Mbps 实机症状的闭环宣告。** NoDrop、WAN 内部端口映射和完整 TM/TE 基线目前只有代码/SDK 差异证据，没有板级根因证明。本轮补充可安全采集的证据，不用未经验证的全局寄存器修改换取“已经修好”的结论。

PR #20 的 NI 自主冷启动、自动 SVL/MRU 接管、两个生产板型和原生 L2 请求能力均保留。没有停用自动冷接管，也没有把原生 L2 永久改为软件模式。本轮不刷机、不更改运行中路由器配置、不触发固件发布；实际固件开机与吞吐仍须另行验收。

## 一、问题闭环

| 编号 | 核实结果 | 本轮实现 | 主要验证 |
| --- | --- | --- | --- |
| F1 | tagged PPPoE/VLAN 下行被无关 untagged DSCP 属性拒绝 | 去掉全局依赖否决；依照真实 selector 的 stage/row 顺序追踪可达依赖；下行仍验证 wire key、GEM 和所有必要 PCP/DEI 变体 | `test_fe_evto_dependencies.py` 的合法 session 1 / VLAN 41 反例、歧义与真实依赖负例 |
| F2 | 独立逐流统计先占满相同 EIF 配方，第二种配方无法入表 | 先共享已经 ready 的 source-MAC/PPPoE 配方，再申请空行；每配方仅一个 flow 拥有计数，其他 flow 用各自 hash age | `test_fe_interface_capacity.py`、`test_fe_flow_stats.py`、`test_fe_flow_release.py` |
| F3 | 不相关 DSCP 配置把 QinQ 等价求值扩大 64 倍；已有 cookie 还重新编译 | 每模板保守预筛 + 必要时逐候选依赖追踪；现存 cookie 在 `fe_parse()` 前返回；deleting cookie 仍 EBUSY | 真实 selector 对照、旧版本负控、`test_fe_observe.py` 的零 parse 断言 |
| F4 | native L2 不支持 multi-bridge/mixed/VLAN filtering 时，L3 也被关闭 | 分开 native 能力与 routed-flow 策略准入；普通三类拓扑不再全局否决 L3 | `test_l2_switch_worker.py`、`test_l2_switch_control.py`；真实策略 veto 仍拒绝 |
| F5 | 同 namespace 无关设备、相同 MTU/flags、重复模式写入触发 gate/rebuild | 以实际受管设备及上下层关系缩小局部事件；MTU/flags 无变化不建事务；健康同值模式不重建；故障后的同值请求仍可重排恢复 | `test_l2_policy_races.py`、`test_l2_policy_noop.py`、`test_fe_lan_lifecycle.py` |
| F6 | 任何历史删除失败让所有 FLOW callback 先失败 | callback 仅处理自己的 cookie；失败 owner 保留所有权，独立有界 cleanup worker 分批、轮转和退避 | `test_fe_cookie_index.py`、`test_fe_cleanup_isolation.py`、实际表释放故障回归 |
| F7 | 没有生产者的三个旧 bridge Hash 模板仍参与查找 | profile 只启用 routed mask 63；原生 LAN–LAN 保持 switchdev/FDB 路径；拒绝无生产者的旧 bridge rule 安装 | 生命周期冷/温状态回读、SDK profile/tuple bitfield oracle、旧 bridge install 负例 |
| F8 | DIRECT 丢弃 L3 dst 引用，硬件活跃流可能长期保留旧路由或 MAC | 持有 route dst/cookie，CPU lookup 检查双向路由；GC 在 HW stats 续期前验证逻辑 next hop 和 MAC；整连接撤流 | `test_flowtable_direct_route.py`、既有 bridge/GC/work 生命周期回归、实际 ARM64 对象检查 |
| F9 | PPP channel 在接口和 route 不变时重连；旧 ADD 可跨越完整 gate/rearm 后才到达驱动 | 双 PPP 锁串行化奇偶代次；channel 首次发布变更前 gate；nft/xt 路径两侧采样，CPU/GC 校验，FE mutex 内再次检查双向会话；回调独立持有 PPP netdev 引用 | `test_ppp_channel_generation.py` 的真实 connect/disconnect/unpublish、并发、wrap、迟到 ADD 和设备引用；`test_flowtable_partial_offload.py` 的回调接受数量契约 |
| F10 | PPP 的 NPMODE、过滤器和压缩/loop 策略变更不走 netdev gate，可能被 DIRECT 绕过 | 实际内部策略变更使用同一代次与 gate；只在建流时按真实 IPv4/IPv6 检查资格，需软件处理的策略不允许 DIRECT | `test_ppp_flow_policy.py`：native/compat ioctl、四种 FILTER/MULTILINK 编译组合、协议独立正例及运行时缺陷变体 |

### 正确性约束未放松

- 真正影响动作/GEM 的 DSCP、DHCP、标签和多路径歧义仍拒绝硬件准入；不是删判断后强制卸载。跨流编译/负结果缓存不是本轮方案：通过依赖收敛和现存 cookie 快路消除已复现的放大，避免把瞬时 ENOSPC/EAGAIN 或旧策略结果缓存成永久否决。
- F4 只解除拓扑能力限制。STP 阻塞、端口隔离、私有 bridge 策略、显式 TC/qdisc、TCX、XDP、netfilter veto 继续保守处理。新增物理端口的上层 qdisc 检查覆盖真实 adjacency（如 VLAN/bridge）。**PPP/PPPoE 并没有这条 netdev 邻接边**，其变更保留 namespace gate，每个 snapshot 额外一次检查该 namespace 的 PPP qdisc；不能用伪造的 PPP upper/lower 测试图声称覆盖 shaping。
- namespace-global 策略仍由持久 veto 管理。相关硬件的真实配置变化仍有完整 gate/generation 事务；不宣称已经实现每流精细失效或任意 bridge/VLAN 的 native L2 卸载。
- 第一个受管端口加入一个此前没有硬件 lower 的新桥时，同时对端口和桥建立 scope，不能因新桥尚无 lower 就漏掉准入门控。
- 每个失败硬件 owner 的 cookie、EIF、CAM 和 hash 资源仍保留至可证明释放。没有因一次 timeout 就回收可能还在被 ASIC 引用的资源。
- 健康重复配置是 no-op；IO_ERROR、失败 arm 或未完成清理后的重试不是 no-op。交叉审计还复现了“native 不支持或存在 foreign FDB，同时路由 fallback 的 arm 失败”的组合：原错误分类会让恢复请求也变成 no-op。现在失败明确保留可重试状态，覆盖首次及有限自动重试耗尽后的显式恢复。

## 二、修复后的重要行为

### 资源、统计和清理

EIF 的 32 行是输出配方容量，不是连接数上限。相同配方的 64 条流只占一行，保留 31 行用于后续不同配方；仍可支持既有的 4096 流 / 30 配方模型。代价是**不再为了逐流字节统计额外复制配方**：只有当前计数 owner 的 MIB 可用于该流计数，其余流靠自身 hash age 更新 lastused。计数 owner 移交前读新基线，旧共享 flow 不会把同一字节重复计给多个连接。

独立 cleanup 每批最多处理 8 个条目，遇到一次失败即结束当前批次并轮转失败者，退避上限 32 秒。这个上限是队列级退避，不是每个 owner 的即时恢复保证；新健康待清理项可能等待下一批。共享硬件窗口本身仍 busy 时，使用该窗口的操作也仍可能失败。修复的是“无关 callback 被迫先处理旧失败 owner”的全局队头阻塞，不是掩盖硬件故障。

后续深入审计补充了 F6 的必要边界：**age/cache 撤销未证实时，仅保留资源不足以阻止旧硬件动作。** 当前版本会临时关闭 L3 硬件准入，直到全部不确定的 published owner 撤销证实；只有已撤销动作的 EIF/CAM/FDB 等资源恢复失败才保持局部隔离。原生 L2 仍可独立工作。详见 [第二轮深入整改](rtl9617c-offload-deep-audit-20261115.md)，不要将本轮早期的清理隔离理解为“不确定的硬件规则仍可继续运行”。

新增 FE 观测字段包括：`eif_rows_used`、`retry_flows`、`cleanup_backoff_ms`、三个方向的 installed rule 数。方向数量只统计未进入删除状态的规则，明确 `rule_counts_are_hits=0`；不把它们显示成 hit rate。

### DIRECT 失效与时间边界

`222-flowtable-direct-route-validation.patch` 保留真实路由引用，遵循现有 IPv4/IPv6 dst-cookie 语义。next-hop 验证通过保留的**逻辑**路由设备进行，不在错误的最终物理端口上查 ARP/ND；正常 NUD STALE/DELAY/PROBE 属于有效状态，不应因普通邻居刷新就反复清流。PPP/P2P 不用 ARP 检查代替其会话生命周期。

CPU lookup 的路由检查可以让回流包及时退出旧 flow；纯硬件流通过 GC 触发异步撤销。**GC 周期、调度延迟和驱动完成时延仍形成窗口**，这不是零时延、与 FIB/ARP 发布原子同步的 fence。硬件 activity 不能继续把已经检测出失效的规则无限续期。

### PPP channel 交接与迟到安装

`224-ppp-channel-generation.patch` 处理与 FIB 变化不同的会话生命周期：同一个 `ppp` 接口的 channel connect、disconnect，以及 unregister 首次将 `chan` 发布为 NULL 时，先关闭硬件准入，再发布奇偶代次。所有 writer 使用已有的双 PPP 锁串行化；代次绕回零后永久拒绝，避免 ABA 重新认可旧 cookie。不能只在稍后的 disconnect 清表，因为最早的 NULL 发布也已经改变了数据路径。

建流在解析路径前后校验相同 cookie，后续 CPU/GC 只做廉价代次检查，不逐包重跑路径解析。硬件回调借用的 PPP netdev 另行持有引用，不能假设持有 dst 就能永久固定 `dst->dev`。最终在 FE 配置 mutex 内再次校验；若变化发生在校验之后，PPP gate 立即关闭准入，恢复 worker 必须获取同一 mutex 并撤销旧规则后才能重开。

交叉回归发现并修复了这一改动自身的返回值陷阱：`nf_flow_offload_tuple()` 返回的是“成功接受回调的数量”，不是 errno。PPP 前置校验失败返回零；若返回负 errno，上层累加后可能错误设置 `HW_OFFLOAD`。正反例保留了 Linux 允许单方向硬件成功的现有语义，不把这个标志当成双向硬件命中证明。

`225-ppp-flow-policy-fence.patch` 进一步覆盖内部分流策略，而非仅检测 channel 更换：flags 的实际变化、IP NPMODE 变化、native/compat pass/active filter 替换、compressor 安装/关闭，都先 gate 并更新同一 cookie。普通 IPv4-only PPPoE 不会因为 IPv6 的 NPMODE 为 DROP 被关闭硬件卸载，IPv6-only 反之亦然；没有 compressor 的 `CCP_OPEN` 协商也仍允许。已经安装 compressor 时，即使尚未 `CCP_UP`，也不能跳过其对普通包的状态跟踪。

新流的 PPP 策略检查只在路径解析阶段执行；既有流仍通过代次失效。这里是**对不支持的 PPP 处理语义正确回退**，不是实现了压缩、加密、filter 或 multilink 的硬件执行，也没有将正常 PPPoE 一律切回软件。

## 三、SDK 差异：确认了什么，没有改什么

采用固定公开厂商 GPL 镜像，不称为取得 Realtek 官方 NDA SDK。没有将 SDK 源码复制入工程。

| 疑点 | 实际核实 | 本轮边界 |
| --- | --- | --- |
| R1 NoDrop | CPU LAN TX HeaderA bit13=1；HW action 未置 NO_DROP_VLD，实际是继承入口待遇，不等于所有硬件包 NoDrop=0 | 未强开所有 HW NoDrop；需结合 admission、drop、backpressure 实机证据 |
| R2 24→12 vs 24→10 | SDK 不只是 enum 不同，真实 `rtk_8277c_init → asic_fb_init → asic_l2fe_init` 的 mymac/deep 四组初始化都是 24→10；未找到可证明 12→10 别名的代码 | 当前 driver 对 12 有配套 ES/ARB 使用，ITU 软件路径也使用逻辑 24；不能只凭差异认定本次 HW/SW 性能根因。保留映射并显式标记板级契约未证实 |
| R3 TM/TE baseline | buffer/EQ/private/ES 等只有部分初始化，尚不能证明完整 shaping/admission/PFC 契约 | 补 read-only 证据，不盲目照搬整个 SDK reset/init |
| ES speed=6 | SDK 对 QM8、L3 WAN10、L3 LAN13 也使用 6 | 未当作 400 Mbps 固定限速修改 |

依据：

- [ca-network-drivers 固定提交](https://github.com/jameywine/ca-network-drivers/tree/8b4f4882ff0e237a1fa558fb0838e4b680bd6bd0)：`aal-77c/aal_l2_tm.c`、`aal_l2_te.c`、相关 HeaderA/port 头。
- [GPL-for-GP3000 固定寄存器头](https://github.com/jameywine/GPL-for-GP3000/blob/5090fbcb6ba743dd7b1314811ef557bad0460147/linux-5.10.x/include/soc/cortina/rtl8277c_registers.h)：generated union/offset；SHA256 `ce5940a274a14c91e5bf3cf96e4583d2d1d086ae601eb716566dfc70d87633e0`。
- 同一 GPL-for-GP3000 的 `rtk_8277c_asicDriver.c`：真实初始化链与 WAN 映射；这是源级差异证据，不是本板寄存器 readback。
- [Linux 6.18 flowtable 文档](https://docs.kernel.org/6.18/networking/nf_flowtable.html)：异步 HW 安装、软件回退，以及 bridge/HW 缓存目的 MAC/egress 可能过期的限制。
- [Linux 6.18 switchdev 文档](https://docs.kernel.org/6.18/networking/switchdev.html)：bridge/FDB/STP 与硬件交换所有权。

## 四、可用于下一轮实机归因的证据入口

新 `rtl9617c-tm-evidence.h` 与 NI owner 提供两个入口：

| 入口 | 行为 | 注意 |
| --- | --- | --- |
| `fabric_sample` | 显式采样 27 个配置、15 个状态、11 个 PM；RTNL + 单 owner mutex；250 ms 限频 | 不写 MMIO、不访问 ARB 等间接窗口；**读取 PM 仍可能消耗 clear-on-read 计数**，不能作为普通 UI 轮询 |
| `fabric_evidence` | 只复制缓存，零 MMIO | 带 seq、epoch、owner_generation、时间窗、有效位和原始配置；旧缓存不等于当前硬件状态 |

BM 的 clear-on-read 语义由 L2TM GLB_CTRL bit31 控制，已通过 SDK 行为及真实 generated union 核对。**L2TE PM_CTRL bit5 描述的是间接 PM MEMORY**，不能移用为直读 TE drop 寄存器的语义，所以 TE 始终 raw-only，既不做 delta，也不推算速率。

BM 的“已观测增量”排除首样本之前的启动流量；配置变化、NI start/stop/poison 代次变化、下降/饱和、时钟异常等均切断 epoch。它不证明没有外部读者、未观察到的硬件 reset 或 ABA，因此输出一直保持 `hardware_reset_verified=0`、`atomic_hardware_snapshot=0`，作用域为全 fabric，不能直接归因到某一 LAN/flow。

`observe_tyfza1_datapath.sh` 默认仍只读缓存；仅 `--active-diagnostics` 主动触发 sample。离线 `summarize_tyfza1_datapath.py` 校验 sample ack、缓存年龄、seq/epoch、NI owner、时钟、配置和计数集合；数据不完整或跨 owner 时拒绝生成差分。TE 原始值、FE rule 数、Linux/CPU 计数不会被冒充为 ASIC 命中率或物理 LAN 吞吐。

## 五、验证与证据层次

验证入口已经接入 PR 的自动检查，不需要触发固件构建：

1. `scripts/check_firmware_prebuild.sh`：现有冷接管/native L2/QM/DMA/生命周期回归，加上本轮 EVTO 依赖、清理隔离、统计和 TM summary。
2. `scripts/check_sdk_contracts.sh`：固定 commit 下载，再核对文件 SHA256；新增 TM/TE 语义 oracle，扩展实际 route profile/tuple bitfield 校验。
3. `scripts/check_kernel_objects.sh`：完整锁定 Linux/OpenWrt patch stack，实际 66 个 ARM64 对象及两个生产 DTB；新增 patch 的调用者也纳入对象覆盖检查，包括 `xt_FLOWOFFLOAD`，不只编译 nftables 路径。专用编译检查片段同时启用 COMPAT、PPP_FILTER、PPP_MULTILINK，覆盖相关代码分支，但不改变固件的 package 配置。
4. `scripts/check_flowtable_contracts.sh`：同一个完整准备内核中的 13 项真实生产函数 contracts；新增 DIRECT route/next-hop、no-op policy、PPP channel 生命周期及内部策略测试。

宿主执行使用 ASan/UBSan；本地 ptrace 环境不支持 LSan，因而本地关闭 leak detector，但没有关闭地址/未定义行为检测。Mock 用来提供 MMIO、内核对象或调度边界，不等于在芯片上执行。实际对象编译只证明编译/API/DTB 契约，不等于最终固件链接或设备启动。

完整测试和编译状态以本提交对应的 PR checks 为准。即使上述检查全部通过，也不能替代下一节的实机验收。

### 规则编译的前后对照

在同一 x86_64 / AMD EPYC 9V74 宿主上，用 GCC 14.2 `-O2`、进程 CPU 时间，交替执行旧/新各五次；每样本处理 200 条合法纯 IPv4 QinQ 规则。旧源码来自与远端基线完全相同 tree 的本地审计镜像 `79de9ec`，不是另一个固件版本。

| 版本 | unmarked mapper | 中位 CPU 时间 | 五次范围 | selector 求值/规则 |
| --- | --- | --- | --- | --- |
| 修复前 | 关闭 | 1.306 ms | 1.264–1.473 ms | 256 |
| 修复后 | 关闭 | 1.306 ms | 1.276–1.396 ms | 256 |
| 修复前 | 开启但不作用于当前 tagged 业务 | 84.203 ms | 80.167–93.207 ms | 16,384 |
| 修复后 | 同上 | 1.387 ms | 1.296–1.407 ms | 256 |

可复现入口为 `python3 scripts/test_fe_evto_dependencies.py --benchmark-only`；比较历史源码可加 `--revision REF`（该 REF 必须在运行者仓库中存在）。精确的变化是当前无依赖分支的 selector 工作量减少为 1/64。它测的是建流 helper，不是 GCC 编译时间、逐包转发或路由器吞吐。

历史源码的两个独立负控均在运行时断言失败：`--revision REF` 捕获 tagged 下行误拒；`--upstream-cost-only --revision REF` 捕获合法单 VLAN + PPPoE 上行 1,024 次而非 16 次求值。新代码的依赖追踪另通过 1,320,480 次真实 selector 对照；这些计数并不等于实机覆盖率。

## 六、仍需实机完成的闭环

下一轮先记录准确固件提交、物理口、方向、PPPoE/VLAN/GEM 配置和同一组测试端点，在一致条件下做软件/硬件对照：

1. 两板型冷启动及 warm open；LAN 管理链路正常，自动 SVL/MRU 未回退，native L2 请求在支持拓扑可进入 active。
2. LAN→PON 和 PON→LAN 分别观察安装/拒绝、软件回流、CPU 负载；不能只看 conntrack 的 HW_OFFLOAD 标志（允许单方向成功）。
3. 同网段 LAN–LAN 单独测 native FDB，不与 routed flowtable 混为一种开关；检查 STP、隔离、软件策略和异常恢复。
4. 变更 route/next-hop/邻居 MAC，确认两个方向在预期 GC/删除窗口退出旧硬件规则；邻居正常刷新不反复清流。另测相同 PPP 接口的断线重拨、channel unregister，以及并发建流，确认旧 session 不会在恢复后重新安装。PPP filter/NPMODE/压缩策略生效时不得被 DIRECT 绕过，恢复普通双栈或单栈配置后能重新卸载。
5. 大流量时对照 BM/TE、buffer-free、FC/pending 和端口计数，再决定 NoDrop、24→12 映射或 TM/TE admission 是否需要板级行为修复。

在这些证据取得前，不宣称所有硬件语义已经确认、不承诺线速、不把规则编译的宿主加速倍数换算为 RTL9617C 的 Mbps 提升。
