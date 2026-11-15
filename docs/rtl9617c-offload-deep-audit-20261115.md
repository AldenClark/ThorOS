# RTL9617C 硬件卸载：第二轮深入整改

日期：2026-11-15（北京时间）。基线是 PR #21 的远端提交
`f074f2edb1253dfa06d8f0fe75ab882f371ef06e`，内容树
`d05454cef2b7a26d18b6b924e22eb90f75a1c7ad`。

## 结论与范围

本轮继续检查硬件建流、撤流、路由与 PPP 生命周期、native L2、NI 发送和恢复。
确认并修复六类问题，新增修复经过独立交叉复审与生产函数回归。
**没有连接、改配置、重启或刷写用户家中的设备。自动 SVL/MRU 冷接管与原生 LAN–LAN L2 能力保持，不以关闭它们代替修复。**

本报告区分三种证据：实际生产代码中的错误、可控宿主后端复现的行为、仍须实际芯片验证的结果。
这些改动不等于已经证明“硬件卸载慢于软件”的全部根因，也不承诺一个未经测量的 Mbps 数字。

## 一、确认的问题与实现

| 编号 | 原问题 | 本轮实现 | 核实方式 |
| --- | --- | --- | --- |
| D1 | 普通 Ethernet/VLAN 和 PPPoE 解封装的路由 MTU 没有进入硬件动作；只有 PPPoE PUSH 携带 MTU | patch226 将每方向的逻辑 L3 MTU 传给 routed REPLACE；FE 必须验证并使用显式 MTU 槽；PUSH 的 MTU 与路由元数据必须一致 | 旧 parser 的普通 IPv4 反例失败；真实 NAT/IPv6/VLAN/PPPoE builder + parser；实际 install 动作位；16 槽资源测试及独立 SDK 位域 |
| D2 | dst 可以原地改变有效转发 MTU而不改变 route cookie，硬件活跃流可能长期保留旧 MTU | patch227 在 DIRECT CPU lookup 与 GC 续期之前比较有效转发 MTU；任一方向失效撤销整连接 | 提取真实 IPv4/IPv6 MTU helper 和原地 route 更新函数，51 场景、6 个错误变体 |
| D3 | age/cache 撤销超时只保留资源，没有阻止旧硬件路由动作继续被命中 | 每 flow 记录未证实撤销状态；累计待撤销数量，立即关闭 L3 硬件准入；优先完成此类撤销，证实后再协调恢复 | 真实 delete/cleanup/route helpers：双 owner、不同完成顺序、部分安装、两侧 gate 读回失败、shutdown；8 个错误变体；disabled + pending 的真实 L2 arm |
| D4 | 共享目的 MAC 的第一个 owner 正在删除时直接 EBUSY，即使稍后还有健康共享 owner | 继续寻找 live + ready owner；只存在 retiring owner 或遇到未就绪 writer 时仍拒绝 | 2 种原表状态 × 2 种 owner 顺序 × 6 种释放顺序；24 组真实 get/put；旧代码运行时断言失败 |
| D5 | NI 空闲后短突发耗尽 DMA 描述符，BUSY 只停队列，可能继续等待之前 4–10 ms 的空闲 timer deadline | 仅在 LAN/PON 发送返回 BUSY 时把较远 deadline 提前到 1 ms；不推迟已有更早 deadline；初始 start、callback 与 kick 在同一 TX 锁下发布 deadline | 150 场景，其中 125 个受控 callback/stop/实际 warm-start 时序；6 个错误变体被拒绝；核对真实 hrtimer 队列契约 |
| D6 | 健康状态重复写相同 native L2 开关，仍触发撤流、FDB 恢复和重建 | 只有已经完整提交且 guard 代际一致的状态才 no-op；失败、能力回退、未释放 owner、代际变化等仍允许同值重试 | 51 场景：200 次健康重复操作，14 类异常/代际条件、8 类关态遗留 owner 和同步停用失败重试 |

### D1：使用路由 MTU，而不是最后物理端口的 MTU

`flow_cls_offload.route_mtu` 只由路由型 flowtable 的 REPLACE 填入；STATS、DESTROY 和非路由规则不伪造这个元数据。
来源就是软件路径使用的 `tuple->mtu`，因此覆盖 VLAN upper、路由显式 MTU、PPP 上行，以及 PPP 解封装后通往 LAN 的下行。

FE 对缺失、零值、超出 14 位硬件范围的 MTU 拒绝硬件准入，保留软件路径。
不是把不支持的值截断到寄存器，也不是用最后一个 physical netdev 的 MTU 代替逻辑路由约束。
PPPoE PUSH 不额外再减 8 字节：其 tuple 已经是封装前的逻辑 IP MTU。

16 个硬件 MTU selector 仍按相同数值共享，只有首次申请和最后释放访问对应寄存器。
4096 个 owner / 4 种 MTU 只占 4 个 selector；第 17 种同时在用的 MTU 正确返回 ENOSPC。
释放一个 14 位半字不改动同寄存器另一个仍被使用的 selector 或 reserved bits。
SDK 模式使用未经改写、SHA256 固定的 generated union 验证全部 16 个地址与位域。

### D2：失效检查使用真正的 forwarding MTU 语义

比较逻辑与 `flow_offload_fill_route()` 一致：IPv4 使用
`ip_dst_mtu_maybe_forward(dst, true)`；IPv6 使用
`ip6_dst_mtu_maybe_forward(dst, true)`。

- IPv4 默认不使用的学习 PMTU 变化，不会无故清理转发流。
- IPv4 `ip_fwd_use_pmtu`、MTU lock、现有 exception 的更新与到期按实际 helper 生效。
- IPv6 未锁定的学习 PMTU 不被错误当作转发 MTU；`mtu6`、locked metric 和有效变化会失效。
- 增大、减小、到期恢复以及 helper 的 headroom 处理都有对照。

没有逐包重做路由解析或邻居查找。纯硬件命中流不增加 CPU 逐包处理。
CPU 回流和 GC 增加的是同一 dst 的有效 MTU 校验。

**这是现有异步 flowtable 模型下的过期修复，不是逐次 FIB/PMTU 更新的同步 fence。**
若原地 MTU 更新恰好遇到 pending ADD，旧动作仍可能短暂先发布，随后由有效 CPU lookup / GC 成对撤销。
行政 netdev MTU 更改的既有同步 fabric gate 仍保留；不能把它与普通 PMTU 的 GC 窗口混为一谈。

### D3：把“旧动作仍可能存在”与“资源尚未释放”分开

上一轮的清理隔离解决了任意旧失败 owner 阻塞所有 callback，但需要补上这条正确性边界：
**资源保留可以避免复用错误，却不能自行停止过期硬件动作。**

当前状态处理如下：

| 状态 | L3 硬件准入 | 原生 L2 | 资源与恢复 |
| --- | --- | --- | --- |
| age 或 cache 撤销未证实 | 关闭；任何 arm、同值 enable、其他 reconcile 均不能绕过待撤销计数 | 验证过的 CPU-only L3 gate 不妨碍独立 native L2 | 保留 hash、cookie、FDB/EIF/CAM/MTU owner；有界 cleanup 重试 |
| 所有 hash/cache 撤销已证实，但部分资源 restore 失败 | 可正常协调恢复 | 仍按自身策略判断 | 仅保留相应未释放 owner，不继续全局暂停路由卸载 |
| gate 寄存器写入未能读回确认 | 禁止软件声明已重新准入；`route_gate_verified=0` | 后续 arm 必须重新证实门控，否则不发布成功 | 不能声称已阻断物理流量；保留未证实撤销 owner，不回收可能仍被引用的资源 |
| 正在 shutdown | 不重新准入 | 不重新启动 | 不排新恢复任务；既有硬件/DMA 生命周期隔离仍保留 |

清闩发生在 age=0、DDR key 清除与 DMA barrier、cache invalidate 全部成功之后，不能只因 age 成功就清除。
重复失败不重复累计同一个 owner；两个 owner 中只完成一个也不能重开。
最后一个完成时排队恢复，不在 FE mutex 下等待 RTNL。

交叉审计补上了两个组合边界：

- `enabled=0` 不代表失败的旧硬件动作已消失。即使已经停用 L3，仍有 pending owner 时，native-only arm 也必须在开放 RX/native selector **之前**验证 CPU L3 gate；验证失败不能以“现在只开 L2”为理由跳过。
- cleanup 优先处理 `withdrawal_pending` owner，不能让一个已经无硬件动作、只剩 EIF/CAM restore 失败的条目反复挡住恢复。首次全局 0→1 且已有长退避时，将重试一次性提前到 1 秒；重复 callback 或第二个 pending owner 不反复改 deadline。若本轮 A 已撤销、只在资源恢复失败，仍有 pending B，则旋转 A 并在剩余预算内继续 B；未证实撤销的真实失败仍退避，不忙重试。20 个部分成功 owner 的回归确认严格按 8 / 8 / 4 推进；pending 清零后恢复普通资源清理和失败退避。

新增可观察字段：`route_withdrawals_pending`、`route_gate_verified`。
后者只表示 CPU profile gate 的回读证据，不表示所有硬件 pipeline 已经 drain。
D4 的共享查找修复也不能绕开本节的全局正确性门槛；不宣称 hash 撤销不确定时仍允许无条件建流。

### D5 / D6：有明确边界的性能改进

NI 调整只作用于已经返回 BUSY 的生产者。正常发送不会每包重启 timer，空闲仍保持 1–10 ms 配置策略。
连续 BUSY 重试不会把更早的 timer 一直向后拖延。
stop 先撤销 host ownership，再在 TX/RX 锁外 cancel；新 callback 的状态检查避免停机后重启或额外访问 DMA。

第三轮以真实 `kernel/time/hrtimer.c` 复审时还发现：原 `rtl_engine_start()` 发布 host 后在锁外启动 timer；warm close 保留满 ring 后的 reopen 中，独立于 RTNL 的 PON recovery probe 可能先触发 BUSY kick 并启动 timer，迟到的初始 start 因而可能与 callback 的 `hrtimer_forward_now()` 并发。当前首次 start 也移入同一 TX 临界区；回归提取真实 engine_start 执行该时序，不再用手写 `host_active=true` 代替启动过程。

在可控时钟模型中，默认 4 ms 的空闲 deadline在 BUSY 发生后被提前至不超过 1 ms；10 ms 配置同理。
这是 deadline 的逻辑界限，不是对真实 Linux 调度延迟、IRQ 延迟或端到端吞吐的承诺。

L2 同值优化要求完整的已提交状态，而不是只检查 `error == 0`：
engine 在线、guard 已注册且未阻塞、route generation 一致、没有 replay/错误/未证实撤销；开态必须 native active，关态必须清完相应 native ownership。
因此 foreign FDB、能力回退、故障恢复或 pending state 仍可显式同值重试。

## 二、审计与验证层次

1. 并行查阅生产路径与锁定 Linux/公开 SDK 参考，先形成可复现反例，再改生产代码。
2. 实施者运行定向测试；其他审计者独立复核 MTU、FE withdrawal 与 native L2、PPP/GC、定时器并发组合。
3. 汇总后执行完整预构建、完整准备内核上的 flowtable contracts、独立 SDK 位域检查，再由 PR checks 做真实 ARM64 编译与全套检查。

主要入口：

- `scripts/check_firmware_prebuild.sh`：原冷接管、native L2、PON、QM/DMA、资源生命周期回归，新增 MTU 池和 NI deadline 测试。
- `scripts/check_flowtable_contracts.sh`：在完整 Linux 6.18.60 / OpenWrt patch stack 上运行 14 项生产函数 contracts。包括 51 个 MTU 场景、66 个 DIRECT 路由场景、4026 个 PPP generation 场景及相关错误变体。
- `scripts/check_sdk_contracts.sh`：新增全部 MTU selector 与固定 SDK 寄存器头的独立对照，不将厂商源码复制入工程。
- `scripts/check_kernel_objects.sh`：既有 66 个 ARM64 对象与两个生产 DTB 检查，额外把 patch226/227 的调用者纳入覆盖断言。对象编译不是完整固件链接，也不是设备开机。

宿主模型使用 ASan/UBSan；本地 ptrace 环境仅关闭不支持的 leak detector。
时钟、MMIO、设备与内核对象的模拟是测试边界，不冒充芯片执行。
历史 parser、destination-sharing、withdrawal 实现均能被相应新测试以运行时行为断言识别；错误变体用于确认关键判断被测试覆盖。
准确的远端编译与回归结果，以本轮提交在 PR #21 的 checks 为准，不沿用上一提交的成功状态。

## 三、仍不能用离线审计代替的验证

没有对 NoDrop、WAN 24→12 映射或 TM/TE admission 全局设置作猜测性修改。
这些差异仍缺板级证据，既不能证明是本次约 400 Mbps 症状的原因，也不能证明没有影响。
MAC owner 查找最坏仍有线性扫描，但普通共同 WAN 网关通常首个 owner 即命中；本轮没有为未测定瓶颈另造索引架构。

实机可用后需分别验收：

- 两板型断电冷启动、LAN 管理访问、自动 SVL/MRU 接管、受支持 native L2 的 active 状态。
- 同端点、同方向的 LAN→PON、PON→LAN 软件/硬件对照；同时记录规则准入、实际回流、CPU、BM/TE 与端口计数。
- LAN–LAN 原生 FDB 路径单独验证，不能把 routed flowtable 开关当作完整 L2 的命中证据。
- 低 MTU VLAN/路由、PPP 双向、IPv4/IPv6 超长包和 PTB 行为；变化/恢复后旧规则最终撤销。
- 短突发、持续满载、双向竞争和关停/重启，不只测单次长期大流。

**本轮的交付是更多经过反例验证、交叉复审的代码级正确性与控制路径性能修复；不是未经实机证明的线速声明。**

参考：[Linux 6.18 flowtable](https://docs.kernel.org/6.18/networking/nf_flowtable.html)、
[公开厂商驱动固定提交](https://github.com/jameywine/ca-network-drivers/tree/8b4f4882ff0e237a1fa558fb0838e4b680bd6bd0)、
[固定 generated 寄存器头](https://github.com/jameywine/GPL-for-GP3000/blob/5090fbcb6ba743dd7b1314811ef557bad0460147/linux-5.10.x/include/soc/cortina/rtl8277c_registers.h)。
寄存器头 SHA256：`ce5940a274a14c91e5bf3cf96e4583d2d1d086ae601eb716566dfc70d87633e0`。
