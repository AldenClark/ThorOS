# RTL9617C 实机前准备：可复现、默认被动的数据面证据

日期：2026-11-14。此工具准备不等于已经完成实机验证，也不证明硬件交换已上线。

本轮扩展既有 `scripts/observe_tyfza1_datapath.sh`，没有另建一个不同步的采集器。
`observe_wired_offload.sh` 继续作为兼容入口，默认间隔仍是 10 秒。

## 使用方式

将独立采集脚本复制到测试设备。它不自动建立 SSH、不请求凭据、不发起流量、不改变接口和卸载开关：

```sh
sh observe_tyfza1_datapath.sh 15 --output /tmp/tyfza1-passive-01.txt
```

`--output` 只创建**不存在的新文件**，权限为 `0600`；存在的文件、符号链接、FIFO 一律拒绝，不覆盖历史证据。
如果仍用 `> file` 的旧用法，文件由调用者的 shell 创建，必须自行控制其权限，脚本不能补救已经打开的 stdout。

将结果带回工作机后，使用纯离线、Python 标准库的分析器：

```sh
python3 scripts/summarize_tyfza1_datapath.py tyfza1-passive-01.txt
```

它只打印经过筛选的 JSON，不连接路由器，不执行输入内容，不写回日志或系统。
新分析器只接受 v3 格式；旧日志缺少 boot/采样窗口标识，不能补造可靠速率。

## 默认采集的内容

| 类别 | 内容 | 不能据此推断 |
| --- | --- | --- |
| 固件/板型 | 内核、OpenWrt revision、ThorOS commit/dirty/source lock、DT model/compatible、可用 SoC family/id/revision | DT 声明不等于硅片 stepping 已实测；缺失信息明确 unavailable |
| 连续性 | 两次快照起止 uptime 与 boot ID；缓存 LAN MIB 样本使用 BOOTTIME（含 suspend） | 两个端点不能排除中间发生又恢复的策略变化或计数器重置；`l2_evidence` 的 MONOTONIC 时间不拿来混算 |
| 接口拓扑 | 最多 32 个 netdev 的 ifindex、iflink、dev_port、MTU、协商速率、duplex、carrier、master ifindex、可用 bridge/port 属性；不按 lanN 名字筛选 | iflink 不是物理端口号，其他驱动默认 dev_port=0 不代表同一 ASIC；应匹配 MIB exporter 提供的真实 ifindex，PCB 丝印还须实测 |
| FE/L2 | 请求、活动状态、回退原因、LAN 实际 bypass mask、基础 owner/隔离状态 | `requested=1`、`active=1`、HW flag 都不是流量命中证据 |
| `l2_evidence` | 新驱动提供的直接配置/状态读取；旧固件缺失时明确报告 | 不触发复制表遍历，不把 MCE 控制值当作已验证 token/退休语义 |
| NI/QM | `xram_state`、`qm_voqs` 软件累计 CPU 计数 | Linux host/QM CPU 字节不是 ASIC LAN MIB，不能直接计算硬件卸载比例 |
| 缓存 LAN MIB | `lan_mib_evidence` 的既有后台/OAM 样本，物理 NI port、当前 ifindex、raw counters、seq/error/时间窗/配置 | getter 不访问硬件，不新增轮询；`counter_mode_verified=0`，当前只保留原始观察，不把它当可靠累计量或 L2FE 命中计数 |
| 主机负载 | CPU/softirq/interrupt/softnet、Linux netdev 计数、conntrack 数量、选定内存指标 | 不是端到端吞吐测试，不包含 conntrack 会话内容 |

默认不读 FDB 行、原始包、IP/路由/邻居/完整 nft 规则、PON 身份、WAN 凭据、设备 serial 或其他配置。
不自动挂载 debugfs，不写 sysfs，不执行 `devmem`、`ethtool` 修改、服务重启、重拨或流量压力测试。
采集的是已有统计读取和新加的配置证据，**不是“全 ASIC MIB 已无副作用导出”**。

## 主动诊断与隐私是两个独立选项

原默认采集路径会读 `fe/flows`（触发间接表事务）、`qm_state`（旧版本还会写全局 monitor selector），
以及 `dma_state`（含 AXIM2 interrupt status，其 read/clear 副作用尚未确认）。
仅仅以只读方式打开 sysfs/debugfs 文件，不足以声称内核 getter 没有硬件副作用。
因此 v3 默认跳过这三项，并输出具体跳过原因；仅用 `dma_state` 文件存在性定位 NI，不读取它的值。

受控维护环境确实需要这些诊断时，可明确请求：

```sh
sh observe_tyfza1_datapath.sh 15 --active-diagnostics --output /tmp/tyfza1-active-01.txt
```

这会允许现有 FE 间接读取和 QM/DMA 状态读取，仍限制 FE 条目数（最多 64 的准入快照）、每次命令时间和打印大小；
但无法保证表不会在检查后增长，也不把超时解释成内核事务已取消。旧固件的 QM getter 可能改 monitor selector。
该结果明确标记为有扰动诊断，不能与被动测量混作同一观察条件。

`--details` 仅允许显示 IP/MAC/端口/会话字段，**不隐式开启主动诊断**。
需要完整 FE 明细时两个选项必须同时指定；结果仍可能敏感，分享前需要检查。

## 边界与失败处理

- 可选探测必须有 `timeout`，每个探测 3 秒，直接向目标进程发送 KILL；没有该工具时跳过，不回退成无界 I/O。
- 普通文件读取限制 16 KiB、1024 行、每行 4096 字节；接口最多 32 个。截断和超时均留标记。
- Linux D 状态中的不可中断硬件 I/O 不能被 shell 的超时硬实时终止；不对已卡死设备持续重复探测。
- 间隔 1–3600 秒指两次采集之间的等待，不是总耗时；实际窗口使用 uptime 起止值。
- 默认输出与新文件的内容不自动上传任何服务；输入环境覆盖变量仅用于隔离 fixture/明确指定设备路径，不会推测新的设备地址。
- 采集会占用少量 CPU，且系统状态持续变化。它是两次**非原子**快照，不是零扰动测量或 ASIC 模拟。

## 离线判定不会越过证据

分析器最多读 2 MiB；不接受重复快照/重复 section，不以 last-wins 隐藏损坏数据。
两个快照之间的 boot ID 必须一致，单调时间必须构成不重叠采样窗口。
速率给出窗口的最小/最大范围，纳入 `/proc/uptime` 的 10 ms 截断精度，不拿脚本请求的 15 秒当成实际采样间隔。
累计值先用 Python 整数相减，避免大于 `2^53` 的累计字节产生浮点精度丢失。

主机/QM 计数器下降只报告 `reset_or_wrap`，**不猜测回绕位宽**；接口 ifindex、iflink、master、bridge 属性、速率等端点变化时拒绝对应比较。
QM CPU 比较还要求 NI 生命周期字段在两端都是 ready/active、无 poison/需重启状态。
缺字段、探测失败、截断、只有前快照都不会变成“零丢包”或“硬件已命中”。
失败/截断标记即便粘在未输出换行的上一字段之后也优先判为无效，正常 `master_ifindex=unavailable` 不视为探测失败。
FE counter row 可能复用，当前没有稳定 generation，因此分析器不自动对 FE 行求吞吐差分。
缓存 MAC MIB 单独验证 `clock=boottime`、显式 read opcode0、完整 5 行与 registered mask 的一致性、
registered/valid/error、真实 ifindex 与两端接口 `dev_port`/bridge 属性映射、递增 seq/attempts、
`attempts >= seq` 及最后 error=0 的 attempt 时间与成功样本时间一致、样本时间顺序、
成功样本距捕获不超过 3 秒，以及样本内/跨样本原始计数配置没有变化。
失败读取留下的旧缓存不会当成最新计数；配置缺失、非数值、跨样本变化时拒绝观察比较，同值不等于配置语义已经验证。

目前 SDK 同时出现 global mode 的“clear on read”描述与显式 opcode0 的“不清零”描述，优先级尚无足够依据闭合。
因此这一版始终记录 `counter_mode_verified=0`；即使上述采样检查通过，摘要也只输出每口的 before/after raw 值与对应窗口，
标记 `raw_observations_valid=true`、`valid=false`、`counter_continuity_unverified`，**不生成 MAC 差分、Mbps 或包速率**。
不能通过把输入 header 改成 `counter_mode_verified=1` 就绕过这一边界：未知 schema 被拒绝。
也不使用旧软件累计扩展值掩盖 reset/wrap，或假装 5 个端口是同时锁存。
即使所有状态都稳定，输出也始终保留 `hardware_forwarding_proven=false`：完整 LAN–LAN 验收还需要两台外部测试主机、
明确端口映射、帧计数/CPU 路径证据及策略切换/异常恢复测试。

## 宿主回归

```sh
python3 scripts/test_datapath_observer.py
python3 scripts/test_datapath_summary.py
```

覆盖真实采集脚本的隔离 sysfs/procfs、缺少 debugfs/timeout、真实 userspace hang、默认隐私、主动/隐私权限分离、
输出权限/拒绝覆盖、读取截断、生命周期/拓扑/boot 改变、精确 64-bit 差分、reset/wrap 和损坏输入。
这些测试不执行真实 MMIO、不声称完成硬件或吞吐验证。
