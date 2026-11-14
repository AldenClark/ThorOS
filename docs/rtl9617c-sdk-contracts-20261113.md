# RTL9617C SDK 对照契约与验证边界（2026-11-13）

本文记录本轮实际读取的外部参考、可重复的独立 oracle 与其证明范围。
它不是整仓整改报告，也不是芯片认证或 400 Mbps 问题的实机根因报告。
生产目录为 `port/overlay/target/linux/rtl9617c/files-6.18/drivers/net/ethernet/realtek/`。
以下源码行号均对应锁定提交；后续修改 ThorOS 不应改变外部参考含义。

## 1. 来源、版本与可信度

| 标识 | 锁定仓库与提交 | 实际使用路径 |
|---|---|---|
| SDK-NE | [jameywine/ca-network-drivers][ne-root]，`8b4f4882ff0e237a1fa558fb0838e4b680bd6bd0` | `ca-network-engine/1.0-r0/ca-network-engine-1.0/aal-77c/` |
| SDK-REG | [jameywine/GPL-for-GP3000][reg-file]，`5090fbcb6ba743dd7b1314811ef557bad0460147` | `linux-5.10.x/include/soc/cortina/rtl8277c_registers.h` |

SDK-NE 是包含厂商署名实现的公开 GPL 源码镜像；SDK-REG 是同系列实际 silicon generated register header。
本轮没有用 FPGA header、其他 RTL960x 芯片资料或 ThorOS 手写位域替代这个 header。
这些 GitHub 镜像不是 Realtek 官方认证渠道；源码中的 workaround 注释不是已取得的正式勘误文件。
未取得完整 RTL9617C 编程手册、芯片 stepping 对应 errata、时钟/带宽参数和所有寄存器时序说明。
外部 SDK 保持独立，不把整份 SDK 或私有模块纳入产品源码。

### 1.1 自动校验的输入摘要

路径相对于 SDK-NE 的 `aal-77c/`；最后一行相对于 SDK-REG 仓库。

| 文件 | SHA256 |
|---|---|
| `include/aal_common.h` | `6b5b388ed35fd7dd9b91115961da41551b143948e67e50c7f3ae6390817a4b98` |
| `aal_common.c` | `5348dbc331aebab85231788229b3ddb70cba85437abebb6519ce4fe77907c2db` |
| `include/aal_hash.h` | `e9771a58e015ac5aa0e844be74e1b225daa8ebd90a63ffba60a35aeb3b6556c8` |
| `aal_hash.c` | `679ca0a0a8588b3af5a3b04e0ce242636b6d723741a7ef8c5ed04b592035f3ea` |
| `aal_l3qm.c` | `afd977c54889b62866a90f484169de2971301ba93283a3a3c3a11b13cc73720a` |
| `linux-5.10.x/include/soc/cortina/rtl8277c_registers.h` | `ce5940a274a14c91e5bf3cf96e4583d2d1d086ae601eb716566dfc70d87633e0` |

这六个内容摘要由下面的 oracle 校验；仅提交号或文件名相同不足以绕过校验。
新增 L2 oracle 另逐文件校验 `aal_fdb.c`、`aal_l2_classification.c` 及 FDB、port、arb、QOS、VLAN、CLS/LPB headers；完整摘要在测试的 `SDK_FILES` 清单。
`aal_pdc.c` 等人工交叉阅读资料以 SDK-NE 锁定提交为准，不冒充额外自动输入。

## 2. 独立 oracle：验证了什么

| 测试 | 独立输入与执行方式 | 本轮结果 |
|---|---|---|
| `scripts/test_fe_sdk_contract.py` | 提取真实 SDK bitfield、normal action converter、masked-key/CRC 函数，编译实际 ThorOS header 和运行时 route mask | PASS |
| `scripts/test_fe_register_contract.py` | 从 SDK-REG 提取真实地址宏和 union，解码生产 FE helper 产生的寄存器内容 | PASS |
| `scripts/test_qm_sdk_registers.py` | 真实 SDK-REG union、16 个地址宏及 SDK `aal_l3qm_get_buffer_size_index()`，解码生产 QM/DQ 初始化 | PASS |
| `scripts/test_pon_sdk_registers.py` | 真实 SDK-REG union 解码生产 PDC/PVT/VSTBL/CIR/PIR 写入 | PASS |
| `scripts/test_l2_sdk_contract.py` | 真实 register unions、SDK FDB MAC encoder、PONCLE encoder、MAC-limit 实际操作函数及 CLS/LPB 类型 | PASS |
| `scripts/test_fe_base_contract.py` | 真实 CLS mode0 字段、第二行 format、LPB v32 与 STG0 generated unions；提取生产 readback 掩码并运行三个错误变体 | PASS |

这些外部 oracle 均已执行，使用 hosted C、ASan/UBSan；运行过程不读写设备寄存器。
FE source oracle 覆盖 67 个 action 字段 × 32 单 bit、512 个随机 action、33 个 key 字段 × 32 单 bit。
它另覆盖 1,024 个 IPv4/IPv6 TCP/UDP VLAN/QinQ/PPPoE key 和 256 个 L2 key，比较 masked key 与 CRC16/CRC32。
FE register oracle 覆盖 12 个 ACCESS busy 契约、8,192 组 invalidate 编码及 48 个 FDB MAC 单 bit。
实际 SDK `reverse_n()` 存在 signed-shift UBSan 触发；仅该未修改 vendor helper 关闭 shift instrumentation。
native 实现和其他参考/测试仍保留检查；不能将结果写为“全部 vendor 源码无 UB”。
hosted little-endian 布局相符不等于完成 ARM64 ABI、CCI coherency 或物理芯片验证。
现有私有 `ca-ne.ko` action/key oracle 不是这些公开源码 oracle 的输入，本资料不声称本轮运行了它们。

## 3. FE 格式、表与生命周期契约

### 3.1 格式与匹配域

- `aal_common.h` 的 `HASH_ACTION_GROUP_20`（318–375 行）和 `aal_hash.c` 的 `convert_act_flow_nomal_mode()`（401–474 行）定义固定 normal action。
- native 67 个 action 字段与真实 converter 的 packed 输出逐位一致，包括 NAT、MAC/EIF、VLAN、PPPoE、MTU 字段。
- SDK key 为 736 bits；mask 为 224 bits；normal action 为 224 bits，测试同时检查这些实际 `sizeof`。
- mask 不是通用的“1 表示匹配”：多数 flag 为 1 时 SDK 把 key 置 0，IP 地址 mask 使用前缀长度，TTL 为独立 selector。
- `aal_common.c:809–832` 说明 IP options、fragment、IPv6 DOH/RH/HBH、L3 checksum error 的 mask 行为。
- `aal_common.c:875–877` 说明 TCP flags 与 `l4_chksum_zero` 的 mask 行为。
- native 路由模板让 FIN/SYN/RST、fragment、options、L3 checksum error 保留在 key；安装值为 0，因此这些类不匹配正常流。
- 本轮另保留 IPv6 DOH/RH/HBH 和 zero-checksum flag，避免依赖“ip_options 也许覆盖一切”的假设。
- transparent L2 模板不因上述路由保护而擅自变成 L3/L4 报文过滤器；其授权由 Linux 控制层负责。

### 3.2 DDR 与 cache

| 契约 | 锁定依据 | 已验证范围 |
|---|---|---|
| 64K main entries / 32-slot bucket，bucket mask `0xffe0` | `aal_hash.c:149–159,3746–3761` | native bucket 计算与编码 |
| 同 bucket 硬件只存/比较 CRC32 | `aal_hash.c:3764–3775` | 碰撞必须拒绝或安全回退，不能仅比较软件完整 key |
| `crc16[12:0]==0` 不使用 slot 0 | `aal_hash.c:3777–3783` 的 cache-age0 workaround 注释 | native 分配避让；不宣称掌握其他 stepping 勘误 |
| 48-byte DDR slot / 224-bit normal action | SDK-REG `L3FE_FE_L3E_HS_HASH_INI` 等实际字段 | `ha_width=4`，cache 内部 action width 与 DDR stride 分开 |
| 2,048 cache entries / 32 ways | SDK-REG cache 配置及 access/key 字段 | set/slot、低 19-bit identity 与 invalidate 编码 |
| EIF 32 rows，但 MIB 不是“总共只有 32 个” | SDK-REG EIF addr 5 bits、TX IFID MIB addr 6 bits | native 仅分配 EIF 0–31；共享流 counter ownership 另行管理 |

SDK `aal_hash.c:2898–2899,2944–2955` 先写 key/action，最后设置 age 使能；`HASH_AGING_INVALID` 为 0。
native 的 key → action → `dma_wmb()` → age 1 与此一致；依赖槽位初始化/删除后 age 0、复用前完成缓存撤销。
SDK `aal_hash.c:3302–3305` 要求先清 DDR key 再 invalidation；native 保持该顺序。
这些是源码流程一致性证据，不是硬件发布、排空或 cache ageing 原子性的物理时序证明。

### 3.3 间接窗口与命令结果

SDK `aal_fdb.c:115–124` 在 staging 前检查忙状态；ACCESS timeout 不代表硬件已经放弃 DATA。
native 增加 staging 前 idle guard，未完成时不覆盖 DATA，恢复责任仍由资源 owner 保留。

| FE 相对偏移 | SDK-REG 字段 | busy bit |
|---|---|---|
| `0x1654/0x1ca0/0x1cb4/0x3000/0x3200/0x3380/0x33b0/0x35c8` | PDPID / FDB / MAC-limit / EIF / CAM / CLS key/FIB / TX MIB `access` | 31 |
| `0x38b0/0x38e0/0x393c` | cache request / SWO / memory init status | 0 |
| `0x38e4/0x3910/0x3928` | cache read / mask / age access status | 31 |

`test_fe_window_idle.py` 验证 busy、timeout 后重试、保持 CAM ownership 和 idle 后恢复；它是故障模型，不是 silicon 测时。
FDB ACCESS 完成与 CMD_RETURN 成功是两层结果：SDK `aal_fdb.c:1207–1215` 接受 APPEND 4/5，10 为 full，其他不是成功。
`test_fe_destination_status.py` 另测试这些状态和不确定操作的 rollback ownership。
MAC-limit 与 FDB 共用 `cpu_opt_mode`：任一窗口 BUSY 时不切模式，timeout 保留 owner，等两者 idle 后显式恢复。

### 3.4 AXI workaround

SDK `aal_hash.c:4152–4173` 的 `aal_hash_hw_patch_set()` 设置 `0x3944` bits 0/31、`0x3948` bit 0。
注释涉及避免 AXI deadlock 和 CRC offload 修补；本轮保留并核对这些设置，不杜撰额外优化 bit。
SDK-REG `L3FE_AXIM2_CONFIG` 的 read/write outstanding 各占 4 bits；native 设置 15/15，保留其他字段。
测试证明 RMW 与 field 编码正确，不能证明这组参数在本板负载下达到最佳吞吐。

## 4. Checksum / NAT 的限定结论

SDK-REG `L3FE_PP_SPCL_PKT_DETECTION_CFG`（18924–18954 行）明确以下字段。

| 字段 | bit | 当前处理与边界 |
|---|---|---|
| `ipv4_chksum_chk_enable` | 15 | native 显式启用，避免继承未知 boot 状态 |
| `l4_chksum_chk_enable` | 16 | native 显式启用；SDK `aal_l3fe.c:752–755` 有同类初始化 |
| `l4_chksum_rh_chk_enable` | 17 | 不以打开它取代 IPv6 RH 的保守 CPU fallback |
| `chksum_err_drop` | 18–23 | 未凭另一代 SDK 推断六个位全部语义并重写策略 |
| `drop_udp_ov_ip6_cs_zero_en` | 28 | 独立 IPv6 UDP zero-checksum policy；不是通用 L4 checksum 校验 |

normal action 的 NAT 字段为 `ip_addr_vld/ip_type/ip_addr/l4_port`，没有独立的任意 CSUM repair action。
位域正确不代表芯片真的按预期重算 checksum；公开树中未找到完整 normal-mode NAPT 上层 builder 来补足这一证明。
native 仅支持其能完整表达的 IPv4 source 或 destination 改写；双向字段混合、未知 checksum 请求必须安全回退。
zero-checksum fallback 包含合法 IPv4 UDP checksum 0；这是有意收窄的支持域，不是新吞吐优化。
仍须实机抓包验证非零错误 checksum、SNAT/DNAT 的 IP/TCP/UDP checksum、TTL、MTU 和异常报文路径。

## 5. QM / DMA 可确认的编码

SDK-REG EQ0 CFG0–4（25232–25328 行）定义 buffer 地址、BID、数量、size、CPU ownership 与 AXI 属性。
SDK `aal_l3qm.c:1051–1081` 的实际 decoder 确认 2 KiB 对应 size index 5；oracle 编译该函数而非复制结论。
native hardware-owned DQ EQ1/2 各 512 × 2 KiB，BID 512–1535；CPU EQ4/5 各 256 × 2 KiB，BID 0–511。
oracle 验证二者地址/BID 不重叠、CPU EPP ring 1,024 bytes、profile/coalescing 字段及 16-port/128-VOQ 配置。
`QM_QM_AXI_ATTRIBUTE_DATA0/1`（25752–25788 行）的 prefix 是 6+2 bits，而非只由 DATA0 决定。
本轮显式清 staging DATA1，测试以脏 DATA1 为初态，防止其污染 native `0x02` prefix。
WAN low/high threshold、credit、buffer ownership 是寄存器编码验证；没有把原始 token 值换算成未经证实的 Mbps。
`test_qm_rx_bounds.py` 与 `test_qm_table_staging.py` 是另外的生产代码故障模型，不冒充 SDK/芯片 oracle。
尚未验证实机 AXI coherency、DMA completion 次序、队列饥饿、背压传播或长时间 credit 平衡。

## 6. PON 可确认的编码

SDK `aal_pdc.c:73–112` 对 ITU PDC 分 OMCC slots 0–7 与 business slots 8–255；generated map 在 103768–103827 行。
PON oracle 解码全部 256 个生产条目：source 7，OMCC destination 16/bypass/COS 6/no-drop，business destination 24。
相应 POL_ID 分别为 `index+128` 与 `index-8`，`pol_en=0`；POL_ID 携带内部标识不等于启用 policer。
SDK-REG PVT（101092–101178 行）为每队列 9-bit ID+validity；VSTBL（101499–101569 行）为每队列 20-bit credit。
oracle 检查跨 word 的 queue/weight/credit 字段，覆盖 credit shift 0–3；生产值为 `weight << (7+shift)`。
SDK `aal_puc.c:1069–1123` 进一步确认 VSTBL 的 20-bit 分片写入；这不证明 OLT 已给足 upstream grant。
CIR/PIR 字段见 SDK-REG 102873–102906、103027–103060 行；测试核对 native rate、burst、enable/mode 编码。
本轮没有从这些原始值推断确定的限速 Mbps，也未证明任何固定 400 Mbps shaping ceiling。
OMCI/OLT grant、GPON/XG-PON framing、GEM 方向、EVTO 语义和实际排队公平性不能由这一 register oracle 代替验收。

### 6.1 原生 L2 与原包 CPU gate：新增契约

- L2 oracle 已比较 129 个字段、16 个 indirect windows、16,384 个 FDB 向量、448 个 PONCLE key 与 128 条 SDK MAC-limit 成功写序列；计数随新增字段测试更新。
- FDB 是 4,096 主表 + 32 overflow；`aal_fdb.c:149–159` 的 L3 Hash 容量不能套用到 L2 FDB。
- L2 key 为 MAC/VID/SC/可选 PCP，没有独立 Linux bridge/FID 字段；不能靠 port mask 解决同 VID、同 MAC 的多 bridge key 冲突。
- `aal_fdb.c:4950–4952,5113–5115,5166–5168` 在 SVL 软件 key 中明确清 VID/SC；不以 ILPB 的默认 SC/PVID 推断 tagged key 隔离。
- `aal_port.c:2722–2728` 初始化全部 64 个 IPPB physical→logical 映射；仅检查 ILPB、遗漏 IPPB alias 无法证明非 LAN 不参与学习。
- DFT flood type 与 PONCLE packet type 不是同一枚举；前者 BC/UUC/UL2MC/UL3MC = 0/1/2/3，来自 `aal_arb.h:52–58`。
- MC vector 的 64 bits 选择 MCFIB recipes，不是 64-bit 端口掩码；MCFIB COS command 是 active-low：0=改写、1=保留。
- `aal_fdb.c:862–1010` 的 MAC-limit 窗口在 RAW mode0 运行，address bit6 选择 limit、低6 bits 是端口，DATA low13 是 limit。
- `aal_fdb.c:3704` 明确 limit0 用于软件学习，不是无限制；native 的 limit helper 不暴露全 FDB flush 或 live counter init。
- 外部 oracle 只对齐 SDK 成功路径；SDK timeout 后立即恢复模式的做法没有被照搬，native 等所有共享窗口 idle 后才恢复。
- `aal_fdb.c:4434–4435` 的 `sm_static_entry_fwd=1` 只证明静态 SA move 时允许报文转发，不能证明 static FDB destination 会自动迁移。
- 后置 PONCLE 的 CPU redirect 没有 learn-disable 字段；控制报文必须由已验证的前置特殊包分类/SPB 禁学，不能把“CPU trap”当作“没有硬件学习”。
- CLS 仅两个 profiles，各 128 key rows；SDK `aal_l3_cls.h:27–31` 与 `aal_l3_cls.c:3209–3213` 给出范围。
- CLS KEY window `0x3380` / DATA10 `0x3384` 的有效位为 `[30:27]`；所有 foreign 有效 key 均阻止 default-only gate ownership。
- `aal_l3_cls.c:4899–4918` 证明每个 default result 是连续两行；第二行 DATA6 `[25:23]` 存 `fib_format_sel`，只写第一行不完整。
- default 地址按 `1024 | (profile<<2) | ((result&1)<<1) | ((result&2)<<3)`；两个 profiles、四 result types、两行共 16 行，不能当连续 1024–1039 使用。
- `ca_aal_proc.c:2894–2922` 的 bypass recipe 同时设置 `keep_orig_pkt=1`、`t2_ctrl=15` 和 CPU destination；不等同 raw PDC bypass。
- LPB `t1_ctrl` 位于 mid-word `[13:10]`；LAN/PON 对应 `0x3418/0x3424`，可直接选择预置原包 CPU profile，不能在原子 gate 内写间接 FIB。
- L3 parsing-error / over-VLAN / DDoS 控制也能覆盖 T1/T2；只有 default FIB 正确，不能排除这些 foreign override。
- 新增只读 PP override 准入：`0x3248/0x324c/0x3314/0x3318` 必须是 keep-original CPU0/blackhole、T0 disable、T1–T5 bypass，先于 TCAM 查询和任何配置写入。拒绝时暴露寄存器与原值，不覆盖 foreign 策略。独立 generated-union oracle 实际通过 436,864 组合，4 个破坏生产逻辑的变体被拒绝。
- 设备生命周期 FE base 的 warm readback 使用真实 CLS mode0 语义掩码：第一行七个 word 分别为 `ffffcfff/cfffffff/ffffffff/fffffffb/ffffffff/ecffffff/03ffffff`，第二行只检查 DATA6 的 `03800000` format bits。LPB 使用 `aal_l3fe.h` 的 v32 实际结构，HI 的高两位保留；不用同文件早先未使用的 G3 v25 结构推断偏移。独立 oracle 从字段赋值构造期望值，不从生产常量反推答案。
- STG0 `my_mac_fail_pkt_bypass_cls` 不因名称可疑就擅自清零；SDK CPU-force 调用链禁用 LPB MAC filter，当前 LPB 同样禁用。只核对本 owner 的 STG0 bits 和映射，保留未接管位。
- PDC 控制寄存器没有已证实的 all-data 原包 CPU force；关闭 map、改 raw bypass 或仅关闭 LAN RX 都不是完整 PON→L3 gate。
- FDB 扫描只作有界 reconciliation，不是硬件 atomic snapshot；失败/部分扫描不证明未见条目已删除，private L3 DA-index 域不得被清除。
- 当前 BUM 走 CPU-only trap，没有设置“已硬件转发”标志；这不应表述为广播/多播/未知单播已经全硬件交换。
- 上述源码契约不替代实际 SVL/IPPB/aging clock 基础配置检查、policy 变化中的流量截断抓包、MAC move、PPPoE/LCP 与 line-rate 验收。

BUM、CPU-copy、精确 MDB/SSM、VLAN 及 L3/REO reset 的重新核证见 [完整 L2 资料矩阵](rtl9617c-full-l2-evidence-20261114.md)。该矩阵明确区分已有 SDK 配方、尚未实现的控制面与未证明的完整 DMA/行退休契约；当前没有把公共源码镜像称为 Realtek 官方 NDA 手册。

## 7. 重现命令

在 ThorOS 根目录执行；外部目录必须对应以上锁定内容，路径自行替换，不需要接设备。

```sh
THOROS_SDK_NE=/path/to/ca-network-drivers
THOROS_SDK_REG=/path/to/rtl8277c_registers.h
THOROS_SDK_AAL="$THOROS_SDK_NE/ca-network-engine/1.0-r0/ca-network-engine-1.0/aal-77c"
export ASAN_OPTIONS=detect_leaks=0
python3 scripts/test_fe_sdk_contract.py --sdk "$THOROS_SDK_NE"
python3 scripts/test_fe_register_contract.py --registers "$THOROS_SDK_REG"
python3 scripts/test_fe_pp_exception_contract.py --sdk "$THOROS_SDK_NE" --registers "$THOROS_SDK_REG"
python3 scripts/test_fe_base_contract.py --sdk "$THOROS_SDK_NE" --registers "$THOROS_SDK_REG"
python3 scripts/test_qm_sdk_registers.py --sdk-header "$THOROS_SDK_REG" --sdk-qm "$THOROS_SDK_AAL/aal_l3qm.c"
python3 scripts/test_pon_sdk_registers.py --sdk-header "$THOROS_SDK_REG"
python3 scripts/test_l2_sdk_contract.py --sdk "$THOROS_SDK_NE" --registers "$THOROS_SDK_REG"
python3 scripts/test_l2_table_transactions.py
python3 scripts/test_fe_window_idle.py
```

最终硬件验收必须将软件模型通过、目标内核编译通过、实机双向命中和吞吐/丢包通过分别记录。
`enabled`、安装条目数量、hosted oracle PASS 均不能独立证明报文绕过 CPU，更不能证明 400 Mbps 根因已消失。
应同步采集双向 FE activity、CPU punt bytes/packets、MAC/队列丢包、IRQ/softirq、checksum 抓包与同拓扑 A/B 吞吐。

## 8. 固定链接

[ne-root]: https://github.com/jameywine/ca-network-drivers/tree/8b4f4882ff0e237a1fa558fb0838e4b680bd6bd0/ca-network-engine/1.0-r0/ca-network-engine-1.0/aal-77c
[reg-file]: https://github.com/jameywine/GPL-for-GP3000/blob/5090fbcb6ba743dd7b1314811ef557bad0460147/linux-5.10.x/include/soc/cortina/rtl8277c_registers.h

- [FE key/mask/CRC 实现][sdk-common]；[action / DDR / cache / workaround 实现][sdk-hash]。
- [FDB busy 与状态处理][sdk-fdb]；[checksum engine 初始化][sdk-l3fe]。
- [QM buffer decoder / 初始化][sdk-qm]；[PDC 映射][sdk-pdc]；[PUC scheduler 表][sdk-puc]。

[sdk-common]: https://github.com/jameywine/ca-network-drivers/blob/8b4f4882ff0e237a1fa558fb0838e4b680bd6bd0/ca-network-engine/1.0-r0/ca-network-engine-1.0/aal-77c/aal_common.c
[sdk-hash]: https://github.com/jameywine/ca-network-drivers/blob/8b4f4882ff0e237a1fa558fb0838e4b680bd6bd0/ca-network-engine/1.0-r0/ca-network-engine-1.0/aal-77c/aal_hash.c
[sdk-fdb]: https://github.com/jameywine/ca-network-drivers/blob/8b4f4882ff0e237a1fa558fb0838e4b680bd6bd0/ca-network-engine/1.0-r0/ca-network-engine-1.0/aal-77c/aal_fdb.c
[sdk-l3fe]: https://github.com/jameywine/ca-network-drivers/blob/8b4f4882ff0e237a1fa558fb0838e4b680bd6bd0/ca-network-engine/1.0-r0/ca-network-engine-1.0/aal-77c/aal_l3fe.c
[sdk-qm]: https://github.com/jameywine/ca-network-drivers/blob/8b4f4882ff0e237a1fa558fb0838e4b680bd6bd0/ca-network-engine/1.0-r0/ca-network-engine-1.0/aal-77c/aal_l3qm.c
[sdk-pdc]: https://github.com/jameywine/ca-network-drivers/blob/8b4f4882ff0e237a1fa558fb0838e4b680bd6bd0/ca-network-engine/1.0-r0/ca-network-engine-1.0/aal-77c/aal_pdc.c
[sdk-puc]: https://github.com/jameywine/ca-network-drivers/blob/8b4f4882ff0e237a1fa558fb0838e4b680bd6bd0/ca-network-engine/1.0-r0/ca-network-engine-1.0/aal-77c/aal_puc.c
