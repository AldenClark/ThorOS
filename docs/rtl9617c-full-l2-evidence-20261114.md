# RTL9617C 完整二层硬件转发：资料、可实施路径与未闭合契约

日期：2026-11-14。目的：区分“资料允许实施”“当前尚未实现”“缺少关键完成语义”与“缺少实机验收”，不把四者混写成“缺资料”。

## 结论与当前代码边界

公开的 RTL77C 厂商 GPL 源码和真实寄存器头，**足以继续实施受控的原生 BUM 硬件复制，以及规划精确 IP 组播和 VLAN 域**。MCE、复制动作、原始源口保持、IP 精确 Hash 键都不是只能猜测的能力。

但“有这些字段”不等于已完成 Linux bridge 集成、共享资源所有权、迟到 CPU 副本去重、复位恢复与板卡验收。尤其完整 L3/DDR/AXI 在途事务的完成条件，现有已读公开源码仍未给出可直接用于释放内存的证明。

当前 ThorOS 代码的实际范围仍是：

- 默认关闭的原生 L2 后端；`fe_switch_create()` 将 `requested` 初始化为 `false`，sysfs `l2_switch` 只表达启用请求。
- 单个合格的无 VLAN filtering、纯原生 LAN 网桥，**已学习的无标签单播**可使用原生 L2 快路径。
- 广播、未知单播、组播、标签和控制流量仍为 CPU trap；当前不设置硬件复制的 `offload_fwd_mark`。
- 当前不是“所有二层流量均硬件卸载”，也没有实测确认原约 400 Mbps 症状的唯一根因或修复后吞吐。

实现与验收范围见 [原生 L2 实现记录](rtl9617c-native-l2-20261114.md)。本文不替代其状态表。

## 锁定资料与引用规则

以下行号均指锁定版本原文件，不是 ThorOS 重排后的副本。

| 简称 | 锁定来源与根路径 | 性质 |
| --- | --- | --- |
| `NE/` | [jameywine/ca-network-drivers@8b4f4882ff0e237a1fa558fb0838e4b680bd6bd0](https://github.com/jameywine/ca-network-drivers/tree/8b4f4882ff0e237a1fa558fb0838e4b680bd6bd0)，`ca-network-engine/1.0-r0/ca-network-engine-1.0/` | 公开厂商 GPL 源码镜像；本文优先使用 `aal-77c/`，不将其他芯片分支类推为 77C |
| `GPL/` | [jameywine/GPL-for-GP3000@5090fbcb6ba743dd7b1314811ef557bad0460147](https://github.com/jameywine/GPL-for-GP3000/tree/5090fbcb6ba743dd7b1314811ef557bad0460147)，`linux-5.10.x/` | 产品公开 GPL 树；不是独立获取的 Realtek NDA 编程手册或勘误 |
| `REG` | `GPL/include/soc/cortina/rtl8277c_registers.h` | 真实 RTL77C generated register header，不使用其他 Realtek 型号网页替代 |
| `FC/` | `GPL/drivers/net/ethernet/realtek/rtl86900/FleetConntrackDriver/` | 用明确 `CONFIG_FC_RTL8277C_SERIES` 分支核对生产调用链 |

关键输入 SHA256：

```text
REG                       ce5940a274a14c91e5bf3cf96e4583d2d1d086ae601eb716566dfc70d87633e0
FC/src/rtk_fc_mgrTRx.c     4b091b936190bd1c9a742a60538e91d53cc47b5278db6dfeb5bc8c1d53903a01
FC/include/rtk_fc_helper_wlan.h
                          73986b7b0b16255f9742c3fb33bf4aee866aa76d046ce215e26a3ed7ea79f7ff
NE/aal-77c/include/aal_l3_specpkt.h
                          3bbef0c9e18b548b7a9732da17b943af8eeed3a7db2f045014e63f59c8e11259
NE/aal-77c/include/aal_port.h
                          190e4c0c2ac7e99515162fac8775fb33c5ee605423d3809b09bda85708c99f7e
```

本轮已重新获取、逐文件核对以上输入。SDK 保留在仓库外，不将整份厂商代码并入产品。

## 共享基线后续修正

后续冷交接实现见 [原生 L2 管理与实机边界](rtl9617c-native-l2-20261114.md)。NI 延迟注册 LAN，PON 先关闭全部 RX 家族，再完成共享 SVL 的空 FDB 预检和读回。TPID 的“必须在四个 CMP CSR 中看到 88a8”不是硬件要求：真实 SDK 位图自带该标准值，本轮已删除错误拒绝并保留比较寄存器。

UNI 接收容量与原生出口 MTU 必须分别处理。核对实际 Linux VLAN/bridge 函数后，固定 1522 会破坏现有 QinQ1500 CPU 回退；全局 UNI/存储预算本轮保持不变，原生帧长准入仍拒绝无法等价表示的基线。冷基线管理不等于这一硬件语义已经闭合。

## 1. 原生 BUM：已有足够基础配方，不是未知硬件能力

BUM 指广播、未知单播和组播。普通全成员洪泛与启用 snooping 的选择性组播不是同一个控制面。

| 契约 | 精确证据 | 能得出的结论 / 尚需实施 |
| --- | --- | --- |
| 复制组与动作容量 | `NE/aal-77c/include/aal_mcast.h:27–38` | MCE 有 256 个 64-bit vector；64 个 MCFIB 动作。**vector 的 bit 是动作索引，不是物理端口号** |
| MCE 访问窗口 | `REG:39269–39307`，`NI_HV_MCE_INDX_LKUP_ACCESS/DATA1/DATA0` | 地址 `0xf430aa64/aa68/aa6c`，可用已有有界表事务访问；不等于可抢用 PON/其他 owner 的行 |
| MCFIB 窗口 | `REG:7675–7751`，`L2FE_ARB_MC_FIB_TBL_*` | ACCESS `0xf4301634`，DATA2/1/0 `1638/163c/1640`；3×32-bit 动作可独立设置目的口、编辑与 metadata |
| 按入口、类型选择洪泛 | `NE/aal-77c/aal_arb.c:903–946`，尤其 `925` | DFT 索引是 `(lspid << 2) \| type`，支持每个 LAN 入口独立分组，不需要每包软件查 SA 来选择 ingress |
| 类型编号 | `NE/aal-77c/include/aal_arb.h:52–58` | BC=0、UUC=1、UL2MC=2、UL3MC=3；不能与 PONCLE 的 `pkt_type` 编号混用 |
| 无编辑复制 | `NE/aal-77c/include/aal_mcast.h:94–149`；`aal_mcast.c:841–946` | S/C VLAN、TPID、PCP、DEI 的 NOP=0；不改 MAC SA、TTL；COS 保留对应 `cos_cmd=1`，不是全零动作 |
| 入口排除 | 同 `aal_mcast.h:115`；`aal_mcast.c:874–877` | `src_port_filter_dis=0` 转为 `permit_spid_en=0`。仍须与 ingress 保持和成员矩阵联合验证，不可只凭端口位图假定不会回流 |
| 保持真实源口 | `NE/aal-77c/include/aal_arb.h:107`；`aal_arb.c:53–60,827–828`；`aal_mcast.h:80` | 全局 `keep_o_lspid_en_for_mc` 与每动作 `keep_o_lspid` 已有字段、setter 和初始化证据；后者是 DATA2 bit11 |
| 发布顺序 | `NE/aal-77c/include/aal_mcast.h:223–248`；`aal_mcast.c:1080–1124,1249–1331` | SDK 示例是构建新 group → 更新 consumer → release 旧 group。没有因此证明旧 CPU 副本或在途 recipe 已全部消失 |

可据此实施的有限原生 BUM 架构：

1. 只准入当前可精确表示的单个无标签 LAN bridge，先保持 Linux snooping 不被误覆盖。
2. 用独享 MCFIB 动作表达每个成员端口的无编辑复制，并有一个 CPU 副本动作；DFT 为入口选择对应 group。
3. 用 `keep_o_lspid` 或明确 per-ingress group/token 保持来源，不能依赖 MAC 学习表反查。
4. 既有已知组播 FDB 是另一条 group 来源：必须纳入 owner 或拒绝，不能只配置 unknown DFT 后宣称所有 MC 都受控。
5. 原生 BUM 上线前必须增加 CPU 副本标记、Linux 去重、旧 epoch 副本处理、资源表满与部分写失败恢复。

这些是可实现的工程工作，不是本提交已完成的功能。CPU 对业务的本机接收、IGMP/MLD 控制面、软件成员端口仍需保留，不能为了“全硬件”随意丢弃 CPU 副本。

## 2. CPU 副本：存在生产标识约定，但不能直接照抄

| 原始调用链 | 精确位置 | 审计解释 |
| --- | --- | --- |
| 创建 CPU 复制动作 | `FC/core/rtk_fc_driver.c:8070–8123` | 8277C 使用 `portForwardActionVlanExtend_t`，目的 WLAN_CPU0，`wifi_flowid=COPY2CPU_INTF`；有标签时显式重建原标签 |
| token 定义 | `FC/include/rtk_fc_helper_wlan.h:179` | `RTK_FC_COPY2CPU_INTF=56`，是软件保留约定，不是全芯片天然独占的 reason |
| token 编入复制动作 | `NE/aal-77c/aal_mcast.c:880` | `wifi_flowid` 写入 9-bit MCFIB `pol_id`；不能误当成“独立副本限速已开启” |
| RX 识别副本 | `FC/src/rtk_fc_mgrTRx.c:2649–2661` | 先解析 metadata；当 LSPID=MC、DA 为组播、POL_ID=56 时，软件赋 `CPU_REASON_FLOW_COPY` |
| 来源补救 | `FC/core/rtk_fc_driver.c:3964–3986` | 用软件 SA LUT 找回入口，PON stream id 仍有 FIXME。新 MAC、MAC move 和迟到包不能照搬这种推断 |

`CPU_REASON_FLOW_COPY=17` 不是可直接从原始 HeaderA 单个位读取的“已转发”标志。`HeaderA.mirror`、拥塞 `mark`、`cpu_flg` 也不能替代复制契约；其字段说明见 `NE/aal-77c/include/aal_common.h:781–798`。

`keep_o_lspid` 提供比 SA 反查更直接的实施方向。默认 SDK builder 没有设置该 per-copy bit，不是“硬件无法保留源口”的证据。

新设计必须证明 token 只可能来自本 owner 的 CPU 复制 recipe，不能与 PON、普通 trap、L3 miss、legacy descriptor、其他 policer metadata 冲突。旧 token 的生命周期必须长于在途副本，不能在桥变更后立即赋给另一 ingress。

另一个不能省略的前置条件是 `NI_HV_MCE_CTL_REG`（`0xaa60`）的 `cp_lspid_to_pol_id_en`（bit17）：generated header 的默认值 `0x0002f0ff` **已经置位**。已取得的目标 `aal_mcast/arb/ni/FC` 源码中尚未找到这个字段与 MCFIB `pol_id` 的明确先后/覆盖契约。厂商完整配置能够用 token56，不足以证明 ThorOS 保留当前启动值时也一定保留所选 token；不能反推一个未经证实的执行顺序。本轮不改这个共享控制位。BUM 准入需要补齐该设置的所有权、实际执行语义及板端 metadata 验证。

还需保证 Linux 对该硬件域的已转发成员不再次洪泛，同时允许正确的本机/非该域处理。给任意 CPU 报文无条件置 `offload_fwd_mark` 会掩盖数据丢失或制造错误去重。

**未证实 CPU-copy-only 限速。** `NE/aal-77c/aal_arb.c:391–447` 是按入口 policer index 与类型选择 flood policer；77C FC 路径 `rtk_fc_driver.c:7418` 明确当时 MC meter 仅 ingress。整体 storm policing 不能宣称为 CPU 副本独立限速。

### 2.1 为什么“写入复制表 + 设置 mark”还不够

一个可审查的设计应让 CPU token 指向不可变的 `{代际、原始入口、实际已复制成员集}`，不能只读取当前 `l2_active`。旧代副本在策略切换后应按明确规则丢弃，不能简单清除 mark 后重新洪泛。当前 LAN 收包经过 GRO；即便 NAPI 入口校验了代际，软件聚合/批处理仍可能把包延迟到新代际。复制副本需要单独的递交与 bridge 发布同步契约，不是单次 token 比较就解决所有 TOCTOU。

表项退休与 token 退休也必须分开：

- **MCFIB/MCE 行复用**需要证明 NI MCE/ARB/PE 不再引用旧索引。现有 `0x11c0/0x1534/0x175c/0x1904` 仅描述指定 L2 阶段，不能据此推断 NI MCE 已空。
- **CPU token 复用**还需要所有旧 EPP/GRO/网络栈副本被消费或丢弃、软件读者结束。`synchronize_net()` 不会清空尚在硬件或 EPP 的报文。
- `REG:39249–39347` 定义 NI MCE 的 `0xaa60` 控制和 `0xaa74/0xaa78` 进出计数；复制的入/出数量不是 1:1。`buf_flush_en` 位存在，但已读锁定资料未给出 flush 的 ack/idle 与引用释放契约，不能猜测翻转该位即完成 fence。
- `NE/aal-77c/aal_mcast.c:1249–1331` 的新组/旧组释放是软件引用计数流程，没有同时给出硬件完成和 CPU 队列栅栏。因此本轮不把这个序列当作跨代复用已获证明。

“每个代际永久保留旧行”可以构造有限的保守实验：假设 5 个固定 LAN 无编辑动作、每代每入口另占一个 CPU 动作，仅 64 个 MCFIB 动作理论上最多容纳 11 个完整代际，实际还要扣除保留或外部行。耗尽后必须回 CPU。这不是可持续的完整二层实现，不能靠有限不复用方案宣称已经解决退休问题。

## 3. 精确 MDB/SSM：不是把 IP 组简单写成 MAC FDB

| 能力与问题 | 已读证据 | 实施结论 |
| --- | --- | --- |
| MAC 组播表 | `NE/aal-77c/include/aal_fdb.h:549–576`，FDB 的 MAC/VID/SC/PCP 与 MC destination 字段 | 可以表示二层 MAC 组；不能自动等价于 IPv4/IPv6 IP 组，IP→MAC 映射有别名 |
| 77C 精确 IP 组转发 | `FC/core/rtk_fc_driver.c:7066–7463`，`rtk_fc_syncToHw_G3addGroupFwdHash()` | 构建 IPv4/IPv6 DA/SA、VLAN 等键；8277C 分支设置 `action.mc=1`、`mcgid` 并使用专用 MC Hash profile/mask。硬件并非只有 MAC 匹配一种路线 |
| 更新同一组的动作 | `FC/core/rtk_fc_driver.c:6957–7048` | exact 8277C 分支更新 group action；与 L3 规则共享 Hash、DA index、policer/统计及编辑资源，不是独立“免费 MDB 表” |
| 通用源码的 IM3E 表 | `NE/cortina-api/mcast.c:633–845` | 该通用路径含 `IM3E_MLDDA/MLDSA`，但本轮真实 77C generated header 与 `aal-77c` 未提供相应表定义，不能把其他架构的表当作已证 77C 实现 |

可实施方向是专用精确组播 owner：将 Linux 的组、源过滤、router port、本机订阅、删除/超时更新转换成匹配精确的硬件规则和复制组。
必须分别处理 `(*,G)` 与 `(S,G)`、include/exclude、组 MAC 别名，以及无法表示/资源不足时的完整回退。仅存在 SIP/DIP 字段不足以证明所有 Linux MDB/SSM 策略都已被正确映射。

当前 ThorOS 没有实现这一 owner；其 CPU trap 保留 Linux snooping，不等于已完成 MDB 硬件化。

## 4. VLAN 与多个 bridge：需要域设计，不是取消检查

| 域契约 | 精确证据 | 当前约束 / 后续路线 |
| --- | --- | --- |
| FDB key 没有独立 bridge FID | `NE/aal-77c/include/aal_fdb.h:549–576` 与真实 FDB 编码 | 同 MAC+VID+SC(+PCP) 不能同时存储两个不同 bridge 的独立目的端口；仅 egress mask 不能补出缺失的 key 维度 |
| SVL 的包侧 key 归一化 | `NE/aal-77c/aal_fdb.c:4950–4953,5113–5116,5166–5169` | SVL key VID=0、SC=0。当前原生域只使用这一个受控命名空间 |
| IVL/SVL 是全局变化 | `NE/cortina-api/vlan.c:454–499` | SDK 切换前停学习、flush FDB，再改全局 mode。不能在活跃 PON/L3 index pin 下原样照做 |
| VLAN membership 编程 | `NE/aal-77c/aal_l2_vlan.c:59–64`；`NE/cortina-api/vlan.c:650–696` | 入口/出口 membership 与 VLAN action 有真实 API；16-bit membership 映射将 PON32..63聚合到bit7、L3口24/25同bit15，不能当成 GEM/TCONT 隔离 |
| LAN VLAN membership/untag/group | `NE/cortina-api/vlan.c:2120–2268` | 有 VLAN FIB、untag 与 group 的组合路线；文件包含不同芯片宏分支，具体 recipe 必须再用 77C 类型/寄存器核验，不能整段机械移植 |
| L3 私有 DA index 域 | `FC/core/asicDrv/rtk_8277c_asicDriver.h:604–608`；当前 `rtl9617c-fe-pipeline.h` | L3 通过 FDB index 取 DA，现保留 VID4095/SC1；新增 VLAN 包侧查找与 metadata remap 必须继续排除该私有域 |

单 bridge 的普通 VLAN-aware 交换有足够基础资料继续实施；多 bridge 重复 wire VID 还需选择内部域映射、互斥准入或可证明的其他 lookup 维度。
不能把 ILPB 的 `sc_ind` 当成强制所有带标签包 SC=0；也不能仅用后置 trap 证明包从未查询或学习私有 VID4095 域。

当前策略是保留已有全局模式，只在受限 SVL 域启用无标签单播。VLAN filtering、多 bridge 仍回退，这是**当前实施边界**而不是声称 ASIC 不支持 VLAN。

## 5. 全流水线 drain 与 reset：仍缺少释放资源所需的完成证据

| 候选依据 | 已读精确位置 | 为什么不能直接作为完整 drain |
| --- | --- | --- |
| L3 packet debug count | `NE/aal-77c/include/aal_l3fe.h:447–453`；`aal_l3fe.c:84–105` | PP进入、PE离开、CLS→Hash、stage3→PE各16-bit计数；未定义一致性采样、回绕、drop 与末端 AXI 完成关系 |
| 局部 FIFO / CPU ACCESS busy | `REG:20946–20957,23148–23165`，`0x3488/0x38b4` | 局部 header FIFO、CPU cache command 状态，不是所有 PP/CLS/Hash/PE/DDR 请求的总在途计数 |
| AXI outstanding 配置 | `REG:24715–24734`，`0x3c80` | 配置允许的 transaction 数量，不是实时剩余事务或“所有写回已确认” |
| SRAM test 的 empty 名称 | `REG:18111–18343` | 属 SRAM test/LS 寄存器组，不得因名称含 empty 当作业务流水线 idle |
| FE block reset 位 | `REG:54565–54605` | `GLOBAL_BLOCK_RESET=0xf4320098`，bit3=`reset_l3fe`、bit11=`reset_l3fe_reo`；两个独立域，字段存在不说明外部 AXI 请求的完成/取消保证 |
| SDK reset 调用 | `NE/ni-drv-77c/ca_ni.c:2613–2622,3485–3487` | probe 中 assert L3FE→`mdelay(1)`→deassert；不是运行期内存回收/AXI fence 文档 |
| reset controller 实现 | `GPL/drivers/reset/reset-ca77xx.c:42–108` | assert/deassert/status 只是 MMIO 位操作，未等待 AXI outstanding 清空或返回取消确认 |

因此，不能把“撤销 PDC 新入口”“切换 CPU-original profile”“cache invalidate”“某计数暂时不变”或固定 1ms sleep 单独描述为完整 L3 drain。

受控 reset 是值得继续核证的路线，至少需明确 L3FE、REO、fabric 的复位依赖、在途 AXI response 处理和对共享 PON/QM 的影响；本轮没有足够依据宣称仅置 bit3 即可安全释放 DDR。

缺少证明时，关闭新准入后保留仍可能被硬件访问的 DDR、classifier profile 和引用对象；不能恢复 foreign profile 或复用内存来制造“卸载已关闭”的假成功。受控整机重启与运行期可恢复 drain 也必须分开描述。

还必须把**大块分配的寿命**与**块内行索引的退休/复用**分开：即使整个 DDR 仍在，已进入流水线的旧包也可能继续引用 action、Hash slot、DA FDB index、EIF、source CAM 或 MTU。现有逐流删除使用 key 失效、缓存失效和窗口完成，并不能仅凭这些源码宣称已证明整个流水线不再持有这些索引。设备生命周期 owner 消除的是过早还原基础配置/释放整块内存这一类已定位漏洞，不等于全 L3 硬件正确性认证。

## 6. 本轮新增的确定性修复与验证范围

已实现 `rtl_fe_pp_exceptions_check()`：只读检查 `0x3248/0x324c/0x3314/0x3318` 四种 PP 例外动作，避免 foreign parsing-error/over-VLAN/DDoS selector 绕过 LPB 的 CPU gate。

- 接受 CPU0=16 或 blackhole=31；`keep_orig_pkt=1`、保留位10=0；T0禁用LPB、T1..T5全部 bypass；COS可为任意合法3-bit值。
- 根据 `NE/aal-77c/include/aal_l3_specpkt.h:26–44` 的语义和 `REG:19144–19187,19871–19914` 的四个真实 union 判定，不依赖推测 reset 常量。
- 仅 read、不改 foreign 配置；拒绝时报告首个 register/value。它不防护成功检查后未经同一 owner 协调的外部写入。
- `scripts/test_fe_pp_exception_contract.py` 实际编译四个外部 generated union 与 SDK selector 定义，PASS **436,864** 个 word/admission 组合。
- 四个真实错误变体被运行时断言拒绝：去掉 keep-original、忽略所有 selector、接受任意目的口、漏检第四寄存器。使用 ASan/UBSan；输入 SHA256 验证。

这项测试证明编码和只读准入契约，不证明真实 ASIC 时序、所有旁路都已覆盖或完整 L3 drain。

后续生命周期复审还修复了：普通 NI stop/open 重置已曝光 QM/DMA、FE stop 恢复旧 classifier/LPB、partial setup 被当成可复用、remove 后同一硬件地址被新实例重新接管等路径。当前 FE 基础配置与队列改为设备生命周期持有；warm start 核验并复用，未曝光 preflight 失败可重试，部分初始化失败隔离。详见原生 L2 实现记录的生命周期章节。

`test_fe_base_contract.py` 用真实 CLS/LPB 结构和 STG0 generated union 对照生产 warm-readback 掩码；三个实际错误变体（漏有效字段、把保留位当有效字段、忽略第二行 format）均被断言拒绝。这避免因为比较保留位而误判，也避免第二行 format 漂移仍被报告 ready。源码模型通过不代表已完成硬件读回、完整 drain 或逐流索引退休验证。

## 7. 实施完成与板端验收应分别判定

| 后续交付 | 软件/源码层应完成 | 仍需真实设备证据 |
| --- | --- | --- |
| 原生 BUM | group/recipe owner、exact source+copy token、Linux 去重、epoch、资源耗尽/恢复测试 | BC/UUC/MC是否只发目标成员各一次；CPU副本source/长度/标签；MAC move与断链切换 |
| 精确 MDB/SSM | 全IP组/源键、router/local成员、通知与删除状态机、别名及不支持回退 | 同MAC不同IP组、IPv6、include/exclude、快速join/leave无泄漏/重复 |
| VLAN域 | IVL/内部域选择、PON共享模式、入站/出站标签与membership、VID4095防护 | 多VID、多桥重复VID、PVID、priority-tag/QinQ、控制帧与管理连接不串域 |
| 生命周期 | 明确 gate→drain/reset或保留所有权契约，禁止未知状态下释放 | 带流量关闭/重启/失败回滚，DDR访问及硬件状态的真实完成证据 |
| 性能 | 不在数据面增添每包软件学习/全表扫描；控制面有预算与观测 | 外部两端有线主机，单流/多流/双向/小包/长稳；QM CPU流量、丢包、时延与实际Gbps |

最终结论：**有足够资料继续写更多完整二层能力，但当前实现没有完成这些能力；也不能将尚缺的 drain/真实硬件验证以 host PASS 替代。**

## 8. 与约 400 Mbps 症状相关、但本基线已排除的候选

Linux 上游提交 [`c203ecf905745d979de5df28fa657121f2e9342d`](https://github.com/torvalds/linux/commit/c203ecf905745d979de5df28fa657121f2e9342d) 修复了 flowtable 运行时用包含 PCP/DEI 的完整 VLAN TCI 查找、而配置键只用 VID 的不匹配，原报告设备也是 RTL9617C ONU。它是值得核对的同型性能退化，不是本次自动成立的根因。

ThorOS 锁定的 OpenWrt `ada52cc7ed401153a8d0b026d1edf918bfc04c45` 已含 `target/linux/generic/backport-6.18/706-04-v7.3-netfilter-flowtable-use-the-vlan-id-not-the-full-tci.patch`。本轮完整准备树中两处生产解析已分别是 `skb_vlan_tag_get_id()` 和 `ntohs(h_vlan_TCI) & VLAN_VID_MASK`。因此不重复打补丁，也不把上游另一设备的吞吐变化当作本用户的复测结果；实际运行固件是否含此修复仍须以该设备的精确源码身份核对。
