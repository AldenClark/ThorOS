# TYFZA1 数据面最终优化：实施、风险与硬件验收

日期：2026-11-12。目标：RTL9617C、ThorOS、Linux 6.18 内核，包含 4×1GbE 与 3×1GbE + 1×2.5GbE 两种 TYFZA1 机型。

## 结论与改动范围

本轮只处理**可在代码和宿主机模型中证明的边界错误、明显的热路径额外开销，以及可回滚的空闲调度**。不重写 NI/FE/PON 驱动，不更改 DMA coherent/noncoherent 所有权模型、硬件寄存器顺序、PPPoE/VLAN 语义及 FE 数据面规则。

| 优先级 | 生产改动 | 收益/理由 | 风险与保证 |
| --- | --- | --- | --- |
| P0 | TX DMA 固定 2048B 槽边界检查、拷贝失败丢包、只清空短帧不足部分 | 防止超长 PON prefix/帧覆写下一槽；移除每帧全量清零 | 不改变 header/descriptor 发布顺序；宿主模型覆盖边界和短帧 |
| P0 | DMA `NETDEV_TX_BUSY` 记录 `wake_pending`，只有实际阻塞过才扫描 LAN/PON 唤醒 | 减少每 1–4ms 遍历队列，保证满环恢复唤醒 | 必须在两个机型验证拥塞后不会卡队列 |
| P1 | TX 热路径仅在接近环满时读取 DMA `VP_READ` | 消除常规每个 TX 包一次 MMIO 读取 | DMA hrtimer 仍定期回收；保留满环前主动回收 |
| P1 | FE 桥接相邻重复 packet 事件合并；仅空队列变非空或剩余待处理事件时立即排程 | 降低桥接流表学习和 workqueue 唤醒压力 | 仅合并完整相同的接口、VLAN、PPPoE、GEM、epoch/包头；保留 topology/FDB invalidation 和超预算续跑 |
| P1 | FE 硬件流表存活/老化扫描由“每次 work”改为 1Hz 或强制事件 | 避免业务帧触发 O(已安装流数) 全表扫描 | FDB 事件要求立即重查；硬件年龄读取失败也继续下一轮扫描 |
| P1 | NI 空闲 hrtimer 默认 4ms，待回收/阻塞/传统 RX 时回到 1ms | 空闲场景理论上减少最多约 75% 的该定时器回调 | 新增 `idle_poll_ms` 1–10ms 可随时回退；**不是整机 CPU 降低 75%** |
| P2 | QM RX EPP DMA 地址严格校验 2048B 对齐/完整槽范围 | 让错误硬件描述符不越过分配边界 | 保留原有信用回收和 DMA sync 次序 |
| P2 | RX cacheline prefetch 开关与每 VOQ、预算耗尽计数 | 允许硬件 A/B 找到不同 MTU/CPU 下最优点 | 默认保持既有 prefetch 开启；额外计数开销需测量 |
| P2 | PPPoE RX checksum 受控开关 | 仅在确认芯片 L4 错误位语义后可能节省 CPU 校验 | **默认关闭**；现有 IPv4 checksum 快路径保持原状 |

没有动频繁但必要的 MIB 计数器维护（2.5Gbps 下 32-bit 计数器很快回绕）、GPON/XG(S)-PON OMCI/OAM、Link/PHY、LED 事件与启动时的校准/复位。不能因为它们会周期运行就直接删除。

## 检测与快速回退

新固件包含 NI 平台设备的只读统计与写入开关；先定位其 sysfs 根目录（通常 `ethernet@4f4300000`），也可在脚本里自动发现。

```sh
for p in /sys/bus/platform/devices/*/dma_state; do
    [ -r "$p" ] && NI="${p%/dma_state}" && break
done
echo "$NI"

# 空闲轮询：固件默认为 4ms；1ms = 旧行为/立即回退
cat "$NI/idle_poll_ms"
echo 1 > "$NI/idle_poll_ms"
echo 4 > "$NI/idle_poll_ms"

# RX 预取：1 = 原行为；0 = 对照组（视机器和负载而定）
echo 0 > "$NI/rx_prefetch"
echo 1 > "$NI/rx_prefetch"

# PPPoE RX checksum：实验性；未经真实好/坏包验证一律为 0
echo 0 > "$NI/pppoe_rx_checksum"

# 累计统计，搭配吞吐、RTT、丢包观测，不能只读总量
cat "$NI/fe"
cat "$NI/dma_state"
cat "$NI/qm_voqs"
```

可将 `scripts/observe_tyfza1_datapath.sh` 复制到设备并运行 `sh observe_tyfza1_datapath.sh 15 > /tmp/tyfza1-15s.log`；脚本只读取 sysfs、`/proc` 和接口计数，生成两次快照，不改系统配置。

**停机阈值/回退顺序**：如出现队列不再唤醒、PPPoE 断连/异常重传、间歇性 LAN/PON 流量停滞或时延明显回归，首先 `echo 1 > "$NI/idle_poll_ms"`、保持 PPPoE checksum 为 `0`、预取恢复 `1`。若仍有异常，回刷优化前的已知良好固件；仅调 sysfs 不能回退 TX/FE 代码。避免在生产网络直接启用 PPPoE checksum 实验开关。

## 验收矩阵（必须有真实设备与对照固件）

| 负载 | 对照/优化各跑 | 记录 | 通过标准 |
| --- | --- | --- | --- |
| 纯空闲、WAN 已联机 | 每机至少 30 分钟，`idle_poll_ms=1/4` | `fast_ticks/idle_ticks`、CPU idle、softirq、内存、温度 | hrtimer 降频可复现，CPU 无意外唤醒/功耗回归 |
| LAN↔LAN 1GbE / 2.5GbE | 64B、1KB、MTU、双向 TCP/UDP，≥3 轮 | 吞吐、单核 CPU、丢包/帧错、DMA busy/overflow、VOQ、P95 RTT | 不能新增 RX 错误、队列假死和可感知延迟回归 |
| 上行 PPPoE / PON、桥接、VLAN | IPv4/IPv6、GEM/EVTO、DHCP、短流、会话重建 | WAN 会话稳定性、重新拨号、桥接规则安装/撤销、P95 RTT | 断连/拓扑更新时规则不残留；旧固件行为不退化 |
| 多端口并发与环满 | 3–5 端口并发、短包突发、持续反压 | DMA `busy/invalid`、队列 stop/wake、softirq、VOQ budget hits | BUSY 后必恢复、无 descriptor 越界、无异常 drop 增长 |
| 24h 稳定性与冷热启停 | 反复网线插拔/重启 PPPoE/重载驱动（若支持） | dmesg、OOM、netdev errors、RSS/页分配、时延 | 无 UAF/死锁、资源泄漏与数据面停滞 |

2.5GbE 型号单独测试 SGMII 10/100/1000/2500 速率切换、热插拔、自协商与温度。在实际机器上必须先固定固件、网络拓扑和测试工具，再比较 A/B；改变上游内核或其他服务会污染结果。

## 已实现的自动化证明及其边界

- `scripts/test_dma_tx_fastpath.py`：编译并运行生产 TX 函数，验证多帧填充、前缀、失效输入、缓存边界、环满与延迟完成；61 个 frame 仅有 2 次模型 MMIO 读取。
- `scripts/test_bridge_learning.py`：真实 FE bridge hook/学习函数宿主模型，1000 个重复事件合并、FDB move、VLAN/PPPoE、STP、老化读取异常及持续入队下超预算续跑。
- `scripts/test_qm_cached_epp.py`：实际 QM poll 代码在 126 组环回绕、不同预算/长度条件下，运行 DMA 缓存可见性模型和多次 stop/open 生命周期。
- `scripts/test_ni_adaptive_timer.py`：实际 hrtimer callback 在 1/4ms、QM refill、DMA 阻塞恢复、PON/LAN 唤醒中的调用测试。
- `scripts/test_rx_checksum_policy.py`：直接编译生产 checksum parser 并测试有效/畸形的 IPv4 与 PPPoE 帧。
- 保留原始 `scripts/test_itu_pppoe_datapath.py`、`scripts/test_fe_lan_lifecycle.py` 等；上述测试加入 PR Checks 和手动 Release CI，在正式 OpenWrt 编译前执行。

以上均为**宿主机模拟的控制流/内存安全测试**，不等同 DMA 缓存一致性、PPPoE RX checksum 位、2.5G 实际吞吐或物理链路验收。本轮没有设备，因此不得将任何性能百分比或线路稳定性宣称为实测。

## 明确延后（消融审计后不建议直接上）

1. **RX zero-copy/page-pool**：QM noncoherent BID 和硬件 credit 拥有权紧耦合；在没有 cacheline 物理所有权与释放时机证明之前，拷贝模式更可靠。
2. **拆除 1Hz MIB/FE 老化/其他协议定时器**：需要 32-bit 回绕、桥接 FDB 和 OLT 控制面保证。FE 学习/扫描已经去掉逐包触发的冗余遍历。
3. **切换 `CONFIG_NO_HZ_IDLE` 或深度电源管理**：需核查 RTL9617C 时钟源、IRQ 唤醒、待机/负载峰值，否则容易引入抖动。
4. **改 NAPI 优先级和 per-VOQ 配额**：新增 VOQ 和预算计数用于判定是否真的存在 bulk traffic 饿死 PON 控制包；没有数据就不改变调度公平性。
5. **强行启用 PPPoE RX `CHECKSUM_UNNECESSARY`、硬件 LSO、GRO/GSO 或可疑 DMA AXI 调优**：不能仅凭寄存器注释证明安全性；须以坏校验报文、包捕获和硬件吞吐测试为准。

## 合并/发布门槛

1. 所有 PR 宿主测试与 OpenWrt 原生编译必须通过；Linux 6.18.60 对应补丁集、设备树、两个 FIT 板型及 sysupgrade 验证必须通过。
2. 使用 4GE 与 2.5GE 实机各跑上述 A/B 矩阵，尤其要验证 DMA BUSY 唤醒和链路变更；遇到异常先回退参数，再回退固件。
3. 完成设备验收后，才合并到 `main`、手动触发发布 Release；不能将 PR 主机侧测试当作硬件验收。
