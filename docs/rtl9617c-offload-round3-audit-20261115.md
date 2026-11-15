# RTL9617C 硬件卸载：第三轮时序、生命周期与低概率故障审计

日期：2026-11-15（北京时间）。基线为 PR #21 第二轮提交
`a0d554bf3bac74969ab5d53c91db5f3a9d71114f`，代码树
`7b5865dde027acc2b86c8ea50e976227a1aa66e5`。

## 结论

在原先的 SVL/MRU 冷接管、原生 LAN–LAN L2、路由流卸载、PON/NI 生命周期修复之上，
第三轮核实并修复了 **6 组低概率但有真实后果的缺陷**。这些缺陷会导致：
过早回收或异常延长硬件流；初始化未完成的半条流对外可见；清理交错将普通 conntrack 超时重新延长至一天；
故障探测或已关闭 OMCI 后残留的 DMA owner 指向已释放设备；以及 legacy XRAM TX 发送不完整数据。

本轮仍未连接、重启、刷写或改配置实机，也没有禁用自动 SVL/MRU 冷接管或原生 L2。
**代码级回归成功不等于实机吞吐已经改善，尤其不能据此认定“硬件卸载慢于软件”的根因已消除。**

## 修复和可复现的反例

| 编号 | 核实的问题 | 实施改动 | 实际函数或反例证据 |
| --- | --- | --- | --- |
| R3-1 | 统计回写以 `u64 max` 比较硬件活动时间与 `u32 flow->timeout`；启动后第一次 32 位低位回绕附近，可用过期数值替换未来截止时间 | `228`：用 `unsigned long jiffies` 比较两方向有效活动，拒绝不存在或已过期的硬件样本；只在确实延长时以 CAS 更新 `u32` 截止时间 | 64 位与 32 位 jiffies 模型均执行原 `flow_offload_work_stats()`；回绕、过期样本、单方向长期静默、CAS 交错 |
| R3-2 | 软件/强制续期以不受保护的 READ/WRITE 和无符号差计算截止时间，慢写者可覆盖较新的续期；`act_ct` 的 `force` 也不能误丢硬件状态同步 | `230-flowtable-refresh`：每次 CAS 尝试重新采样时钟；两个有符号剩余时间相减保留完整有效差，正确区分超时与前进；原有 `>HZ` 去抖与 `force` 行为保持 | 实际 `flow_offload_refresh()`；靠近有效最大超时、并发竞争、2^32 回绕、`force`，11 个错误变体均被测试拒绝 |
| R3-3 | reply tuple 已加入哈希，original tuple 和 `NF_FLOW_HW` 尚未发布，lookup/GC/异步工作可观察或回收半初始化对象 | `229`：插入前设初始化标志和硬件生命周期类；lookup、GC、工作准入跳过初始化流；两条哈希及 CT 初次刷新后再发布 | 实际 `flow_offload_add/lookup/GC/work_alloc`；两阶段插入失败、异步 ADD/DEL/GC 与 RCU 释放 |
| R3-4 | `nf_flow_table_do_cleanup` 先对初始化流执行一次 CT timeout fixup，发布者随后 `NF_CT_DAY` 刷新覆盖了正常超时；之后不会再做第二次 fixup | `229`：初始刷新后、释放初始化标志前，使用写→读内存栅栏与 teardown 的原子标记配对；若已 teardown 则恢复正常 CT 超时 | 使用真实 cleanup/teardown/fixup/CT 刷新函数验证 TCP/UDP 超时；去除复查的错误变体被拒绝 |
| R3-5 | PON probe 的 dying-gasp 初始化失败分支先释放 OMCI、后卸载 OAM 共享 NI endpoint，后者仍有 wake 回调 | PON probe 失败时先卸载 endpoint/OAM，再撤 OMCI；OMCI/OAM/business 最终 free 前清除 NI DMA 描述符中遗留的 owner 引用（保留共享 LAN 引擎和缓冲） | 真实失败回滚与共享 NI 回调的 ASan 用例：旧顺序触发 UAF；OMCI 已 down 后内部 GPON probe 重新发布 TX owner 的实际函数链；两种 missing-forget UAF mutant |
| R3-6 | legacy 非 DMA XRAM `rtl_xmit` 忽略 `skb_copy_bits()` 返回值，片段拷贝失败后仍计算 CRC 并提交部分帧 | 失败则增加 dropped、解锁、只释放一次 skb，保持 producer 不变；DMA 快路径和 BUSY 不变 | 55 个提取的实际 TX 函数用例；旧版未检查拷贝错误被运行时反例拒绝 |

### 截止时间和发布顺序的语义边界

- `flow->timeout` 是 **32 位 jiffies 截止值**，即使内核是 ARM64；不能把它当作 64 位数值比较。
- 可接受的配置超时接近 `INT_MAX` tick，不能简单把两个 32 位截止值之差强制转换为 `s32` 后判断“更晚”。在比较各自相对于同一个新鲜 `now` 的剩余时间后，再用 `s64` 算推进量。
- CPU 每包的续期只有必要时执行 CAS，不引入锁、额外硬件 MMIO 或逐包新路由查询；性能结论仅为代码路径分析。
- `NF_FLOW_INITIALIZING` 必须覆盖 reply-only、两条 tuple 已插入但尚未完成 CT 刷新、GC、异步 work admission 等窗口；成功发布后继续由既有 pending/dying 序列化晚到的 ADD。
- 在并发 cleanup 的一次性 `test_and_set_bit(TEARDOWN)` 与初始 `NF_CT_DAY` 的次序间，使用完整内存屏障，避免 ARM64 上彼此只观察到旧状态；发布者见到 teardown 后重新修正 CT 过期时间。

### PON/NI 修复的所有权边界

- **先停生产者，后撤 endpoint、DMA owner，最后释放 netdev**。`unregister_netdev()` 对原本已关闭的 OMCI 并不保证再触发一次 `ndo_stop`。
- `rtl9617c_ni_forget_tx()` 仅在共享 `tx_lock` 内清掉特定 netdev 的残留描述符 owner；不额外 `engine_put`、不回收尚未完成的 DMA buffer，也不改变 DMA 游标与其他 owner。
- NI 与 LAN 共存时 PON 探测失败必须保持 LAN 正常运行。新增的出错注入和 ASan 复现只验证主机可控时序，不能替代真实 PON 硬件恢复。
- legacy XRAM 分支修复属于防御性正确性整改：TYFZA1 生产 DT 采用 DMA；不将 legacy TX 错误归因为当前板型约 400 Mbps 的硬件卸载差距。

## 本轮已执行的离线验证

1. 完整锁定 Linux `6.18.60` / OpenWrt 源码与板级补丁栈，在**全新**内核目录应用成功；新补丁 `228/229/230` 无 patch fuzz，未运行固件构建或闪存操作。
2. 完整 `scripts/check_firmware_prebuild.sh` 成功，包含原冷接管、原生 L2、FE、PON、QM、DMA、NI、统计和新故障注入；ASan/UBSan 启用，本地仅对不支持的 leak detector 做例外处理。
3. `scripts/check_flowtable_contracts.sh` **16 项全部成功**，包括 `50,036` 个 64 位 jiffies + `50,034` 个 32 位模型实际生产函数时序用例、`11` 个 timeout 负控，以及 `50` 个初始化/清理交错案例和 `6` 个负控。
4. legacy XRAM TX `55` 场景及负控、NI 原 deadline `150` 场景及 `6` 负控、PON probe 回滚和 DMA owner 的 ASan 反例全部通过。原有 flowtable bridge ageing/move/policy/work 的 `--before` 反例仍能重现旧版故障。
5. 使用本地 SHA256 固定的公开 SDK 与 generated RTL8277C 寄存器头，独立运行 FE action/key、寄存器、全部 16 个 MTU selector、L2 recipe/bitmap 对照，全部通过；这只是公开 SDK 的可重复模型对照。
6. 为远端对象编译新增 `net/sched/act_ct.o`，将实际 `force` 调用者纳入 ARM64 编译覆盖，预期由原 **66** 对象增至 **67**；这里的“编译通过”必须以后续**本轮提交**的 CI job 日志为准。

上述测试运行的是从本轮生产文件和完整准备后内核提取的实际函数，硬件状态、时间和调度边界可控；不是在 RTL9617C 芯片上运行。

## 未解决、不得以静态结果冒充的事项

| 问题 | 当前状态 | 下一项必要证据 |
| --- | --- | --- |
| LAN–LAN 原生 L2 是否始终命中 FE、启动 SVL/MRU 是否稳定 | 原能力、冷接管、回滚和回归继续保留；没有本轮实机证据 | 两个 TYFZA1 板型断电冷启、switch/native 状态与端口/FDB 计数 |
| 开硬件卸载时 LAN 速度低于软件卸载 | 仍**未定位到确切硅片瓶颈**；本轮避免猜测性寄存器优化 | 相同端点/方向/报文组合的对照；FE 命中率、CPU、BM/TE、NETDEV/DMA 与 PON 端口计数 |
| NoDrop、WAN logical 24→physical 12、TE/TM admission 与各路径缓存时序 | 缺实机/寄存器闭环，不盲改 | SDK 版本对应的板级读回、合法安全调试路径、吞吐曲线 |
| 核心网络模块的完整固件运行 | 宿主回归和对象编译不足以证明 | 远端 PR checks；随后真实固件上电与恢复测试 |

PR #21 保持待审，**不自动合并、不手动触发固件构建/发布**。有关最终提交 SHA、CI job 与日志结论，见 PR 更新记录。
