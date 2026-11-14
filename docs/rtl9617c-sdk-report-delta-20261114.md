# RTL9617C 补充 SDK 报告：新增证据与使用边界

日期：2026-11-14。核对用户提供的 `RTL9617C-SDK-and-L2-Hardware-Offload-Investigation-2026-11-14(1).md`；本文不修改原报告，也不把资料核验当成实机验收。

## 结论

报告提供了值得核对的 **BPI-RT2 独立发布来源和版本差异**，但没有直接补齐完整二层上线所需的 CPU 副本、MCE 退休和 VLAN 域契约。逐文件查证后有三个重要修正：

1. BPI 的 RTL8277C 寄存器头与我们已使用的 GP3000 头**逐字节相同**，不是一份新勘误或新的硬件时序手册。
2. 报告重点列出的 BPI VLAN DAL 文件，多个关键 API 实际是**成功返回的空实现**。函数名、参数和 `RT_ERR_OK` 不能用来证明已经配置硬件。
3. 报告给出的 `core/asicDriver/rtk_rg_ca8277_asicDriver.c` 属于 G3/8277B 代码线。真实 77C 后端在相邻的 **`core/asicDrv/rtk_8277c_asicDriver.c`**，不是前一个文件，也不是不存在。

因此继续实施应建立在已经取得的 `aal-77c`、正确的 77C 调用链及本项目的独立驱动上；不能整体移植 BPI 初始化或用其空接口填补 Linux bridge 能力。

报告引用的是当时 `main` 上的旧 FE bridge 学习器；当前 PR 已替换为默认关闭的 Linux bridge/switchdev 原生单播 L2 后端。不能把报告中对旧设计的描述误当作本轮工作树的现状，也不能据原生单播已实现就省略未完成的 BUM/MDB/VLAN。

## 1. 锁定来源与可重复检查

- BPI：[`BPI-SINOVOIP/BPI-RT2@c24c6c03c6466cfb1b9e4eacadab8225a457a771`](https://github.com/BPI-SINOVOIP/BPI-RT2/tree/c24c6c03c6466cfb1b9e4eacadab8225a457a771)。选取 11 个文件，共 **4,971,965 字节**。
- 比较基线：[`jameywine/GPL-for-GP3000@5090fbcb6ba743dd7b1314811ef557bad0460147`](https://github.com/jameywine/GPL-for-GP3000/tree/5090fbcb6ba743dd7b1314811ef557bad0460147)。
- 已有更底层资料：[`jameywine/ca-network-drivers@8b4f4882ff0e237a1fa558fb0838e4b680bd6bd0`](https://github.com/jameywine/ca-network-drivers/tree/8b4f4882ff0e237a1fa558fb0838e4b680bd6bd0) 中的 `ca-network-engine/1.0-r0/ca-network-engine-1.0/aal-77c`。附加报告未将此独立仓库纳入其“底层依赖未找到”的判断，不能将该判断直接套到本项目已取得的资料集。

完整 URL、相对路径、文件大小、Git blob SHA1、SHA256、文件头许可线索和使用限制，记录于 [`scripts/rtl9617c-sdk-report-sources.json`](../scripts/rtl9617c-sdk-report-sources.json)。外部 SDK 文件不进入产品仓库。

[`scripts/check_sdk_report_sources.py`](../scripts/check_sdk_report_sources.py) 只读离线验证：

```sh
python3 scripts/check_sdk_report_sources.py --list
python3 scripts/check_sdk_report_sources.py \
  --source-root /path/to/external/bpi-input-cache \
  --gpl-registers /path/to/independently-downloaded/rtl8277c_registers.h
```

`--list` 输出固定 URL 与扁平缓存名，供已有下载流程使用；检查程序本身不联网、不编译或执行 SDK、不访问设备。`--json` 可输出机器可读的资料证据摘要。检查还包含 5 个错误变体：大小改变、同大小内容改变、VLAN getter 写输出、VLAN getter 调硬件、77C 分支错误选择 G3 后端。它们证明**资料检查器**能拒绝相应变化，不是驱动故障注入或芯片行为仿真。

这里的“目标选择”仅核实源码条件分支；未改变 BPI 默认 `.config`，也没有编译其整个 SDK，不能据此宣称该发布树默认能够构建 RTL9617C 固件。其他独立字段 oracle 会在宿主编译外部类型声明或抽出的转换器；“不执行 SDK”仅指本资料核验程序，不泛指所有既有测试。

## 2. 哪些内容新增，哪些没有新增

BPI 下文相对根为 `rtk_openwrt/target/linux/realtek_bb/files-5.10/`；FC 根为其中 `drivers/net/ethernet/realtek/rtl86900/FleetConntrackDriver/`。

| 资料 | 实际核验结果 | 对实施的影响 |
| --- | --- | --- |
| `include/soc/cortina/rtl8277c_registers.h` | BPI/GP3000 均为 Git blob `9f7aaf1bb0badeea31ef85f8bee1c405fa9c180d`；SHA256 `ce5940a274a14c91e5bf3cf96e4583d2d1d086ae601eb716566dfc70d87633e0` | 可以确认第二个公开发布入口，不能算两份独立硬件语义证据 |
| `include/soc/cortina/registers.h`，47–53 行；平台 `image/Makefile`，17–20 行 | Taurus 非 FPGA 分支选择 RTL8277C 头；镜像使用 `rtl8277C`/`realtek,taurus` 命名 | 进一步限定正确芯片分支，不外推 TYFZA1 物理插口映射 |
| `FC/Makefile`，16、128–134、205–211 行 | source build 的 ASIC 目录为 `asicDrv`；77C 与 G3 选择不同目标文件 | 纠正报告的近似名称引用；二者不能交叉替代 |
| BPI VLAN DAL | 10 个关键入口只有日志、初始化/参数检查和成功返回；enable setter 只改软件变量 | 不可充当 VLAN 硬件后端，不可用“返回成功”标记卸载成功 |
| BPI L2 DAL | 确有 AAL FDB 调用，但与 GP3000 并非同版本 | 逐项比较使用，不把“另一个公开仓库”自动当升级版 |
| BPI 真实 77C ASIC 后端，275–325 行 | 初始化对 NI0–6 的 mapping 采用 QM 路径；GP3000 对相同区域另有按 physical-port/deep-Q 状态选择的逻辑 | 显示数据路径依赖整体初始化策略；不能从一个端口 mapping 推导全路径或直接搬入 ThorOS |
| BPI FC CPU copy 与组播替换 | 仍使用 POL token 和 SA LUT 恢复源口；新组发布后释放旧组 | 没有新增可靠的首包/MAC move 源口恢复或 MCE/EPP 完成栅栏 |

### VLAN 空实现的精确范围

[`dal_rtl8277c_vlan.c`](https://github.com/BPI-SINOVOIP/BPI-RT2/blob/c24c6c03c6466cfb1b9e4eacadab8225a457a771/rtk_openwrt/target/linux/realtek_bb/files-5.10/drivers/net/ethernet/realtek/rtl86900/sdk/src/dal/rtl8277c/dal_rtl8277c_vlan.c)：

- `create`、`destroy`、`destroyAll`：138–215 行。
- `portPvid_get/set`：238–276 行。
- `port_get/set`：298–356 行。
- `vlanFunctionEnable_get`：376–387 行；setter 的 408–421 行只更新 `VLAN_FUNC_ENABLE`。
- `fidMode_get/set`：443–490 行。

尤其 getter 不写输出；因此“源码具有 getter/setter”不表示其语义已实现。实际硬件 VLAN 能力仍应逐项取证于 `aal-77c/aal_l2_vlan.c`、端口配置与生成寄存器，而不是否定芯片存在 VLAN 能力。

### 不能回退复制的 L2 DAL 差异

BPI `dal_rtl8277c_l2.c` 81–103 行的 link-down flush 没有 GP3000 对应 95–96 行的静态条目筛选；BPI 141 行也未检查 scan filter 安装返回值，GP3000 对应 146–150 行会检查。两版默认 aging 参数尺度和 unknown-destination drop 配方也存在差异。本文不据此推断确切版本先后，但可以确定：**整体替换为 BPI 代码不是已证明的修复方向**。

## 3. 没有因此解决的硬件契约

### CPU 副本标记仍需验证

BPI `FC/core/rtk_fc_driver.c` 2232–2260 行仍通过 SA LUT 恢复复制报文入口；5924–5940 行将 CPU copy 动作设置为厂商约定 token。`FC/src/rtk_fc_mgrTRx.c` 2258–2266 行仍以 MC 源口、组播 DA 与 POL token 识别副本。它们没有消除首次学习、MAC 移动和旧代报文的问题。

相同 generated header 的 39249–39264 行仍只给出 `NI_HV_MCE_CTL_REG`（`0xaa60`）及 `cp_lspid_to_pol_id_en`、`buf_flush_en` 位，默认 bit17 为 1。此次新增已读文件中没有找到 bit17 与 MCFIB `pol_id` 的明确覆盖顺序。不能凭 token56 在厂商整套系统中使用，就直接开启 ThorOS BUM 去重。

### 计数器与退休仍不可互相替代

同头文件 39311–39347 行定义 `0xaa70/0xaa74/0xaa78` 的字段宽度和默认值；本次已取的 BPI/GP3000/77C 相关文件中未找到这些计数器的 clear-on-read、W1C 或可信复位协议。故不能将它们默认为无副作用的周期采样寄存器。

MCE 输入、输出本来就可能因复制而不相等；即使观察到稳定，也不构成 MCE recipe 退休或 EPP/GRO 旧 CPU 副本已消失的证明。BPI `FC/core/rtk_fc_driver.c` 6091–6112 行仍是新组发布后执行软件释放调用，没有新增硬件完成、CPU 队列或 Linux 发布栅栏。

这次资料对照既没有证明“全二层不可能”，也没有证明“全二层可以无条件开门”。上一轮的[完整 L2 证据矩阵](rtl9617c-full-l2-evidence-20261114.md)仍适用。

### NI MIB：从接口名进一步核到真实读事务

为落实报告的计数证据建议，本轮继续读取已有底层仓库中此前未纳入独立 oracle 的
[`aal-77c/aal_ni_l2.c`](https://github.com/jameywine/ca-network-drivers/blob/8b4f4882ff0e237a1fa558fb0838e4b680bd6bd0/ca-network-engine/1.0-r0/ca-network-engine-1.0/aal-77c/aal_ni_l2.c)，
SHA256 为 `b9a44c40b07e484ef017653afdb60e19d20163a3c12e64d435c0880319cf14e7`。
这不是 BPI 的新版本替换，而是对现有 77C 基线新增可执行对照。

生产 helper 的 64-bit ALL_BYTE 读取原先先 DATA0 后 DATA1；SDK 两个方向均先 DATA1 后 DATA0，本轮已对齐。
新增测试编译运行实际 RX/TX/public getter 与 ACCESS 宏，按 40 组输入比较全部 52 个原始槽位、48 次 ACCESS 写入和 50 次 DATA 读取的有序轨迹，另覆盖超时重试不覆盖在途命令。
ACCESS busy 轮询次数并不要求与厂商代码相同；本项目额外保留发新命令前的 idle 检查。轨迹相同不是实机总线时序相同。

同源 185 行定义 READ_ONLY=0，330 行初始化全局 `cnt_op_mode=2` 并标注 clear-on-read；1857–1955 行的读取使用显式 opcode0/2。
现有资料没有明确二者优先级或可靠的 reset-generation 协议。因此新缓存仅保留 raw 观察、配置与采样状态，明示 `counter_mode_verified=0`，不计算 MAC 吞吐或归因 L2 命中。
真实代码修复与采集边界分别见[原生 L2 实现文档](rtl9617c-native-l2-20261114.md)和[实机前证据工具](rtl9617c-prehardware-evidence-20261114.md)。

## 4. 许可线索和交付边界

选定的 DAL、FC、ASIC 文件包含 Realtek 专有使用声明；`rtk_fc_driver.c` 同时含 `MODULE_LICENSE("GPL")`。generated header 和部分 Makefile 没有可单独据以确定再分发许可的文件内声明。上述事实不能被简化为“整个仓库开源”或“全部文件均禁止参考”的法律结论；本轮只记录证据，不做许可授予判断。

本仓库新增的是原创的资料清单、核验程序、诊断和回归实现，不并入这些厂商文件。公开可读、能够下载、模型/宿主测试成功、内核对象编译成功分别是不同证据层级，都不等于完整固件和两种 TYFZA1 板型已经通过实机验收。
