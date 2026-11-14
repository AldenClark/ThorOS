# L2 FDB 与 L3 DA 引用的隔离依据

## 结论与边界

RTL8277C/RTL9617C 的 L3 普通流动作使用 **13 位 FDB 行索引**读取目的 MAC，VLAN 改写和输出端口是另外的动作字段。公开 GPL SDK 的实际 RTL8277C 生产调用链支持这一设计，不是根据同名的 VENUS MAC 表推测。

本次将 L3 DA 引用的 FDB key 固定为 `(MAC, VID=4095, SC=1, PCP=0)`，行类型固定为有效、静态、单播、双向 permit，禁止 temporary / static-move。行的逻辑输出端口为 CPU16，仅作为误查到该 key 时的防御，不作为隔离的主要机制。

这是一项基于生产 SDK 调用链与寄存器定义的工程推论：**尚未取得完整 ASIC 微架构手册证明所有 stepping 的索引读取不会再次检查 VID，也未在实机完成该域的收发验证。** 单元测试证明编码、共享资源边界及软件实现，不等同于硅片认证或吞吐量结果。启用前必须同时满足下述包侧隔离及所有权约束；只改 key 不足以安全共存。

## 锁定的参考来源

参考仓库是厂商 GPL 发布代码的公开镜像，不冒称为 Realtek 官方认证发布渠道。

- [GPL-for-GP3000](https://github.com/jameywine/GPL-for-GP3000/tree/5090fbcb6ba743dd7b1314811ef557bad0460147)，commit `5090fbcb6ba743dd7b1314811ef557bad0460147`。
- [ca-network-drivers](https://github.com/jameywine/ca-network-drivers/tree/8b4f4882ff0e237a1fa558fb0838e4b680bd6bd0)，commit `8b4f4882ff0e237a1fa558fb0838e4b680bd6bd0`，使用 `aal-77c`，不使用其他芯片目录作 77C 证明。

下表 GPL 路径均相对于 `linux-5.10.x/`。SHA256 对应下载后的原始完整文件，便于独立重新获取核对。

| 文件 | SHA256 |
| --- | --- |
| `drivers/net/ethernet/realtek/rtl86900/FleetConntrackDriver/core/asicDrv/rtk_8277c_asicDriver.h` | `d9b49bd8a67a3638fe2001ddb8d41cf2c4ab8b4eba55d3de875b95724d303f24` |
| `drivers/net/ethernet/realtek/rtl86900/FleetConntrackDriver/core/asicDrv/rtk_8277c_asicDriver.c` | `ff931fc01a1702d33272b0716453c8d2f39e6bf162035b579010fd760dc2780f` |
| `drivers/net/ethernet/realtek/rtl86900/sdk/src/dal/rtl8277c/dal_rtl8277c_l2.c` | `9e450a232f14bf2c214b299c8f83f03a379a24216afdec12a09f37c0e1ff7e45` |
| `drivers/net/ethernet/realtek/rtl86900/FleetConntrackDriver/core/rtk_fc_callback.c` | `87117c742112225962537754f67d74b09d3f95ba48bfc644b5d9c1b0f636d966` |
| `drivers/net/ethernet/realtek/rtl86900/FleetConntrackDriver/core/rtk_fc_mappingAPI.c` | `7e041a4d113115e0749e22032cb0a70302a8326b863fe44d38aa53e2581f8c71` |
| `include/soc/cortina/rtl8277c_registers.h` | `ce5940a274a14c91e5bf3cf96e4583d2d1d086ae601eb716566dfc70d87633e0` |

以下文件来自上述 `ca-network-drivers` commit，路径相对于 `ca-network-engine/1.0-r0/ca-network-engine-1.0/`：

| 文件 | SHA256 |
| --- | --- |
| `aal-77c/aal_fdb.c` | `b578ced837bf926a2f440b25a775e74935413a983cb8b27dbecb46ead35a8683` |
| `aal-77c/aal_l2_vlan.c` | `c3a4703abbe3008eef400d931282603e5439a13cbef04f4ef83f6f589a600084` |
| `cortina-api/vlan.c` | `d819b6621f11054df8a92bb323affcbb741e90dcfad38af5bcefa0f34dc33b20` |

## 生产调用链证据

| 层次 | 精确位置 | 能证明什么 |
| --- | --- | --- |
| 77C 流动作 API | `rtk_8277c_asicDriver.h:604–608`，以及 `653–657`、`706–708` | `out_dmac_trans` 使用 `mac_da_idx`；该 13 位成员的注释明确为 `fdb index 4096 + 32 overflow`。不是 VENUS 的独立 interface-MAC table。 |
| FDB 注册 | `dal_rtl8277c_l2.c:1321–1345` | 实际输入 VID、PCP、MAC、port 和 static/permit 属性写入 FDB；不是只允许 key VID0 的特殊表。 |
| 获取索引 | 同文件 `1355–1359` | 以注册的 MAC、VID、PCP 调用 `aal_fdb_entry_offset_get()`，返回 FDB 行地址给调用者。 |
| FC 所有权 | `rtk_fc_callback.c:1006–1035` | FC 把 `CVID` 传入上述注册路径，固定 static 防止硬件 aging，再保存返回的 FDB index。 |
| 动作编译 | `rtk_fc_mappingAPI.c:479–509` | path5 动作只拿 `lutEgrDaIdx` 作为 DA 引用；输出 VLAN 数量、TPID、VID、PCP、DEI 独立设置，不从 FDB 行 VID 推导。 |
| 写入实际 77C 动作 | `rtk_8277c_asicDriver.c:1404–1438`、`1600–1634`、`1824–1869` | 将该索引赋给 `hash_action.mac_da_idx` 并设置 valid；VLAN 改写是单独的后续动作。 |
| 77C FDB 原语 | `aal-77c/aal_fdb.c:2856–2920` | `aal_fdb_entry_offset_get()` 接受 12 位 VID（含 4095），按 key 执行 READ，返回 `CMD_RETURN.ext_status`；其 API 固定 SC0。本驱动通过原始命令写 SC1，依据的是硬件 key 位域，而非该 API 的固定 SC。 |
| 真实硅片字段 | `rtl8277c_registers.h:11090–11123` | DATA1 的 key VID 为 12 位、SC 为 1 位、PCP 为 3 位；MAC 共 48 位。独立 host oracle 使用原始生成的位域声明解码。 |

`aal-77c/include/aal_fdb.h::aal_fdb_data0_t` 补充单播 DATA0 overlay：LPID 为 6 位、refresh 为 bit6、static-move bit7、temporary bit8、valid bit9。生成头的 DATA0 是复用的 multicast 视图，不能把其中低十位的 `mc_gid` 名称直接当作单播端口定义。

### SVL 包侧 key 与 CPU 原始命令不是同一层

V1 **保持现有全局 VLAN 模式，仅当其已经为 SVL，且 `use_dot1p_l2e=0` 时允许 native L2**；不为启用 LAN 交换改成 IVL，也不在运行中切换全局模式。该限制来自以下可复核的调用关系：

- `aal-77c/aal_fdb.c:4946–4955`（hash collision）、`5110–5125`（learn-limit）和 `5163–5181`（software learning）在 SVL 下明确将学习对象的 `key_vid`、`key_sc_ind` 归零，然后交给后续 FDB API。它支持 SVL 包侧学习采用 `(VID0, SC0)` 的判断，而不是以外层 tag 直接选择私有域。
- `aal-77c/aal_l2_vlan.c:569–582` 的默认配置使用 SVL；实际设备仍须读取模式验证，不能由 SDK 默认值推定其当前状态。真实寄存器 `L2FE_PLC_VLAN_MODE_CTRL` 的 bit0 是该模式；`L2FE_PLC_HASH_CTRL` 的 bit6 控制 PCP 是否进入 L2 key。
- 与包侧学习独立，`aal-77c/aal_fdb.c:96–260` 的 `__aal_fdb_access()` 对 READ/APPEND/DELETE 直接把调用方四个 DATA word 写入 CPU 命令窗口，不读取 VLAN mode，也不把 VID/SC 归零；`2856–2920` 的 offset lookup 同样保留调用方 VID。因此原始命令层与其上方的 SVL 软件归一化明确分开。
- 高层 `__aal_fdb_entry_add_del()` 在 `1168–1175` 还会根据输出端口 TPID 配置重算 SC。ThorOS 私有 pin 不调用这个高层包装，而是编码 raw key 后调用共享 CPU command-window 原语，避免把端口 TPID 当作私有域选择器。
- `cortina-api/vlan.c:454–499` 切换 IVL/SVL 的流程先关闭学习并 flush 整张 FDB。这不是可在 L3 pin 仍被引用时照搬的轻量操作；V1 明确不调用或模拟该切换流程。

这是原始命令保持私有 key、包侧 SVL lookup 使用受控普通域的源码依据；它仍不替代在目标 silicon 上验证“SVL 下 raw APPEND/READ 得到私有行、同 MAC 的普通域行与私有行同时存在、L3 按索引改 DA 正确”的实机测试。不能用主机 MMIO 模型宣称硬件已完成这项验证。

## 为什么不能继续借用普通 bridge FDB 行

原设计按 MAC、VID0、SC0 查找行，建立 L3 流时将其静态 pin；最后一个引用释放时恢复建立流前的整行快照。加入真正的 L2 硬件交换后会出现两类冲突：

1. 没有现存行时会新建静态 LPID0 行，把本应由 bridge 学习的主机固定到错误输出口。
2. 已有 bridge 行时会冻结动态 aging/move，且最后一次 L3 release 会把 bridge 期间更新的端口、permit 或删除动作恢复成旧状态。

反过来，bridge aging、MAC move 或 flush 若释放/复用仍被 L3 引用的行，L3 动作会读取另一对象的目的 MAC。两套独立快照与锁不能解决共享硬件对象的所有权问题。

## 包侧与所有权约束

1. **整个 VID4095 域保留。** 包侧 FDB lookup/learning 不得使用该域，包括线侧 tag、priority-tag 的 PVID、默认 VLAN、分类器 remap、内外层 QinQ 选择以及 PON EVTO 输出域。V1 依赖已验证的当前 SVL、PCP 不参与 key、非 LAN 学习隔离，以及对不支持报文的硬件 trap/整体软件 fallback；不能仅检查 Linux 下发的 VLAN 配置。SC1 本身是正常 S-tag 指示，不是不可达的隐藏域。CF 最终 redirect-to-CPU 不证明较早的 SA lookup/learning 没有发生，不能单独作为域隔离证据。
2. 不支持的 S-tag/QinQ、未知 TPID、MST 或多 bridge 域不得被泛化成“接受所有以太帧”的硬件规则。V1 需要明确的 CPU 保留路径。合法 VID1–4094 和 priority-tag VID0 的正确行为不能因保留域变成静默改写。
3. **保持既有模式，V1 仅准入 SVL。** 正常 VLAN-unaware bridge 使用受控 key0/SC0/PCP0 域；`use_dot1p_l2e` 必须已经为0。IVL、PCP 入 key 或未经证明的 selector 组合回退软件，而不是擅自调整 PON 的全局语义。禁止运行中无协调地切换全局 IVL/SVL。仅将 ILPB 的 PVID/SC 设为0不足以证明带 tag 报文也使用 key0；`ca_port_pvid_tpid_set()` 的 SC 是 PVID 的 TPID属性，解析到的外层 tag 有独立 S/C 信息。
4. L2 walker、Linux learn/move/age 通知、普通 bridge flush 必须调用 `rtl_fe_fdb_is_pin_domain()` 排除所有 VID4095 行，包括 SC/PCP/type 不符合预期的行。不能把私有 CPU16 行报告为 Linux bridge 的 local FDB；普通 VID 的 local CPU16 行又不能误归为 L3 私有行。
5. `rtl_fe_fdb_is_pin()` 是更严格的 ready-row 类型验证，不是 L2 删除过滤器。非预期私有行需要报错/隔离并保留 owner，不能由 L2 清理或由新 L3 引用无条件覆盖。
6. L2、L3 使用同一个 FDB command-window 锁，并由共同 fabric owner 管理全局控制字、学习/老化模式及 reset。BUSY 检查防止旧超时命令的 staging 数据被覆盖，但不能替代跨调用者的互斥锁。
7. 任何全表 reset/flush、驱动重建或私有域迁移必须先阻止新的快路径 admission，再撤销/排空全部 L3 引用和 L2 owner，确认硬件命令完成后重放配置。不能留下旧 index 对应的新 MAC。
8. PON GEM/EVTO/TCONT 属于独立服务控制面，不能因本地 bridge VID 相同就合并。PON logical ports32–63 在 VLAN membership map 中共享 bit7，不代表具有 32 个独立本地 bridge 域。

## 多 bridge 与表容量的保守边界

实际 FDB key 没有经过证明的独立 Linux bridge/FID 字段。SDK 历史 `zone` 成员标注不再使用；VLAN FIB 的 `vlan_group_id` 指向 multicast/flood replication group，不是 FDB 的 FID。

LAN/WAN VID→FIB 索引表各有 12 位地址，但共享 FIB 只有 128 个 profile，membership/untag 位图各为 16 位。独立 port-membership 表覆盖 64 个 logical PID。不能由此宣称任意数量 bridge、任意重叠 VID 和同 MAC 可以同时独立学习。

在没有验证内部 VID remap 与反向 egress translation 之前，多 bridge 重叠域必须拒绝硬件 admission 或回退软件；per-port isolation 单独存在也不能让同一 `(MAC, VID, SC)` 同时指向两个不同 bridge 的端口。

## 验证与剩余实机验收

- `scripts/test_fe_fdb_domain.py`：生产 helper；65,520 个普通 VID/SC/PCP key 与同 MAC/static/local-CPU 并存；私有域损坏字段的保守保护；aging/refresh 不改变所有权。
- `scripts/test_fe_register_contract.py --registers …/rtl8277c_registers.h`：SHA256 验证后，使用实际生成的寄存器位域解码 48 个单 bit MAC 和全部 VID/SC/PCP 组合。
- `scripts/test_fe_table.c`：固定四个 word 的独立已知值断言。
- 既有 destination timeout/status tests：保留 APPEND/LOOKUP/DELETE 不确定性下的引用与回收约束；索引 namespace 变更不允许削弱失败时 ownership。

实机仍须验证：同 MAC 不同 VLAN；LAN 主机移口；bridge local CPU MAC；静态 FDB 增删；未标记/priority-tag/S-tag/QinQ/VID4095；L3 active 时 L2 flush；FDB 满表/overflow；L3 disable/re-enable 与引擎重启；PON 重拨后旧索引清理。至少抓包核对 MAC/VLAN/PCP/DEI 和端口，确认私有 FDB 行没有 learn/move/age 通知泄漏，再进行双向并发吞吐和丢包测试。
