# TYFZA1 Netwatch — ThorOS WAN intermittent outage monitor

Rust 单文件、无第三方 crate 的 macOS 命令行诊断器。专门调查：**外网新连接卡住 10–20 秒、旧连接继续工作、内网互访正常；第三方测速低速并容易诱发断网**。

采用 macOS 自带的 `ssh`、`curl`、`ping`、`dig`。Rust 负责调度、检测、超时控制、对齐时间戳、自动事件捕获和报告。测试没有给路由器安装软件、修改配置、触发重拨或重启服务的操作。

## 使用（Apple Silicon MacBook Air M5）

解压后，在 macOS Terminal 中：

```sh
chmod +x ./tyfza1-netwatch
./tyfza1-netwatch --router 192.168.1.1 --user root
```

运行时可用密码完成**一次 SSH 登录**，后续通过本机 OpenSSH ControlMaster 复用该登录，不会将密码保存到脚本、配置或报告中。第一次连接也可能提示确认路由器 SSH 主机密钥；应先确认该密钥属于你自己的路由器。SSH 账户必须有读取内核/sysfs 信息的权限（通常为 `root`）。

初次测试建议至少运行 1 小时。默认无限运行，按 `Ctrl+C` 结束并整理报告；也可以指定时长：

```sh
./tyfza1-netwatch --router 192.168.1.1 --duration-min 180
```

如果 SSH 在初始阶段失败，先独立验证：

```sh
ssh root@192.168.1.1
```

诊断器不会自动向路由器写入 SSH 公钥或保存密码。需要单独诊断 Mac 对外网络时，可以加 `--no-ssh`，但**缺少路由器侧日志，不能完成根因分析**。

## 监测指标

| 通道 | 默认频率 | 记录什么 | 用来区分什么 |
|---|---:|---|---|
| 已固定 IPv4 的 TCP:443 连接 | 每 2 秒 | 新连接成功/失败和握手时间 | 新建 TCP 流量是否卡住，与 DNS 无关 |
| 中国大陆站点 HTTPS HEAD | 每 3 秒轮换 | URL、IP、HTTP 状态、DNS/TCP/TLS/TTFB/总耗时 | DNS、TLS、HTTP，IPv4 与系统默认栈差异 |
| 路由器网关 ICMP | 每 3 秒 | 延迟与超时 | LAN 通路是否同时受影响 |
| 路由器/公共 DNS | 每 10 秒交替 | `www.baidu.com` A 查询结果与耗时 | 路由器 DNS 是否独立异常 |
| 路由器 SSH | 每 5 秒 | FE、QM、DMA、conntrack、CPU/softnet、PON、接口计数器 | 硬件卸载、转发队列、连接跟踪、CPU 瓶颈 |
| 可选限速负载 | 默认关闭 | 同时下载流数、每流限速、时间、吞吐 | 低速/速度测试能否可控地复现故障 |

使用的是中国大陆常见站点：百度、腾讯、网易、京东、哔哩哔哩、阿里云、新浪。并非全部网站都会对自动化 HEAD 请求返回 200；**403、405、其他非 000 状态也证明网络传输、TLS 已经完成**，不会当成断网。公网平台仍可能限流，因此必须和固定 IP、网关、DNS、路由器计数器交叉判断。

`curl --noproxy '*'` 明确绕过 macOS 的 HTTP 代理设置，减少本机代理/VPN 干扰；但虚拟网卡或系统层隧道路由仍可能影响结果，测试时请记录是否开启 AirRoute 等代理客户端。

## 可选：可控、限速、并发下载

大流量会在正在使用的主路由上增加风险，**程序默认不会启动测速/压测**。只有提供明确的 HTTPS 下载 URL 才会进行测试。推荐先使用自选、可信的大陆 CDN 大文件 URL，默认每条流量上限 512 KiB/s、2 并发，合计最高约 8 Mbit/s，持续 20 秒，每 20 分钟一次。

```sh
./tyfza1-netwatch --router 192.168.1.1 \
  --load-url 'https://YOUR-TRUSTED-MAINLAND-CDN/large-test-file.bin' \
  --load-streams 2 --load-rate-kib 512 --load-seconds 20 --load-every-min 20
```

逐步提高单流限速或并发时，观察 `router-metrics.csv` 中 CPU、FE 硬件流安装/拒绝、丢包和 softnet 计数器的变化。建议在非关键网络时段进行，不要一开始就将合计上限提高到宽带标称速率。

该限速模块仅用于**负载关联与故障复现**，不是经过校准的宽带测速器。服务端、URL 内容、缓存、拥塞控制、CDN 地域和下载时间窗口都影响计算结果；若测速正常，应以独立专业测速结果作为参考。

## 自动证据与报告

程序创建 `results/YYYYMMDD-HHMMSS/`，其中：

- `summary.md`：每 30 秒刷新，包含错误数、p50/p95/p99 延迟、FE/CPU/conntrack 最新值、事件索引。
- `probes.csv`：全部 Mac 侧时间序列，毫秒 Unix 时间戳、探测类型、分阶段耗时、错误详情。
- `router-metrics.csv`：全部路由器侧结构化时间序列，包含 FE 当前流量与安装、删除、拒绝计数，软中断耗时等。
- `router.log`：每 5 秒读取的完整原始硬件、PON/PPPoE、接口、CPU 状态。
- `incident-NNN-*.txt`：检测到连接失败或多个站点同时异常时，附带故障前最多 180 秒、故障后 60 秒的探测结果。
- `incident-NNN-router.txt`：立即通过 SSH 抓取 WAN 状态、IPv4/IPv6 路由、接口、nft/conntrack 统计、最近系统/内核日志。
- `incident-NNN-macos.txt`：Mac 默认路由、DNS 解析器、路由表与接口状态。

触发条件包含：连续两次固定 IPv4 TCP 握手失败、连续两次网关 ICMP 失败、25 秒内三个不同大陆站点传输失败、多个站点超过 4 秒、连续两次路由器 DNS 失败。单个站点一两次 HTTP 错误不会被当作整个 WAN 断网。

故障出现后，尽量让程序再运行 60 秒，保留后半段事件数据。退出时程序会等待当前已触发的取证完成；同一事件会有 45 秒的触发冷却，避免连环捕获加重路由器负担。

**报告注意事项**：原始日志可能包含公网 IP、设备 MAC、邻居地址、连接信息和客户端名称。分享给公开平台前请检查、脱敏。默认不读取 `/etc/config/network` 或其他包含 PPPoE 密码的配置文件。

## 如何利用结果区分原因

1. `tcp`（固定 IP）失败 + `gateway` 正常：新 WAN 连接/PPPoE/NAT/硬件转发应优先排查；不是单纯域名解析问题。
2. `http` 失败，但 `tcp` 正常，路由器 DNS 同时失败：重点排查 DNS 或解析策略。
3. `tcp` 成功，`http` 失败且 TLS 时间突增：重点排查 MTU/MSS、TLS 与目标服务差异。
4. 负载期间 `fe.rejected` 突增、`flows` 不增长，或 `softnet_squeeze`/CPU 激增：调查硬件卸载准入/回退 CPU 的瓶颈；注意 rejected 也可能只是正常的不支持流。
5. 丢包计数器增加且与 TCP 失败同秒：优先检查对应数据面队列；没有计数器变化不代表完全无错误。
6. WAN 拨号状态变化而 LAN 网关仍正常：排查 PON/PPPoE 和 `netifd` 日志。

诊断器只提供证据和关联，不能凭一个计数器自动证明根因。

## 从源码构建

没有任何第三方 Rust crate；在安装 Rust/Cargo 的 macOS 上运行：

```sh
sh build-macos.sh
./dist/tyfza1-netwatch --router 192.168.1.1
```

编译产物跟随本机架构：M 系列是 `aarch64-apple-darwin`，Intel 是 `x86_64-apple-darwin`。CI 模板在 `.github/workflows/build-macos.yml`，可放到独立 GitHub 仓库根目录进行 macOS Actions 编译。

## 最小验证

```sh
cargo test
cargo run -- --help
cargo run -- --no-ssh --duration-min 1
```

最后一个命令仍会访问外部网站，属于网络集成测试；仅执行 `cargo test` 不会访问网络或更改路由器。

