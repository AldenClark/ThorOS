# TYFZA1 runtime memory validation

This release keeps all physical reserved-memory ranges until an actual TYFZA1
can demonstrate that the stock firmware, bootloader, secure world and DMA
engines do not access them. An unused Linux driver is **not** sufficient
evidence that a physical range is unused.

## What is changed

1. Fresh installs use a 128 KiB log ring and no continuously written tmpfs
   log file. Upgrades migrate the original `/tmp/log/tyfza1.log` default and
   leave user-defined destinations and buffer sizes intact. A duplicate
   boot-time `dmesg` snapshot is no longer created.
2. The independent LED `ucode` monitor is not started when users explicitly
   set LED control mode `0`. It continues to run in active LED modes because
   optical LOS and management authentication have no single reliable event
   source. Its default 1-second interval is preserved for diagnostics.
3. The production UBI FIT boots a direct ubiblock SquashFS root, so the
   Device Mapper / dm-verity kernel stack is omitted along with io_uring
   zero-copy RX. `NET_SELFTESTS` remains enabled automatically when PHYLIB and
   INET are built in (Linux `def_tristate PHYLIB`); it is not a background
   test daemon or an independently removable kernel option. The experimental
   `port/tools/make_boot_fit.py` verified-root pipeline still exists, but its
   verity image is **not bootable with the trimmed production kernel**.
4. The TUN, WireGuard, nftables TPROXY and socket kernel packages remain
   installed with upstream load semantics. Changing boot autoload without
   proving automatic `ip link`, `/dev/net/tun` and nft expression module
   loading would introduce hard-to-detect breakage in future router/proxy
   workloads.

## Reserved-memory investigation

| Device tree allocation | Physical size | Requirement before editing |
| --- | ---: | --- |
| VoIP, IPC and vector | 4.004 MiB | Confirm boot firmware/auxiliary core never touches it |
| DDR non-cache | 26.3125 MiB | Record DMA/IOMMU/firmware maps and sustained network traffic |
| DDR cache | 0.0625 MiB | Confirm purpose and owners |
| PE ATU shadow | 4.125 MiB | Prove no ATU alias can overlap released pages |
| TZ/SMC | 0.2539 MiB | Leave reserved (secure world) |

Total: 34.7578 MiB of reserved physical address space. This is **not** an
estimate of recoverable RAM. Data-path DMA/QM/FE allocations are additional
and must not be reduced without performance and packet-loss tests.

## Capture on real hardware

Run `scripts/tyfza1-memory-snapshot.sh` on a device as root, and save its
stdout locally. The script intentionally omits PON credentials and network
configuration. For more precise process-RSS measurements, collect `/proc/PID/
status` for the reported process IDs directly on the device.

Compare cold boot, 10-minute idle, optical reconnect and sustained routed
traffic in both hardware variants (4xGE and 2.5G). Include:

- GPON/EPON/XGPON registration and LOS recovery;
- bridge and PPPoE router modes, DHCP and IPv6;
- Ethernet switch, 2.5G PHY and hardware forwarding;
- WireGuard, TUN and nft TPROXY cold-start and restart;
- sysupgrade, watchdog and rollback from both UBI slots.

Only then test an **experimental, separately identifiable** DT with one
individual carveout removed (starting with VoIP). Do not ship these experiments
as normal production images or combine multiple memory-map changes in one test.
