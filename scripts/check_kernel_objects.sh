#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
# Compile real ARM64 RTL9617C and flowtable/bridge objects against the complete
# locked OpenWrt kernel patch baseline. No firmware, private inputs or signing.
set -euo pipefail
export LC_ALL=C

usage() {
    printf '%s\n' \
        'Usage: bash scripts/check_kernel_objects.sh [options]' \
        '  --work-dir PATH    New/empty output directory (default artifacts/kernel-objects)' \
        '  --openwrt PATH     Existing git checkout at the locked OpenWrt SHA; exported read-only' \
        '  --kernel-tar PATH  Existing official Linux .tar.xz; locked SHA256 is mandatory' \
        '  --jobs N           Parallel build jobs (default 2)' \
        '  --prepare-only     Validate sources and apply ALL patches; does NOT compile' \
        '' \
        'Ubuntu dependencies: build-essential gcc-aarch64-linux-gnu binutils-aarch64-linux-gnu' \
        '  flex bison bc libssl-dev libelf-dev pkg-config python3 perl git curl patch xz-utils' \
        'CROSS_COMPILE may select another ARM64 GCC prefix. This script never installs tools.' \
        'The config merges the production generic/target seeds with kernel-objects.config.' \
        'Passing proves object compilation, not a final vmlinux link, firmware boot or throughput.'
}

project=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
work="$project/artifacts/kernel-objects"
openwrt_input=
kernel_input=
jobs=2
prepare_only=0
while (( $# )); do
    case "$1" in
        --work-dir|--openwrt|--kernel-tar|--jobs)
            (( $# >= 2 )) || { usage >&2; exit 2; }
            case "$1" in
                --work-dir) work=$2 ;;
                --openwrt) openwrt_input=$2 ;;
                --kernel-tar) kernel_input=$2 ;;
                --jobs) jobs=$2 ;;
            esac
            shift 2 ;;
        --prepare-only) prepare_only=1; shift ;;
        --help|-h) usage; exit 0 ;;
        *) usage >&2; exit 2 ;;
    esac
done
[[ "$jobs" =~ ^[1-9][0-9]?$ ]] || { printf 'Invalid jobs: expected 1..99\n' >&2; exit 2; }
# The locked OpenWrt patch-kernel.sh expands its directory operands unquoted.
# Fail clearly instead of quietly changing that upstream helper's semantics.
if [[ "$project" =~ [[:space:]] || "$work" =~ [[:space:]] ]]; then
    printf 'Project and work paths must not contain whitespace (OpenWrt patch helper constraint).\n' >&2
    exit 2
fi

cross=${CROSS_COMPILE:-aarch64-linux-gnu-}
needed=(python3 git curl tar xz patch perl sha256sum cp)
if (( ! prepare_only )); then
    needed+=(make gcc flex bison bc pkg-config "${cross}gcc" "${cross}ld" "${cross}ar"
             "${cross}nm" "${cross}objcopy" "${cross}readelf")
fi
missing=0
for tool in "${needed[@]}"; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        printf 'Missing build dependency: %s\n' "$tool" >&2
        missing=1
    fi
done
(( missing == 0 )) || { usage >&2; exit 1; }

mapfile -t lock < <(python3 - "$project/port/sources.lock.json" <<'PY'
import json, re, sys
with open(sys.argv[1]) as file:
    source = json.load(file)['openwrt']
assert re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', source['kernel'])
assert re.fullmatch(r'[0-9a-f]{40}', source['commit'])
assert re.fullmatch(r'[0-9a-f]{64}', source['kernel_sha256'])
assert source['url'] == 'https://github.com/openwrt/openwrt.git'
print(source['kernel'])
print(source['commit'])
print(source['kernel_sha256'])
print(source['url'])
PY
)
(( ${#lock[@]} == 4 )) || { echo 'Invalid source lock' >&2; exit 1; }
kernel_version=${lock[0]}
openwrt_commit=${lock[1]}
kernel_hash=${lock[2]}
kernel_series=${kernel_version%.*}

if [[ -e "$work" ]] && { [[ ! -d "$work" ]] || [[ -n "$(ls -A -- "$work")" ]]; }; then
    printf 'Refusing to overwrite non-empty work directory: %s\n' "$work" >&2
    exit 1
fi
mkdir -p -- "$work"
work=$(CDPATH='' cd -- "$work" && pwd -P)
printf 'Kernel object check output: %s\n' "$work"
exec > >(tee "$work/build.log") 2>&1
printf 'kernel=%s openwrt_commit=%s prepare_only=%s\n' "$kernel_version" "$openwrt_commit" "$prepare_only"
sh "$project/port/scripts/write-build-info.sh" "$work/thoros-build-info"

if [[ -z "$openwrt_input" ]]; then
    openwrt_input="$work/openwrt-git"
    git init -q "$openwrt_input"
    git -C "$openwrt_input" remote add origin "${lock[3]}"
    git -C "$openwrt_input" fetch --depth=1 origin "$openwrt_commit"
    git -C "$openwrt_input" update-ref HEAD FETCH_HEAD
fi
[[ "$(git -C "$openwrt_input" rev-parse HEAD)" == "$openwrt_commit" ]] || {
    echo 'OpenWrt HEAD does not match sources.lock.json' >&2; exit 1;
}
openwrt="$work/openwrt-source"
mkdir -p "$openwrt"
# Export committed objects, not a possibly patched working tree. This also
# works with sparse checkouts and cannot alter the caller's reference checkout.
git -C "$openwrt_input" archive "$openwrt_commit" \
    target/linux/generic include/quilt.mk include/target.mk \
    scripts/patch-kernel.sh scripts/kconfig.pl | tar -x -C "$openwrt"

if [[ -z "$kernel_input" ]]; then
    kernel_input="$work/linux-$kernel_version.tar.xz"
    curl --fail --location --silent --show-error --retry 3 --connect-timeout 15 --max-time 600 \
        "https://cdn.kernel.org/pub/linux/kernel/v${kernel_version%%.*}.x/linux-$kernel_version.tar.xz" \
        --output "$kernel_input"
fi
printf '%s  %s\n' "$kernel_hash" "$kernel_input" | sha256sum -c -
kernel="$work/linux-$kernel_version"
mkdir -p "$kernel"
tar -xJf "$kernel_input" --strip-components=1 -C "$kernel"
[[ -f "$kernel/arch/arm64/Makefile" && -f "$kernel/Makefile" ]] || {
    echo 'Not a complete ARM64 kernel source tree' >&2; exit 1;
}

generic="$openwrt/target/linux/generic"
target="$project/port/overlay/target/linux/rtl9617c"
printf 'Preparing overlays and full patch stack (OpenWrt include/quilt.mk order)\n'
# OpenWrt Kernel/Patch/Default copies generic/platform files BEFORE applying
# generic-backport, generic-pending, generic-hack and platform patches.
for directory in "$generic/files" "$generic/files-$kernel_series" \
                 "$target/files" "$target/files-$kernel_series"; do
    if [[ -d "$directory" ]]; then
        cp -a "$directory/." "$kernel/"
    fi
done

apply_directory() {
    local directory=$1 file line remainder
    [[ -d "$directory" ]] || return 0
    local -a series=()
    if [[ -s "$directory/series" ]]; then
        while IFS= read -r line || [[ -n "$line" ]]; do
            line=${line%%#*}
            [[ "$line" =~ ^[[:space:]]*$ ]] && continue
            # Pinned series contain simple filenames, not arbitrary commands.
            read -r file remainder <<< "$line"
            [[ -z "${remainder:-}" && "$file" != */* && "$file" != -* ]] || {
                printf 'Unsupported patch series entry: %s\n' "$line" >&2; return 1;
            }
            series+=("$file")
        done < "$directory/series"
    else
        for file in "$directory"/*; do
            [[ -f "$file" ]] && series+=("${file##*/}")
        done
    fi
    for file in "${series[@]}"; do
        [[ -f "$directory/$file" ]] || { echo "Missing patch: $directory/$file" >&2; return 1; }
        # Same decompression/patch mechanism as OpenWrt; additionally fail on
        # context fuzz rather than silently accepting a mismatched baseline.
        PATCH='patch --batch --fuzz=0 --no-backup-if-mismatch' \
            sh "$openwrt/scripts/patch-kernel.sh" "$kernel" "$directory" "$file"
        sha256sum "$directory/$file" >> "$work/applied-patches.sha256"
    done
}
for kind in backport pending hack; do
    directory="$generic/$kind"
    [[ ! -d "$generic/$kind-$kernel_series" ]] || directory="$generic/$kind-$kernel_series"
    apply_directory "$directory"
done
apply_directory "$target/patches-$kernel_series"

out="$work/objects"
mkdir -p "$out"
generic_config="$generic/config-$kernel_series"
[[ -f "$generic_config" ]] || generic_config="$generic/config-default"
# kconfig.pl implements the actual OpenWrt + overlay precedence. Package
# metadata is intentionally replaced by an explicit compile-check fragment.
perl "$openwrt/scripts/kconfig.pl" + + "$generic_config" "$target/config-$kernel_series" \
    "$project/scripts/kernel-objects.config" > "$out/.config"
cp "$out/.config" "$work/config.seed"
if (( prepare_only )); then
    printf 'status=prepared_only\ncompiled=0\n' > "$work/result.txt"
    printf 'PREPARED ONLY: all locked source patches applied; no objects compiled.\n'
    exit 0
fi

"${cross}gcc" --version | head -n 1
export KBUILD_BUILD_USER=thoros-ci KBUILD_BUILD_HOST=kernel-object-check KBUILD_BUILD_VERSION=1
export KBUILD_BUILD_TIMESTAMP='1970-01-01 00:00:00 +0000'
kmake=(make -C "$kernel" O="$out" ARCH=arm64 CROSS_COMPILE="$cross")
"${kmake[@]}" olddefconfig
for symbol in ARM64 ARCH_RTL9617C RTL9617C_XRAM_ETH RTL9617C_PON RTL9617C_BOSA \
              NF_FLOW_TABLE NF_FLOW_TABLE_INET NFT_FLOW_OFFLOAD BRIDGE BRIDGE_VLAN_FILTERING \
              BRIDGE_IGMP_SNOOPING NET_SWITCHDEV VLAN_8021Q NETFILTER_INGRESS \
              SKB_EXTENSIONS NET_CLS_ACT PPP PPPOE; do
    grep -qx "CONFIG_${symbol}=y" "$out/.config" || {
        printf 'Required compile-check feature not enabled after olddefconfig: %s\n' "$symbol" >&2
        exit 1
    }
done
# Linux 6.18 flattens built-in composite targets into their leaf objects;
# rtl9617c-eth.o, nf_flow_table.o and bridge.o are not link targets with =y.
# Keep the production built-in code paths and compile the actual translation
# units, including VLAN/PPPoE forwarding helpers (not just vlan.c/pppoe.c).
targets=(
    drivers/net/ethernet/realtek/rtl9617c-xram.o
    drivers/net/ethernet/realtek/rtl9617c-dma.o
    drivers/net/ethernet/realtek/rtl9617c-qm.o
    drivers/net/ethernet/realtek/rtl9617c-fe.o
    drivers/net/ethernet/realtek/rtl9617c-bosa.o
    drivers/net/ethernet/realtek/rtl9617c-pon.o
    drivers/net/ethernet/realtek/rtl9617c-pon-serdes.o
    drivers/net/ethernet/realtek/rtl9617c-pon-epon.o
    drivers/net/ethernet/realtek/rtl9617c-pon-mpcp.o
    drivers/net/ethernet/realtek/rtl9617c-pon-pdc.o
    drivers/net/ethernet/realtek/rtl9617c-pon-puc.o
    drivers/net/ethernet/realtek/rtl9617c-pon-oam.o
    drivers/net/ethernet/realtek/rtl9617c-pon-itu.o
    drivers/net/ethernet/realtek/rtl9617c-pon-gpon.o
    drivers/net/ethernet/realtek/rtl9617c-pon-omci.o
    drivers/net/ethernet/realtek/rtl9617c-pon-xgpon.o
    drivers/net/ethernet/realtek/rtl9617c-pon-path.o
    net/netfilter/nf_flow_table_core.o
    net/netfilter/nf_flow_table_ip.o
    net/netfilter/nf_flow_table_path.o
    net/netfilter/nf_flow_table_offload.o
    net/netfilter/nf_flow_table_xdp.o
    net/netfilter/nf_flow_table_inet.o
    net/netfilter/nft_flow_offload.o
    net/bridge/br.o
    net/bridge/br_device.o
    net/bridge/br_fdb.o
    net/bridge/br_forward.o
    net/bridge/br_if.o
    net/bridge/br_input.o
    net/bridge/br_ioctl.o
    net/bridge/br_stp.o
    net/bridge/br_stp_bpdu.o
    net/bridge/br_stp_if.o
    net/bridge/br_stp_timer.o
    net/bridge/br_netlink.o
    net/bridge/br_netlink_tunnel.o
    net/bridge/br_arp_nd_proxy.o
    net/bridge/br_sysfs_if.o
    net/bridge/br_sysfs_br.o
    net/bridge/br_nf_utils.o
    net/bridge/br_multicast.o
    net/bridge/br_mdb.o
    net/bridge/br_multicast_eht.o
    net/bridge/br_vlan.o
    net/bridge/br_vlan_tunnel.o
    net/bridge/br_vlan_options.o
    net/bridge/br_mst.o
    net/bridge/br_switchdev.o
    net/core/skbuff.o
    net/core/flow_offload.o
    net/core/dev.o
    net/8021q/vlan.o
    net/8021q/vlan_dev.o
    net/8021q/vlan_core.o
    net/8021q/vlan_netlink.o
    net/8021q/vlanproc.o
    drivers/net/ppp/ppp_generic.o
    drivers/net/ppp/pppox.o
    drivers/net/ppp/pppoe.o
)
printf '%s\n' "${targets[@]}" > "$work/compile-targets.txt"
"${kmake[@]}" -j"$jobs" "${targets[@]}"
for object in "${targets[@]}"; do
    [[ -s "$out/$object" ]] || { echo "Missing compiled object: $object" >&2; exit 1; }
    "${cross}readelf" -h "$out/$object" | grep -q 'Machine:.*AArch64' || {
        echo "Object is not ARM64 ELF: $object" >&2; exit 1;
    }
    sha256sum "$out/$object" >> "$work/objects.sha256"
done
cp "$out/.config" "$work/kernel.config"
printf 'status=compiled\ncompiled_objects=%s\nkernel=%s\nopenwrt_commit=%s\n' \
    "${#targets[@]}" "$kernel_version" "$openwrt_commit" > "$work/result.txt"
printf 'PASS: %s real ARM64 kernel objects compiled. No firmware linked, booted or published.\n' "${#targets[@]}"
