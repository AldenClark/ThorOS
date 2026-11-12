#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
set -eu
export TYFZA1_CARGO=${TYFZA1_CARGO:-$(command -v cargo)}
export PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin
if [ -n "${TYFZA1_PROXY:-}" ]; then
    export http_proxy=$TYFZA1_PROXY https_proxy=$TYFZA1_PROXY
fi
export CURL_OPTIONS='--speed-time 60 --speed-limit 1024'
umask 022
PORT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
PROJECT=$(CDPATH= cd -- "$PORT/.." && pwd)
export TYFZA1_PROJECT=$PROJECT
TREE=${1:?Usage: build.sh /path/to/openwrt-checkout [jobs]}
TREE=$(realpath "$TREE")
JOBS=${2:-2}
if [ -z "${TYFZA1_RUNTIME_INPUTS:-}" ]; then
    python3 "$PROJECT/tools/prepare_pon_runtime.py" "$TREE/files" \
        --stock "${TYFZA1_STOCK_INPUTS:-$PROJECT/analysis/private/live-files}" \
        --check-inputs-only
fi
sh "$PORT/scripts/sync-overlay.sh" "$TREE"
sh "$PROJECT/scripts/prepare_luci_feeds.sh" "$TREE"
cd "$TREE"
make defconfig
for package in luci-app-tyfza1-pon luci-theme-argon luci-i18n-argon-config-zh-cn; do
    grep -qx "CONFIG_PACKAGE_$package=y" .config || {
        echo "Required firmware package missing after defconfig: $package" >&2
        exit 1
    }
done
while IFS= read -r setting; do
    case "$setting" in
        CONFIG_PACKAGE_*=y)
            grep -qxF "$setting" .config || {
                echo "Required plugin dependency missing after defconfig: $setting" >&2
                exit 1
            }
            ;;
    esac
done < "$PORT/configs/tyfza1-compat.config"
# Catch dependencies which would re-introduce an explicitly removed feature.
while IFS= read -r setting; do
    case "$setting" in
        '# CONFIG_'*' is not set')
            option=${setting#\# }
            option=${option% is not set}
            if grep -qx "${option}=y" .config; then
                echo "Removed TYFZA1 feature selected after defconfig: $option" >&2
                exit 1
            fi
            ;;
    esac
done < "$PORT/configs/tyfza1-exclusions.config"
# A custom build config cannot silently put the radio stack back into the image.
if grep -Eq '^CONFIG_PACKAGE_(kmod-cfg80211|kmod-mac80211|kmod-rtl-ax-ap|iw|iwinfo|libiwinfo[^=]*|rpcd-mod-iwinfo|hostapd[^=]*|wpad[^=]*|wifi-scripts|wireless-regdb)=y$' .config; then
    echo "Wireless packages selected in a wired-only TYFZA1 build" >&2
    exit 1
fi
# On this WSL host, TCP fakeroot fails at the first file operation. Use the
# existing upstream SysV backend, not root builds or altered package ownership.
if grep -qi microsoft /proc/sys/kernel/osrelease; then
    if grep -q -- '--with-ipc=tcp' tools/fakeroot/Makefile; then
        patch -p1 < "$PORT/host-patches/100-fakeroot-sysv.patch"
        make tools/fakeroot/clean
    fi
fi
make -j"$JOBS" download
# Catch package-source patch drift before the expensive toolchain/kernel build.
# The upstream version of netifd can change its hotplug event code even when
# the OpenWrt checkout itself is pinned and all configuration checks succeed.
python3 "$PROJECT/scripts/test_fw4_topology_events.py" --source-tree "$TREE" --patches-only
if [ -n "${TYFZA1_RUNTIME_INPUTS:-}" ]; then
    python3 "$PROJECT/tools/install_runtime_inputs.py" "$TYFZA1_RUNTIME_INPUTS" "$TREE/files"
else
    python3 "$PROJECT/tools/prepare_pon_runtime.py" "$TREE/files" \
        --stock "${TYFZA1_STOCK_INPUTS:-$PROJECT/analysis/private/live-files}"
fi
make -j"$JOBS" world
