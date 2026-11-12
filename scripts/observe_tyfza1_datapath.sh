#!/bin/sh
# Read-only before/after snapshot of TYFZA1 kernel datapath and CPU counters.
# Usage on the device: sh observe_tyfza1_datapath.sh [seconds]
set -eu

duration=${1:-15}
case "$duration" in
    ''|*[!0-9]*) echo 'Usage: sh observe_tyfza1_datapath.sh [positive-seconds]' >&2; exit 2 ;;
esac
[ "$duration" -ge 1 ] && [ "$duration" -le 3600 ] || {
    echo 'Sample interval must be 1..3600 seconds' >&2
    exit 2
}

# Attributes are registered on the NI platform device, not on each LAN NIC.
ni_dir=${TYFZA1_NI_SYSFS:-}
if [ -z "$ni_dir" ]; then
    for path in /sys/bus/platform/devices/*/dma_state; do
        if [ -r "$path" ]; then
            ni_dir=${path%/dma_state}
            break
        fi
    done
fi

read_attr() {
    name=$1
    if [ -n "$ni_dir" ] && [ -r "$ni_dir/$name" ]; then
        printf '%s: ' "$name"
        cat "$ni_dir/$name"
    else
        printf '%s: unavailable\n' "$name"
    fi
}

snapshot() {
    printf '\n===== TYFZA1 datapath snapshot: '
    date -u '+%Y-%m-%dT%H:%M:%SZ'
    printf 'NI sysfs: %s\n' "${ni_dir:-not-found}"
    read_attr idle_poll_ms
    read_attr rx_prefetch
    read_attr pppoe_rx_checksum
    read_attr dma_state
    read_attr qm_voqs
    read_attr fe
    printf '\n-- uptime --\n'
    cat /proc/uptime
    printf '\n-- CPU --\n'
    cat /proc/stat
    printf '\n-- softirqs --\n'
    cat /proc/softirqs
    printf '\n-- interrupts --\n'
    cat /proc/interrupts
    printf '\n-- memory --\n'
    sed -n '1,9p' /proc/meminfo
    if command -v ip >/dev/null 2>&1; then
        printf '\n-- interface counters --\n'
        ip -s link show || echo 'interface counters unavailable (netlink restricted)'
    fi
}

snapshot
sleep "$duration"
snapshot
