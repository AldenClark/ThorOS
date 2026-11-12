#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Read-only memory/loaded-module snapshot for the two TYFZA1 board variants.
# No credentials, network configuration or PON identity are collected.
set -eu

printf 'TYFZA1 memory snapshot\n'
date -u '+UTC %Y-%m-%dT%H:%M:%SZ'
uname -r
cat /proc/uptime

printf '\n/proc/meminfo\n'
cat /proc/meminfo

printf '\n/proc/iomem (root may be required for addresses)\n'
cat /proc/iomem

printf '\n/proc/modules (only loaded kernel modules)\n'
cat /proc/modules

printf '\n/tmp/log footprint in KiB\n'
if [ -d /tmp/log ]; then
	du -sk /tmp/log
else
	printf 'no /tmp/log directory\n'
fi

printf '\nPON/LED and log process names (no command arguments)\n'
for status in /proc/[0-9]*/status; do
	[ -r "$status" ] || continue
	read -r label process < "$status" || continue
	case "$process" in
		logd|logread|ucode|pon-oamd|pon-omcid)
			printf '%s %s\n' "${status%/status}" "$process"
			;;
	esac
done

printf '\nRelevant kernel memory messages (filtered)\n'
dmesg 2>/dev/null | grep -Ei 'reserved memory|memblock|Memory:|DMA pool|ATU' || :
