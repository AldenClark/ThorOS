#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
set -e

/usr/libexec/network/packet-steering.uc "$@"

case "$1" in
	""|1) ni_cpus=4 ;;
	*) ni_cpus=f ;;
esac

# Keep the NI receive interrupt on CPU2 when packet steering is enabled.
for irq in $(awk '$NF == "rtl9617c-rx0" { sub(":", "", $1); print $1 }' /proc/interrupts); do
	echo "$ni_cpus" > "/proc/irq/$irq/smp_affinity"
done
