#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Read-only A/B snapshots. Copy this one file to the router; no companion needed.
# Usage: sh observe_tyfza1_datapath.sh [seconds] [--output new-file]
# --active-diagnostics permits bounded FE table transactions and QM/DMA status
# reads. --details separately permits FE addresses, ports and session IDs.
# Neither option toggles offload, flushes tables or mounts debugfs.
set -u
umask 077

usage() {
    echo 'Usage: sh observe_tyfza1_datapath.sh [1..3600 seconds] [--output new-file] [--active-diagnostics] [--details]'
}
duration=15
duration_seen=0
details=0
active_diagnostics=0
output_file=
while [ "$#" -gt 0 ]; do
    argument=$1
    shift
    case "$argument" in
        --help|-h) usage; exit 0 ;;
        --details) details=1 ;;
        --active-diagnostics) active_diagnostics=1 ;;
        --output)
            [ "$#" -gt 0 ] && [ -n "$1" ] && [ -z "$output_file" ] || {
                usage >&2; exit 2;
            }
            output_file=$1
            shift
            ;;
        ''|*[!0-9]*) usage >&2; exit 2 ;;
        *)
            [ "$duration_seen" = 0 ] && [ "${#argument}" -le 4 ] || {
                usage >&2; exit 2;
            }
            [ "$argument" -ge 1 ] && [ "$argument" -le 3600 ] || {
                usage >&2; exit 2;
            }
            duration=$argument
            duration_seen=1
            ;;
    esac
done

# No truncation of an existing file (including symlinks/FIFOs). Noclobber is
# retained for the create itself, not only a racy test before redirection.
# This controls files we create; permissions of caller-owned stdout redirects
# remain the caller's responsibility.
if [ -n "$output_file" ]; then
    if [ -e "$output_file" ] || [ -L "$output_file" ]; then
        echo 'Refusing existing output path; choose a new file.' >&2
        exit 2
    fi
    set -C
    exec > "$output_file" || exit 2
    set +C
fi

# Overrides also let host regression tests use isolated procfs/sysfs fixtures.
proc_dir=${TYFZA1_PROCFS:-/proc}
sys_dir=${TYFZA1_SYSFS:-/sys}
release_file=${TYFZA1_RELEASE_FILE:-/etc/openwrt_release}
build_info=${TYFZA1_BUILD_INFO:-/etc/thoros-build-info}
ni_dir=${TYFZA1_NI_SYSFS:-}
pon_dir=${TYFZA1_PON_SYSFS:-$sys_dir/bus/platform/devices/4f5500000.pon}
fe_debug=${TYFZA1_FE_DEBUGFS:-$sys_dir/kernel/debug/rtl9617c-fe}
has_timeout=0
command -v timeout >/dev/null 2>&1 && has_timeout=1

if [ -z "$ni_dir" ]; then
    for path in "$sys_dir"/bus/platform/devices/*/dma_state; do
        if [ -r "$path" ]; then
            ni_dir=${path%/dma_state}
            break
        fi
    done
fi

# KILL bounds userspace commands even if they ignore TERM. A blocked kernel I/O
# cannot be made hard-real-time by a shell timeout; do not run intensive probes
# on a known-wedged device. Missing timeout means optional probes are skipped.
probe() {
    if [ "$has_timeout" = 0 ]; then
        printf 'probe_skipped=timeout_unavailable\n'
        return 0
    fi
    if ! command -v "$1" >/dev/null 2>&1; then
        printf 'probe_unavailable=%s\n' "$1"
        return 0
    fi
    timeout -s KILL 3 "$@" 2>/dev/null
    probe_result=$?
    # The target may die between printf calls. Separate our marker even when
    # its last successful output did not include a newline.
    [ "$probe_result" = 0 ] || printf '\nprobe_failed=%s status=%s\n' "$1" "$probe_result"
    return 0
}

read_probe() {
    if [ -r "$1" ]; then
        # One bounded process; do not launch cat through sh or collect an
        # unbounded value in command substitution before truncating it.
        probe awk '
            { if (length($0)>4096 || NR>1024 || bytes+length($0)+1>16384) {
                print "read_truncated=16384_bytes_1024_lines_4096_line_bytes"; exit;
              }
              bytes+=length($0)+1; gsub(/\000/,","); print; }' "$1"
    else
        printf 'unavailable\n'
    fi
}

read_proc() {
    printf '\n[%s]\n' "$1"
    if [ -r "$proc_dir/$2" ]; then
        read_probe "$proc_dir/$2"
    else
        printf 'unavailable\n'
    fi
}

fe_counters() {
    printf '\n[fe_flow_counters]\n'
    if [ "$active_diagnostics" = 0 ]; then
        printf 'skipped=active_diagnostics_not_requested\n'
        return
    fi
    # fe/flows walks the table under the FE mutex. Bound the admission sample,
    # not just its printed lines: piping a full table into head is NOT bounded.
    # New flows can still arrive after this check; the command timeout is a
    # second guard, not proof of a bounded kernel transaction.
    flow_count=$(printf '%s\n' "$fe_state" | awk '
        { for (i=1;i<=NF;i++) if ($i ~ /^flows=[0-9]+$/) {
            sub(/^flows=/,"",$i); print $i; exit;
        } }')
    case "$flow_count" in
        ''|*[!0-9]*) printf 'skipped=flow_count_unknown\n'; return ;;
    esac
    if [ "${#flow_count}" -gt 2 ] || [ "$flow_count" -gt 64 ]; then
        printf 'skipped=more_than_64_flows flows=%s\n' "$flow_count"
        return
    fi
    flow_data=$(read_probe "$fe_debug/flows")
    if [ "$details" = 1 ]; then
        printf '%s\n' "$flow_data"
        return
    fi
    # Named columns, not positional IP parsing. Deliberately omit tuples,
    # MACs, PPPoE session IDs and GEM identifiers from the default output.
    printf '%s\n' "$flow_data" | awk '
        !header_seen {
            if (!NF) next;
            header_seen=1;
            if ($1 != "hash") {
                if ($0 == "unavailable" || $0 ~ /^probe_(skipped|unavailable|failed)=/) print;
                else print "unavailable=unsupported_flow_header";
                exit;
            }
            for(i=1;i<=NF;i++) column[$i]=i;
            n=split("hash input output age protocol counter bytes packets drop_bytes drop_packets", selected," ");
            for(i=1;i<=n;i++) if (!(selected[i] in column)) {
                print "unavailable=unsupported_flow_header"; exit;
            }
            for(i=1;i<=n;i++) printf "%s%s",i==1?"":" ",selected[i];
            printf "\n"; next;
        }
        NF==2 && $2 ~ /^error=-?[0-9]+$/ { print $1,$2; next; }
        {
            for(i=1;i<=n;i++) printf "%s%s",i==1?"":" ",$(column[selected[i]]);
            printf "\n";
        }'
}

flowtable() {
    printf '\n[flowtable]\n'
    # Do not print user comments or any other ruleset data. A different fw4
    # table/name is reported as unavailable rather than broadening the query.
    probe nft list flowtable inet fw4 ft | awk '
        /^[ \t]*(devices[ \t]*=|flags[ \t]+|hook[ \t]+ingress[ \t]+)/ {
            sub(/;.*/,";"); print; found=1;
        }
        /^probe_(skipped|unavailable|failed)=/ {print; found=1;}
        END {if(!found) print "unavailable=no_standard_fw4_flowtable_fields";}'
}

link_state() {
    printf '\n[wired_link_state]\n'
    # One timed process for all reads, maximum 32 netdev metadata records.
    # Names can change; use ifindex/dev_port evidence, not lanN spelling, to
    # relate an interface to a driver-provided physical-port record.
    # BusyBox timeout signals only its target PID: do not use sh+cat children
    # that could outlive a killed shell and keep its stdout pipe open.
    probe awk '
        function value(path, line, status) {
            status=(getline line < path); close(path);
            return status>0 && length(line)<=64 && line ~ /^[A-Za-z0-9_.+-]+$/ ? line : "unavailable";
        }
        BEGIN {
            n=split("iflink mtu operstate carrier speed duplex flags dev_port", fields," ");
            m=split("state hairpin_mode bpdu_guard root_block learning unicast_flood multicast_flood broadcast_flood isolated neigh_suppress", port_fields," ");
            k=split("vlan_filtering stp_state multicast_snooping ageing_time", bridge_fields," ");
            for(i=1;i<ARGC;i++) {
                device=ARGV[i]; index_value=value(device "/ifindex");
                if(index_value=="unavailable") continue;
                if(++count>32) {print "truncated=max_32_interfaces"; break;}
                name=device; sub(/^.*\//,"",name);
                printf "dev=%s ifindex=%s",name,index_value;
                for(j=1;j<=n;j++) printf " %s=%s",fields[j],value(device "/" fields[j]);
                printf " master_ifindex=%s",value(device "/master/ifindex");
                for(j=1;j<=m;j++) printf " brport_%s=%s",port_fields[j],value(device "/brport/" port_fields[j]);
                for(j=1;j<=k;j++) printf " bridge_%s=%s",bridge_fields[j],value(device "/master/bridge/" bridge_fields[j]);
                printf "\n";
            }
            if(!count) print "unavailable=no_interfaces";
            exit;
        }' "$sys_dir"/class/net/*
}

sample_clock() {
    printf '\n[%s]\n' "$1"
    printf 'uptime='
    read_probe "$proc_dir/uptime" | awk '
        NR==1 && $1 ~ /^[0-9]+([.][0-9]+)?$/ {value=$1}
        /(probe_(failed|skipped|unavailable)|read_truncated|truncated|skipped)=/ {failed=1}
        END {print value!="" && !failed ? value : "unavailable"}'
    printf 'boot_id='
    read_probe "$proc_dir/sys/kernel/random/boot_id" | awk '
        NR==1 && $0 ~ /^[0-9a-f-]+$/ && length($0)==36 {value=$0}
        /(probe_(failed|skipped|unavailable)|read_truncated|truncated|skipped)=/ {failed=1}
        END {print value!="" && !failed ? value : "unavailable"}'
}

observation_mode=passive
[ "$active_diagnostics" = 0 ] || observation_mode=active_diagnostics
printf 'schema=tyfza1-datapath-v3 mode=%s interval_seconds=%s details=%s active_diagnostics=%s\n' "$observation_mode" "$duration" "$details" "$active_diagnostics"
printf 'scope=two_non_atomic_snapshots_not_a_throughput_test\n'
printf 'counter_note=FE_MIBs_are_raw_cumulative_rows_not_all_flows;compare_each_direction_only_without_flow_or_counter_reuse\n'
printf 'netdev_note=Linux_host_path_counters_are_not_ASIC_LAN_MIBs;no_hardware_hit_ratio_is_inferred\n'
printf 'offload_note=enabled_installs_and_HW_OFFLOAD_do_not_prove_two_direction_hardware_hits\n'
printf 'l2_note=requested_is_not_active;LAN_LAN_known_unicast_and_routed_WAN_are_separate_test_paths\n'
printf 'privacy=default_omits_flow_addresses_MACs_sessions_PON_identity_and_WAN_credentials\n'
[ "$details" = 0 ] || printf 'warning=details_includes_flow_IP_MAC_ports_and_PPPoE_sessions;redact_before_sharing\n'
[ "$active_diagnostics" = 0 ] || printf 'warning=active_diagnostics_invoke_indirect_table_reads_and_unproven_status_counter_read_semantics;not_an_unperturbed_capture\n'
printf 'optional_probe_timeout_seconds=3 timeout_available=%s\n' "$has_timeout"
printf '\n[firmware]\n'
uname -r 2>/dev/null || printf 'kernel=unavailable\n'
if [ -r "$release_file" ]; then
    # Never source configuration files as shell code.
    read_probe "$release_file" | awk '/^DISTRIB_(ID|RELEASE|REVISION|TARGET|ARCH|DESCRIPTION)=/ {print}'
else
    printf 'release=unavailable\n'
fi
printf '\n[thoros_build_info]\n'
if [ -r "$build_info" ]; then
    read_probe "$build_info" | awk '
        /^schema=[0-9]+$/ || /^project_version=[A-Za-z0-9._+-]+$/ ||
        /^project_commit=([0-9a-f]+|unknown)$/ || /^project_dirty=(0|1|unknown)$/ ||
        /^sources_lock_sha256=[0-9a-f]+$/ { print; }'
else
    printf 'unavailable=firmware_does_not_record_ThorOS_source_identity\n'
fi
printf '\n[board_identity]\n'
for attribute in model compatible; do
    printf '%s=' "$attribute"
    read_probe "$sys_dir/firmware/devicetree/base/$attribute"
done
for attribute in family soc_id revision; do
    printf '%s=' "$attribute"
    read_probe "$sys_dir/devices/soc0/$attribute"
done

snapshot() {
    printf '\n[snapshot_%s]\n' "$1"
    date -u '+time=%Y-%m-%dT%H:%M:%SZ'
    sample_clock sample_begin
    read_proc uptime uptime
    printf 'ni_sysfs=%s\n' "${ni_dir:-not-found}"
    printf '\n[offload_configuration]\nsoftware='
    probe uci -q get 'firewall.@defaults[0].flow_offloading'
    printf 'hardware='
    probe uci -q get 'firewall.@defaults[0].flow_offloading_hw'
    flowtable
    link_state
    printf '\n[fe]\n'
    # Native-LAN-only boards need no PON device. New NI l2_state exposes the
    # complete FE/fabric state; older firmware keeps that state under PON/fe.
    # Never guess a NI/fe endpoint: it is not the old driver's FE ABI.
    if [ -n "$ni_dir" ] && [ -r "$ni_dir/l2_state" ]; then
        fe_state_file="$ni_dir/l2_state"
    else
        fe_state_file="$pon_dir/fe"
    fi
    printf 'state_source=%s\n' "$fe_state_file"
    fe_state=$(read_probe "$fe_state_file")
    printf '%s\n' "$fe_state"
    fe_counters
    for attribute in l2_switch l2_evidence lan_mib_evidence xram_state rx_bypass idle_poll_ms rx_prefetch pppoe_rx_checksum qm_voqs; do
        printf '\n[%s]\n' "$attribute"
        if [ -n "$ni_dir" ]; then
            read_probe "$ni_dir/$attribute"
        else
            printf 'unavailable\n'
        fi
    done
    for attribute in dma_state qm_state; do
        printf '\n[%s]\n' "$attribute"
        if [ "$active_diagnostics" = 1 ] && [ -n "$ni_dir" ]; then
            read_probe "$ni_dir/$attribute"
        else
            printf 'skipped=active_diagnostics_not_requested\n'
        fi
    done
    read_proc cpu stat
    read_proc softirqs softirqs
    read_proc interrupts interrupts
    read_proc softnet net/softnet_stat
    read_proc netdev_counters net/dev
    read_proc conntrack_count sys/net/netfilter/nf_conntrack_count
    read_proc conntrack_max sys/net/netfilter/nf_conntrack_max
    printf '\n[memory]\n'
    if [ -r "$proc_dir/meminfo" ]; then
        read_probe "$proc_dir/meminfo" | awk '/^(MemTotal|MemFree|MemAvailable|Buffers|Cached|Slab|SReclaimable|SUnreclaim):/ {print}'
    else
        printf 'unavailable\n'
    fi
    sample_clock sample_end
}

snapshot before
sleep "$duration" || exit 1
snapshot after
