#!/usr/bin/env python3
"""Run the production read-only collector with isolated sysfs/procfs fixtures.

This tests discovery, privacy, missing optional tools, timeout/error handling and
bounded FE admission. It is not a hardware throughput or MMIO safety test.
"""
from pathlib import Path
import os
import shutil
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
collector = root / 'scripts/observe_tyfza1_datapath.sh'
compatibility = root / 'scripts/observe_wired_offload.sh'


def write(path, text, executable=False):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    if executable:
        path.chmod(0o755)


with tempfile.TemporaryDirectory(prefix='datapath-observer-') as temporary:
    base = Path(temporary)
    sysfs = base / 'sys'
    procfs = base / 'proc'
    ni = sysfs / 'bus/platform/devices/4f4300000.ethernet'
    pon = sysfs / 'bus/platform/devices/4f5500000.pon'
    debug = sysfs / 'kernel/debug/rtl9617c-fe'
    commands = base / 'bin'
    calls = base / 'calls'
    release = base / 'openwrt_release'
    build_info = base / 'thoros-build-info'
    state = ('available=1 enabled=1 flows=3 installs=9 counted_flows=1 activity_flows=2\n'
             'admission_requests=12 parse_rejected=3 install_failed=1 reject_pon=3\n'
             'install_unavailable=0 install_collision=1 install_no_space=0 install_io=0\n')
    flow_header = ('hash input output pol_id dpid ingress_sid egress_sid age protocol '
                   'source destination counter bytes packets drop_bytes drop_packets egress_word\n')
    flow_body = ('42 lan1 pon0 8 33 0 999 2 6 192.0.2.12:51000 198.51.100.7:443 1 1000 10 0 0 00\n'
                 '43 pon0 lan1 8 0 999 0 2 6 198.51.100.7:443 192.0.2.12:51000 - - - - - 00\n'
                 '44 error=-110\n')
    write(pon / 'fe', state)
    write(pon / 'identity', 'PRIVATE_PON_IDENTITY\n')
    write(ni / 'fe', 'WRONG_NI_FE_PATH\n')
    for name, value in {
        'dma_state': 'busy=4 invalid=0 completion_checks=22\n',
        'qm_voqs': 'voq7=20 budget_hits=4 cpu_packets=20 cpu_bytes=12345 ring_errors=0\n',
        'qm_state': 'no_buffer=0 fe_drop=0 l3te_tail_drop=0\n',
        'idle_poll_ms': '4\n',
        'rx_prefetch': '1\n',
        'pppoe_rx_checksum': '0\n',
    }.items():
        write(ni / name, value)
    write(debug / 'flows', flow_header + flow_body)
    for name, value in {'ifindex': '3', 'iflink': '3', 'mtu': '1500',
                        'operstate': 'up', 'carrier': '1', 'speed': '1000', 'duplex': 'full',
                        'address': 'PRIVATE_MAC'}.items():
        write(sysfs / 'class/net/lan1' / name, value + '\n')
    for name, value in {
        'uptime': '5.00 3.00\n',
        'stat': 'cpu 1 2 3 4 5 6 7 8\ncpu0 1 2 3 4 5 6 7 8\n',
        'softirqs': 'NET_RX: 10 20 30 40\n',
        'interrupts': '1: 10 20 30 40 NI-QM\n',
        'net/softnet_stat': '00000010 00000000 00000002\n',
        'net/dev': 'lan1: 123 1 0 0 0 0 0 0 321 3 0 0 0 0 0 0\n',
        'sys/net/netfilter/nf_conntrack_count': '3\n',
        'sys/net/netfilter/nf_conntrack_max': '16384\n',
        'meminfo': 'MemTotal: 1024 kB\nMemAvailable: 512 kB\nSlab: 12 kB\n',
    }.items():
        write(procfs / name, value)
    write(release, "DISTRIB_ID='OpenWrt'\nDISTRIB_REVISION='r-test'\nSECRET='PRIVATE_RELEASE_FIELD'\n"
                   "$(touch /not-a-script)\n")
    write(build_info, 'schema=1\nproject_version=0.8.5-beta\nproject_commit=' + 'a' * 40 + '\n'
                     'project_dirty=0\nsources_lock_sha256=' + 'b' * 64 + '\n'
                     'private_field=PRIVATE_BUILD_INFO\nproject_commit=$(PRIVATE_COMMAND)\n')

    # log every optional command and verify the probe contract. No real netlink,
    # router settings, debugfs or sleep is used by the normal fixture cases.
    write(commands / 'timeout', '''#!/bin/sh
printf 'timeout %s\n' "$*" >> "$OBSERVER_CALLS"
[ "$1" = -s ] && [ "$2" = KILL ] && [ "$3" = 3 ] || exit 98
if [ -n "${OBSERVER_REAL_TIMEOUT:-}" ]; then exec "$OBSERVER_REAL_TIMEOUT" "$@"; fi
shift 3
case "$*" in
  *"${OBSERVER_FAIL_MATCH:-MATCH_NOT_PRESENT}"*) exit 124 ;;
esac
exec "$@"
''', True)
    write(commands / 'uci', '''#!/bin/sh
printf 'uci %s\n' "$*" >> "$OBSERVER_CALLS"
case "$*" in
  '-q get firewall.@defaults[0].flow_offloading') echo 1 ;;
  '-q get firewall.@defaults[0].flow_offloading_hw') echo 1 ;;
  *) exit 99 ;;
esac
''', True)
    write(commands / 'nft', '''#!/bin/sh
printf 'nft %s\n' "$*" >> "$OBSERVER_CALLS"
[ "$*" = 'list flowtable inet fw4 ft' ] || exit 99
if [ "${OBSERVER_HANG_NFT:-0}" = 1 ]; then exec /bin/sleep 30; fi
printf 'table inet fw4 {\n flowtable ft {\n  devices = { lan1, pon0 };\n  flags offload; comment "PRIVATE_INLINE_COMMENT"\n  comment "PRIVATE_TABLE_COMMENT";\n }\n}\n'
''', True)
    write(commands / 'sleep', '''#!/bin/sh
printf 'sleep %s\n' "$*" >> "$OBSERVER_CALLS"
exit 0
''', True)
    for forbidden in ('ubus', 'ip', 'conntrack', 'mount', 'ethtool', 'devmem'):
        write(commands / forbidden, f'#!/bin/sh\necho "FORBIDDEN {forbidden}" >> "$OBSERVER_CALLS"\nexit 99\n', True)

    environment = dict(os.environ, PATH=f'{commands}:/usr/bin:/bin',
                       TYFZA1_SYSFS=str(sysfs), TYFZA1_PROCFS=str(procfs),
                       TYFZA1_RELEASE_FILE=str(release), TYFZA1_BUILD_INFO=str(build_info),
                       OBSERVER_CALLS=str(calls))
    for variable in ('TYFZA1_NI_SYSFS', 'TYFZA1_PON_SYSFS', 'TYFZA1_FE_DEBUGFS'):
        environment.pop(variable, None)

    def run(*arguments, script=collector, env=None, expected=0):
        calls.write_text('')
        result = subprocess.run(['/bin/sh', str(script), *arguments], env=env or environment,
                                text=True, capture_output=True, timeout=15)
        assert result.returncode == expected, (result.returncode, result.stdout, result.stderr)
        trace = calls.read_text()
        assert 'FORBIDDEN' not in trace, trace
        assert 'PRIVATE_' not in result.stdout and 'WRONG_NI_FE_PATH' not in result.stdout
        return result.stdout, trace, result.stderr

    original_files = {path: path.read_bytes() for directory in (sysfs, procfs)
                      for path in directory.rglob('*') if path.is_file()}
    output, trace, _ = run('1')
    assert '[snapshot_before]' in output and '[snapshot_after]' in output
    assert output.count('admission_requests=12 parse_rejected=3') == 2
    assert output.count('install_unavailable=0 install_collision=1') == 2
    assert 'ni_sysfs=' + str(ni) in output
    assert 'cpu_bytes=12345' in output and '[softnet]' in output
    assert 'devices = { lan1, pon0 };' in output and 'DISTRIB_REVISION' in output
    assert 'project_commit=' + 'a' * 40 in output and 'sources_lock_sha256=' + 'b' * 64 in output
    assert 'speed=1000 duplex=full' in output
    assert output.count('[flowtable]') == 2
    assert '198.51.100.7' not in output and '192.0.2.12' not in output and ':51000' not in output
    assert '42 lan1 pon0 2 6 1 1000 10 0 0' in output
    assert '43 pon0 lan1 2 6 - - - - -' in output and '44 error=-110' in output
    assert trace.count('sleep 1\n') == 1
    assert 'timeout -s KILL 3 sh ' not in trace
    assert all(path.read_bytes() == value for path, value in original_files.items())

    output, _, _ = run('1', '--details')
    assert '192.0.2.12:51000' in output and 'warning=details_includes_' in output
    assert 'PON_IDENTITY' not in output

    # Missing optional debugfs must not abort the after snapshot or CPU probes.
    (debug / 'flows').unlink()
    output, _, _ = run('1')
    assert '[snapshot_after]' in output and output.count('[cpu]') == 2
    assert output.count('[fe_flow_counters]\nunavailable') == 2
    write(debug / 'flows', flow_header + flow_body)

    # Do not invoke the kernel full-table walk on large or unknown flow counts.
    for value, reason in ((65, 'more_than_64_flows'), (65536, 'more_than_64_flows')):
        write(pon / 'fe', f'available=1 enabled=1 flows={value}\n')
        output, trace, _ = run('1', '--details')
        assert f'skipped={reason}' in output and str(debug / 'flows') not in trace
    write(pon / 'fe', 'available=0\n')
    output, trace, _ = run('1')
    assert 'skipped=flow_count_unknown' in output and str(debug / 'flows') not in trace
    write(pon / 'fe', state)

    # Probe failures are explicit and do not turn a partial capture into silence.
    failed_environment = dict(environment, OBSERVER_FAIL_MATCH='qm_state')
    output, _, _ = run('1', env=failed_environment)
    assert output.count('probe_failed=cat status=124') == 2 and '[snapshot_after]' in output

    # Check a real userspace hang, not just a mock timeout return code. There
    # are two three-second NFT probes; the 15-second subprocess deadline is
    # an independent safeguard against accidentally dropping the timeout.
    timeout_binary = shutil.which('timeout')
    assert timeout_binary, 'host timeout is required to test bounded probes'
    output, trace, _ = run('1', env=dict(environment, OBSERVER_REAL_TIMEOUT=timeout_binary,
                                       OBSERVER_HANG_NFT='1'))
    assert output.count('probe_failed=nft status=137') == 2
    assert '[snapshot_after]' in output

    # Limit hardware-link probes even with many PON logical interfaces.
    for number in range(17):
        write(sysfs / f'class/net/pon{number}/ifindex', f'{number + 10}\n')
    output, _, _ = run('1')
    assert output.count('truncated=max_16_interfaces') == 2
    assert output.count('dev=') == 32
    for number in range(17):
        directory = sysfs / f'class/net/pon{number}'
        (directory / 'ifindex').unlink()
        directory.rmdir()

    write(debug / 'flows', 'unsupported private_column_header 198.51.100.7\n198.51.100.7\n')
    output, _, _ = run('1')
    assert '198.51.100.7' not in output
    write(debug / 'flows', flow_header + flow_body)

    # No timeout applet: never silently fall back to unbounded sysfs/netlink I/O.
    limited_commands = base / 'limited-bin'
    limited_commands.mkdir()
    for command in ('sh', 'cat', 'awk', 'uname', 'date', 'dirname'):
        target = shutil.which(command)
        assert target, command
        (limited_commands / command).symlink_to(target)
    (limited_commands / 'sleep').symlink_to(commands / 'sleep')
    output, trace, _ = run('1', env=dict(environment, PATH=str(limited_commands)))
    assert 'timeout_available=0' in output and 'probe_skipped=timeout_unavailable' in output
    assert '[snapshot_after]' in output and 'timeout ' not in trace

    # Isolated, renamed NI and PON directories must work via documented overrides.
    overridden = dict(environment, TYFZA1_NI_SYSFS=str(ni), TYFZA1_PON_SYSFS=str(pon),
                      TYFZA1_FE_DEBUGFS=str(debug))
    output, _, _ = run('1', env=overridden)
    assert output.count('admission_requests=12 parse_rejected=3') == 2

    output, trace, _ = run(script=compatibility)
    assert 'interval_seconds=10' in output and 'sleep 10\n' in trace
    output, trace, _ = run('--details', script=compatibility)
    assert 'interval_seconds=10' in output and '192.0.2.12:51000' in output
    output, _, _ = run('1', script=compatibility)
    assert 'interval_seconds=1' in output
    lone_wrapper = base / 'observe_wired_offload.sh'
    lone_wrapper.write_bytes(compatibility.read_bytes())
    _, _, error = run(script=lone_wrapper, expected=1)
    assert 'standalone collector' in error

    for invalid in (('0',), ('3601',), ('-1',), ('1.5',), ('',), ('1', '2'),
                    ('--invalid',), ('999999999999999999999999999999999',)):
        output, trace, _ = run(*invalid, expected=2)
        assert not trace and not output
    output, trace, _ = run('--help')
    assert 'Usage:' in output and not trace

print('Datapath observer: PON/NI separation, private-by-default counters, missing debugfs/tools, '
      'bounded flow-table admission, explicit failures, two snapshots and legacy wrapper passed')
