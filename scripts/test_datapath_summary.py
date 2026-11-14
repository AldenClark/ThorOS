#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Exercise the real offline parser; no router, SDK, or external dependencies."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile


root = Path(__file__).resolve().parents[1]
program = root / 'scripts/summarize_tyfza1_datapath.py'
spec = importlib.util.spec_from_file_location('summary', program)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
boot = '11111111-2222-3333-4444-555555555555'
other_boot = '11111111-2222-3333-4444-666666666666'
state = 'base_ready=1 dma_exposed=1 engine_poisoned=0 host_active=1 reboot_required=0'
topology = ('dev=lan1 ifindex=3 iflink=3 mtu=1500 operstate=up carrier=1 speed=1000 '
            'duplex=full flags=0x1003 dev_port=0 master_ifindex=7 brport_state=3 bridge_vlan_filtering=0')


def capture(*, after_boot=boot, times=('10.00', '11.00', '21.00', '22.00'),
            q_before='9007199254740993', q_after='9007199254741193',
            ni_after=state, link_after=topology, after=True, missing='', extra='', mib=None):
    result = 'schema=tyfza1-datapath-v3 mode=passive interval_seconds=10 details=0 active_diagnostics=0\n'
    for index, which in enumerate(('before', 'after') if after else ('before',)):
        identity = boot if index == 0 else after_boot
        result += f'''[snapshot_{which}]
[sample_begin]
uptime={times[index * 2]}
boot_id={identity}
[wired_link_state]
{topology if index == 0 else link_after}
[fe]
l2_requested=1 l2_active=1 l2_bum_hardware=0 l2_vlan_hardware=0 lan_admission_valid=1 lan_native_l2_mask=3
PRIVATE_TUPLE=192.0.2.1:1234
[xram_state]
{state if index == 0 else ni_after}
[qm_voqs]
cpu_bytes={q_before if index == 0 else q_after} cpu_packets={20 + index} ring_errors=0 buffer_errors=0 budget_hits={index}
[lan_mib_evidence]
{mib[index] if mib else 'unavailable'}

[netdev_counters]
lan1: {1000 + index * 300} 10 0 0 0 0 0 0 {2000 + index * 600} 20 0 0 0 0 0 0
[fe_flow_counters]
42 private 192.0.2.1:1234 198.51.100.1:443
[sample_end]
uptime={times[index * 2 + 1]}
boot_id={identity}
'''
    if missing:
        # Preserve the section so parser has to reject absent content rather
        # than relying on a schema/version rejection.
        import re
        result = re.sub(rf'\[{missing}\]\n[^\[]*', f'[{missing}]\nunavailable\n', result)
    return result + extra


result = module.summarize(capture())
assert result['clock_window']['valid']
assert result['clock_window']['min_seconds'] == 9.99
assert result['clock_window']['max_seconds'] == 12.01
assert result['qm_cpu']['cpu_bytes']['delta'] == 200  # >2**53 exact cumulative subtraction
assert result['qm_cpu']['cpu_bytes']['per_second_min'] == 200 / 12.01
assert result['qm_cpu']['cpu_bytes']['per_second_max'] == 200 / 9.99
assert result['netdev_host']['lan1']['rx_bytes']['delta'] == 300
assert result['netdev_host']['lan1']['tx_bytes']['delta'] == 600
assert result['hardware_forwarding_proven'] is False
assert result['states']['after']['fe']['l2_active'] == '1'
serialized = json.dumps(result)
assert '192.0.2.1' not in serialized and '198.51.100.1' not in serialized and 'PRIVATE' not in serialized

for reason, text in (
    ('boot_changed', capture(after_boot=other_boot)),
    ('overlapping_or_non_monotonic_samples', capture(times=('10', '12', '11', '13'))),
    ('overlapping_or_non_monotonic_samples', capture(times=('10', '11', '11', '12'))),
    ('clock_resolution_insufficient_for_rate_bounds', capture(times=('10', '11', '11.01', '12'))),
    ('overlapping_or_non_monotonic_samples', capture(times=('10', '11', '5', '6'))),
    ('monotonic_clock_missing_or_invalid', capture(times=('nan', '11', '21', '22'))),
    ('sample_clock_probe_incomplete', capture(missing='sample_begin')),
    ('boot_identity_missing_or_invalid', capture(after=False)),
):
    result = module.summarize(text)
    assert result['clock_window'] == {'valid': False, 'reason': reason}, result
    assert result['qm_cpu']['valid'] is False and result['netdev_host']['valid'] is False

for value in ('1', '9007199254740992'):
    result = module.summarize(capture(q_after=value))
    assert result['qm_cpu']['cpu_bytes']['reason'] == 'counter_decreased_reset_or_wrap_not_guessed'
for value in ('-1', 'unavailable', '18446744073709551616', 'NaN', '1e20', '0x12'):
    result = module.summarize(capture(q_after=value))
    assert result['qm_cpu']['cpu_bytes']['reason'] == 'counter_missing_or_invalid'
result = module.summarize(capture(q_after='9007199254740993'))
assert result['qm_cpu']['cpu_bytes']['delta'] == 0
assert module.summarize(capture(q_before='18446744073709551614', q_after='18446744073709551615'))['qm_cpu']['cpu_bytes']['delta'] == 1
assert module.summarize(capture(q_before='4294967295', q_after='10'))['qm_cpu']['cpu_bytes']['valid'] is False

for before, after in (('engine_poisoned=0', 'engine_poisoned=1'), ('host_active=1', 'host_active=0'),
                      ('base_ready=1', 'base_ready=0'), ('reboot_required=0', 'reboot_required=1')):
    result = module.summarize(capture(ni_after=state.replace(before, after)))
    assert result['qm_cpu']['reason'] == 'NI_lifecycle_not_stable_ready_at_endpoints'
assert module.summarize(capture(missing='xram_state'))['qm_cpu']['valid'] is False
assert module.summarize(capture(missing='qm_voqs'))['qm_cpu']['reason'] == 'QM_sample_incomplete'
for marker in ('probe_failed=awk status=137', 'read_truncated=16384_bytes'):
    result = module.summarize(capture(ni_after=state + '\n' + marker))
    assert result['qm_cpu']['valid'] is False
    text = capture().replace(f'boot_id={boot}', f'boot_id={boot}\n{marker}')
    result = module.summarize(text)
    assert result['clock_window']['reason'] == 'sample_clock_probe_incomplete'
for marker in ('probe_failed=awk status=137', 'read_truncated=16384_bytes', 'truncated=max_32_interfaces'):
    for separator in (' ', ''):
        suffix = ' diagnostic=0' + separator + marker
        result = module.summarize(capture(ni_after=state + suffix))
        assert result['qm_cpu']['valid'] is False
        result = module.summarize(capture().replace(f'boot_id={boot}', f'boot_id={boot}\nnote=0{separator}{marker}'))
        assert result['clock_window']['reason'] == 'sample_clock_probe_incomplete'
        result = module.summarize(capture().replace(topology, topology + suffix))
        assert result['netdev_host'] == {'valid': False, 'reason': 'link_samples_missing_or_incomplete'}
# Missing optional attributes are legitimate on an unbridged interface.
result = module.summarize(capture().replace('master_ifindex=7', 'master_ifindex=unavailable'))
assert result['netdev_host']['lan1']['rx_bytes']['valid'] is True

for before, after in (('ifindex=3', 'ifindex=4'), ('master_ifindex=7', 'master_ifindex=8'),
                      ('brport_state=3', 'brport_state=4'), ('speed=1000', 'speed=100'),
                      ('bridge_vlan_filtering=0', 'bridge_vlan_filtering=1')):
    result = module.summarize(capture(link_after=topology.replace(before, after)))
    assert result['netdev_host']['lan1']['reason'] == 'interface_identity_link_or_topology_changed'
assert module.summarize(capture(missing='netdev_counters'))['netdev_host']['lan1']['valid'] is False
assert module.summarize(capture(link_after=topology + '\nprobe_failed=awk status=137'))['netdev_host']['lan1']['valid'] is False
assert module.summarize(capture(link_after=topology + '\ntruncated=max_16_interfaces'))['netdev_host']['lan1']['valid'] is False


def mib_row(index):
    captured = 10_500_000_000 if index == 0 else 21_500_000_000
    begin = 9_000_000_000 if index == 0 else 20_000_000_000
    return (f'schema=1 cached=1 clock=boottime raw=1 reset_tracking=0 l2_attribution=0 '
            f'atomic_hardware_snapshot=0 read_opcode=0 counter_mode_verified=0 capture_ns={captured} registered_mask=0x1\n'
            f'port=0 ifindex=3 registered=1 valid=1 error=0 seq={9 + index} attempts={9 + index} '
            f'begin_ns={begin} end_ns={begin + 1000000} '
            f'attempt_begin_ns={begin} attempt_end_ns={begin + 1000000} config_begin=0 config_end=0 '
            f'rx_bytes={1000 + index * 200} tx_bytes={2000 + index * 300} '
            f'rx_uc=10 rx_mc=0 rx_bc=0 tx_uc=10 tx_mc=0 tx_bc=0\n' +
            '\n'.join(f'port={port} ifindex=0 registered=0 valid=0 error=-61 seq=0 attempts=0' for port in range(1, 5)))


mib = (mib_row(0), mib_row(1))
result = module.summarize(capture(mib=mib))
assert result['physical_mac_cached']['0']['raw_observations_valid'] is True
assert result['physical_mac_cached']['0']['valid'] is False
assert result['physical_mac_cached']['0']['rates_available'] is False
assert result['physical_mac_cached']['0']['reason'] == 'counter_continuity_unverified'
assert result['physical_mac_cached']['0']['before']['rx_bytes'] == '1000'
assert result['physical_mac_cached']['0']['after']['rx_bytes'] == '1200'
assert 'per_second' not in json.dumps(result['physical_mac_cached'])
assert result['physical_mac_cached']['0']['sample_window']['min_seconds'] == 10.999
assert result['hardware_forwarding_proven'] is False
assert module.summarize(capture())['physical_mac_cached']['valid'] is False
for before, after, reason in (
    ('seq=10', 'seq=9', 'MIB_sample_not_advanced_or_sequence_reset'),
    ('error=0', 'error=-110', 'last_MIB_read_failed_old_cache_not_reused'),
    ('valid=1', 'valid=0', 'port_not_registered_or_sample_not_valid'),
    ('config_end=0', 'config_end=1', 'MIB_configuration_changed'),
    ('ifindex=3', 'ifindex=4', 'physical_port_interface_identity_missing_or_changed'),
    ('config_end=0', 'config_end=unknown', 'MIB_configuration_missing_or_invalid'),
    ('attempts=10', 'attempts=9', 'MIB_attempt_sequence_inconsistent'),
    ('attempts=10', 'attempts=unknown', 'MIB_attempt_sequence_inconsistent'),
    ('attempt_begin_ns=20000000000', 'attempt_begin_ns=20000000001', 'MIB_successful_attempt_clock_mismatch'),
    ('attempt_end_ns=20001000000', 'attempt_end_ns=20001000001', 'MIB_successful_attempt_clock_mismatch'),
    ('attempt_end_ns=20001000000', 'attempt_end_ns=unknown', 'MIB_successful_attempt_clock_mismatch'),
):
    result = module.summarize(capture(mib=(mib[0], mib[1].replace(before, after))))
    assert result['physical_mac_cached']['0']['reason'] == reason, result
stale = mib[1].replace('20000000000', '17000000000').replace('20001000000', '17001000000')
assert module.summarize(capture(mib=(mib[0], stale)))['physical_mac_cached']['0']['reason'] == 'cached_MIB_older_than_3_seconds'
attempts_reset = (mib[0].replace('attempts=9', 'attempts=100'), mib[1].replace('attempts=10', 'attempts=100'))
assert module.summarize(capture(mib=attempts_reset))['physical_mac_cached']['0']['reason'] == 'MIB_attempt_sequence_inconsistent'
result = module.summarize(capture(mib=(mib[0], mib[1].replace('rx_bytes=1200', 'rx_bytes=5'))))
assert result['physical_mac_cached']['0']['reason'] == 'counter_continuity_unverified'
assert result['physical_mac_cached']['0']['after']['rx_bytes'] == '5'
assert 'delta' not in json.dumps(result['physical_mac_cached'])
result = module.summarize(capture(mib=(mib[0], mib[1].replace('registered=1', 'registered=0').replace('registered_mask=0x1', 'registered_mask=0'))))
assert result['physical_mac_cached']['0']['reason'] == 'port_not_registered_or_sample_not_valid'
for marker in ('probe_failed=awk status=137', 'read_truncated=16384_bytes'):
    result = module.summarize(capture(ni_after=state + '\n' + marker, mib=mib))
    assert result['physical_mac_cached']['valid'] is False
for before, after in (('master_ifindex=7', 'master_ifindex=8'), ('brport_state=3', 'brport_state=4'),
                      ('bridge_vlan_filtering=0', 'bridge_vlan_filtering=1')):
    result = module.summarize(capture(mib=mib, link_after=topology.replace(before, after)))
    assert result['physical_mac_cached']['0']['reason'] == 'physical_port_link_or_bridge_policy_changed'
result = module.summarize(capture(mib=mib, link_after=topology.replace('dev_port=0', 'dev_port=1')))
assert result['physical_mac_cached']['0']['reason'] == 'physical_port_dev_port_mapping_mismatch'
result = module.summarize(capture(mib=mib, missing='wired_link_state'))
assert result['physical_mac_cached']['0']['reason'] == 'physical_port_link_mapping_missing_or_ambiguous'
for before, after, reason in (
    ('capture_ns=21500000000', 'capture_ns=10500000000', 'MIB_capture_outside_snapshot_clock_window'),
    ('read_opcode=0', 'read_opcode=1', 'unsupported_cached_MIB_schema'),
    ('clock=boottime', 'clock=monotonic', 'unsupported_cached_MIB_schema'),
    ('schema=1', 'schema=2', 'unsupported_cached_MIB_schema'),
    ('counter_mode_verified=0', 'counter_mode_verified=1', 'unsupported_cached_MIB_schema'),
    ('registered_mask=0x1', 'registered_mask=0x3', 'registered_port_mask_mismatch'),
    ('registered_mask=0x1', 'registered_mask=0xff', 'invalid_registered_port_mask'),
):
    result = module.summarize(capture(mib=(mib[0], mib[1].replace(before, after))))
    assert result['physical_mac_cached']['reason'] == reason, result
result = module.summarize(capture(mib=(mib[0], mib[1] + '\n' + mib[1].splitlines()[1])))
assert result['physical_mac_cached']['reason'] == 'invalid_or_duplicate_physical_port'
result = module.summarize(capture(mib=(mib[0], '\n'.join(mib[1].splitlines()[:2]))))
assert result['physical_mac_cached']['reason'] == 'physical_port_samples_missing'

for invalid in ('schema=tyfza1-datapath-v2\n', 'not a capture',
                capture(extra='[qm_voqs]\ncpu_bytes=0\n'),
                capture(extra='[snapshot_after]\n'),
                'schema=tyfza1-datapath-v3 ' + 'x' * module.MAX_BYTES):
    try:
        module.summarize(invalid)
    except ValueError:
        pass
    else:
        raise AssertionError('invalid capture accepted')

# The CLI uses the same bounded parser and emits only a sanitized summary.
with tempfile.TemporaryDirectory(prefix='datapath-summary-') as temporary:
    path = Path(temporary) / 'capture.txt'
    path.write_text(capture())
    run = subprocess.run([sys.executable, str(program), str(path)], text=True,
                         capture_output=True, timeout=5, check=True)
    assert json.loads(run.stdout)['qm_cpu']['cpu_bytes']['delta'] == 200
    assert '192.0.2.1' not in run.stdout and 'PRIVATE' not in run.stdout
    for payload in (b'\xff', b'x' * (module.MAX_BYTES + 1)):
        path.write_bytes(payload)
        run = subprocess.run([sys.executable, str(program), str(path)], text=True,
                             capture_output=True, timeout=5)
        assert run.returncode == 2 and 'Invalid capture:' in run.stderr and not run.stdout

print('Datapath summary: exact host/QM deltas, quantized clock bounds, cached MAC raw-only evidence, '
      'mode/boot/reset/wrap/link/policy/lifecycle/partial refusal, privacy, bounded parser and CLI passed')
