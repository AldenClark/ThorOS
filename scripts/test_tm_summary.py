#!/usr/bin/env python3
"""Exercise production offline TM/TE summaries; no hardware or fake Mbps."""
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('summary', ROOT / 'scripts/summarize_tyfza1_datapath.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
BOOT = '11111111-2222-3333-4444-555555555555'


def evidence(which, clear=0):
    clock = (10 if not which else 20) * 1_000_000_000
    config = {key: 0 for key in module.TM_CONFIGS}
    config['tm_clear_control'] = clear << 31
    return (f'schema=1 cached=1 clock=boottime global=1 atomic_hardware_snapshot=0 '
            f'hardware_reset_verified=0 te_direct_mode_verified=0 capture_ns={clock + 50} '
            f'seq={1 + which} epoch=1 owner_generation=1 current_owner_generation=1 valid=1 '
            f'delta_valid={which} epoch_reason={0 if which else 1} begin_ns={clock} end_ns={clock + 10}\n'
            f'contract=partial tm_te_baseline_verified=0 wan_arb_readback=0 sw_lan_nodrop=1 '
            f'hw_nodrop_policy=ingress_inherited bm_clear_on_read={clear} te_mem_clear_on_read=1 l3lan_rxpfc=0\n' +
            ' '.join(f'{key}={value}' for key, value in config.items()) + '\n' +
            ' '.join(f'{key}=0' for key in module.TM_STATUSES) + '\n' +
            ''.join(f'counter={name} raw={100 + which} observed={which * 7} mode={"read_clear" if clear else "cumulative"}\n'
                    for name in module.TM_BM_COUNTERS) +
            ''.join(f'counter={name} raw={1000 - which} mode=unknown\n' for name in module.TM_TE_COUNTERS))


def capture(before=None, after=None, active=True, trigger=None):
    output = ('schema=tyfza1-datapath-v3 mode=' + ('active_diagnostics' if active else 'passive') +
              ' interval_seconds=10 details=0 active_diagnostics=1\n')
    for i, which in enumerate(('before', 'after')):
        t = 10 if not i else 20
        output += (f'[snapshot_{which}]\n[sample_begin]\nuptime={t}.00\nboot_id={BOOT}\n'
                   f'[xram_state]\nbase_ready=1 dma_exposed=1 engine_poisoned=0 host_active=1 reboot_required=0\n'
                   f'[fabric_sample]\n')
        output += (trigger if trigger is not None else f'schema=1 sampled=1 seq={i + 1} epoch=1 valid=1\n')
        output += '[fabric_evidence]\n' + ((before if not i else after) or evidence(i))
        output += f'[sample_end]\nuptime={t}.01\nboot_id={BOOT}\n'
    return output


def result(*args, **kwargs):
    return module.summarize(capture(*args, **kwargs))['fabric_cached']


for clear in (0, 1):
    r = result(evidence(0, clear), evidence(1, clear))
    assert r['valid'] and r['raw_observations_valid'] and not r['rates_available']
    assert r['bm_observed_increments'] == dict.fromkeys(module.TM_BM_COUNTERS, 7)
    assert not r['hardware_drop_attribution'] and not r['hardware_reset_verified']
    assert r['after']['counters']['te_tail_drop'] == {'raw': 999, 'mode': 'unknown'}
    assert not any(word in json.dumps(r) for word in ('per_second', 'Mbps', 'hit_ratio'))

for old, new, reason in (
    ('valid=1 delta_valid', 'valid=0 delta_valid', 'unsupported_or_invalid_fabric_cache'),
    ('owner_generation=1 current_owner_generation=1', 'owner_generation=1 current_owner_generation=2', 'fabric_owner_changed_after_sample'),
    ('delta_valid=1', 'delta_valid=0', 'fabric_interval_unusable'),
    ('epoch_reason=0', 'epoch_reason=3', 'fabric_interval_unusable'),
    ('seq=2', 'seq=1', 'active_fabric_capture_ack_missing_or_mismatched'),
    ('bm_clear_on_read=0', 'bm_clear_on_read=1', 'fabric_counter_mode_mismatch'),
    ('counter=te_tail_drop raw=999 mode=unknown', 'counter=te_tail_drop raw=999 mode=cumulative', 'fabric_counter_value_or_mode_invalid'),
    ('counter=te_tail_drop raw=999 mode=unknown', 'counter=te_tail_drop raw=999 mode=unknown observed=10', 'unverified_TE_counter_must_not_have_total'),
    ('observed=7', 'observed=-1', 'fabric_observed_counter_missing'),
    ('counter=bm_rx raw=101', 'counter=bm_rx raw=4294967296', 'fabric_counter_value_or_mode_invalid'),
    ('es_lan4=0', 'es_lan4=unknown', 'fabric_register_snapshot_missing_or_invalid'),
    ('te_control=0', 'te_control=1', 'fabric_configuration_changed'),
    ('begin_ns=20000000000', 'begin_ns=10000000000', 'cached_fabric_older_than_3_seconds'),
    ('begin_ns=20000000000', 'begin_ns=20000000011', 'fabric_sample_clock_invalid'),
):
    r = result(after=evidence(1).replace(old, new))
    assert not r['valid'] and r['reason'] == reason, (old, r)
    assert 'bm_observed_increments' not in r

changed = evidence(1).replace('epoch=1', 'epoch=2')
r = result(after=changed, active=False)
assert not r['valid'] and r['reason'] == 'fabric_observed_epoch_changed'
r = result(after=evidence(1).replace('owner_generation=1', 'owner_generation=2'), active=False)
assert not r['valid'] and r['reason'] == 'fabric_owner_epoch_changed'
r = result(before=evidence(0).replace('observed=0', 'observed=100'))
assert not r['valid'] and r['reason'] == 'fabric_observed_counter_decreased'
r = result(after=evidence(1).replace('seq=2', 'seq=1'), active=False)
assert not r['valid'] and r['reason'] == 'fabric_sample_not_advanced_or_overlapping'
for extra, reason in (('probe_failed=awk status=137\n', 'fabric_cache_missing_or_incomplete'),
                      ('counter=bm_rx raw=101 observed=7 mode=cumulative\n', 'fabric_counter_duplicate_or_unknown')):
    r = result(after=evidence(1) + extra)
    assert not r['valid'] and r['reason'] == reason
for trigger in ('', 'schema=1 sampled=1 seq=0 epoch=1 valid=1\n', 'probe_failed=awk status=137\n'):
    r = result(trigger=trigger)
    assert not r['valid']
r = result(active=False, trigger='skipped=active_diagnostics_not_requested\n')
assert r['valid']  # a fresh sample produced by the same owner may be read passively
r = module.summarize(capture().replace('host_active=1', 'host_active=0'))['fabric_cached']
assert not r['valid'] and r['reason'] == 'NI_lifecycle_not_stable_ready_at_endpoints'
r = module.summarize(capture().replace(f'boot_id={BOOT}', 'boot_id=unavailable'))['fabric_cached']
assert not r['valid'] and r['reason'] == 'invalid_clock_window'
print('TM summary: observed BM increments only; unknown TE semantics, epoch/config/lifecycle, stale cache, active ack, corruption and raw privacy checks PASS')
