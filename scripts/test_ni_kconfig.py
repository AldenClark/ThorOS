#!/usr/bin/env python3
"""Test prepared NI linkage with the real Linux Kconfig conf executable.

The driver stanza is extracted unchanged from --kernel. Minimal dependency
symbols isolate its PHYLIB tristate contract; this is not a replacement for
configuring or linking the complete kernel. --conf must be the executable
built from that prepared tree (CI supplies $out/scripts/kconfig/conf).

Linux 6.18 scripts/kconfig/conf.c accepts --defconfig=<seed>; confdata.c uses
KCONFIG_CONFIG for the resulting configuration. Each case has an independent
temporary directory, so neither the kernel build config nor its outputs are
changed. The former bare PHYLIB dependency is run as a negative control: its
bool consumer incorrectly remains y when PHYLIB=m.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile


def stanza(text, symbol):
    """Read one top-level config block, retaining its actual type and body."""
    match = re.search(r'^config ' + re.escape(symbol) + r'\s*$', text, re.M)
    if not match:
        raise ValueError('missing prepared Kconfig symbol: ' + symbol)
    lines = text[match.start():].splitlines(keepends=True)
    count = 1
    while count < len(lines):
        line = lines[count]
        if line.strip() and not line[0].isspace() and not line.startswith('#'):
            break
        count += 1
    return ''.join(lines[:count]).rstrip() + '\n'


def config_value(text, symbol):
    match = re.search(r'^CONFIG_' + re.escape(symbol) + r'=(\w+)$', text, re.M)
    return match.group(1) if match else 'n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kernel', type=Path, required=True,
                        help='Linux source tree after all OpenWrt/ThorOS patches')
    parser.add_argument('--conf', type=Path, required=True,
                        help='scripts/kconfig/conf built from that kernel tree')
    args = parser.parse_args()
    kernel, conf = args.kernel.resolve(), args.conf.resolve()
    if not conf.is_file() or not os.access(conf, os.X_OK):
        parser.error('--conf must name the real executable produced by the kernel build')

    version = (kernel / 'Makefile').read_text()
    values = []
    for field in ('VERSION', 'PATCHLEVEL', 'SUBLEVEL'):
        match = re.search(r'^' + field + r'\s*=\s*(\d+)\s*$', version, re.M)
        if not match:
            parser.error('cannot identify kernel ' + field)
        values.append(match.group(1))
    kernel_version = '.'.join(values)
    project = Path(__file__).resolve().parents[1]
    locked_version = json.loads((project / 'port/sources.lock.json').read_text())['openwrt']['kernel']
    if not locked_version or kernel_version != locked_version:
        parser.error(f'kernel version {kernel_version} does not match locked kernel {locked_version}')

    relative = 'drivers/net/ethernet/realtek/Kconfig'
    actual = stanza((kernel / relative).read_text(), 'RTL9617C_XRAM_ETH')
    if not re.search(r'^\s+bool\s', actual, re.M):
        parser.error('prepared NI stanza is not built-in-only; prepare the current target patches')
    if not re.search(r'\bPHYLIB\s*=\s*y\b', actual):
        parser.error('prepared NI stanza lacks PHYLIB=y; prepare the current target patches')

    # These symbols only provide the surrounding configuration universe.
    # The complete NI block (including depends/select/help) remains verbatim.
    prefix = '''mainmenu "ThorOS NI linkage regression"

config MODULES
\tbool "Loadable modules"
\tmodules
\tdefault y

config PHYLIB
\ttristate "PHY library"

'''
    for symbol in ('OF', 'ARCH_RTL9617C', 'INET', 'NET_SWITCHDEV'):
        prefix += f'config {symbol}\n\tbool\n\tdefault y\n\n'
    for symbol in ('CRC32', 'RTL9617C_SWITCH_GUARD', 'NETFILTER',
                   'NETFILTER_INGRESS', 'SKB_EXTENSIONS', 'NET_CLS_ACT'):
        prefix += f'config {symbol}\n\tbool\n\n'

    previous, replacements = re.subn(r'\bPHYLIB\s*=\s*y\b', 'PHYLIB', actual)
    if replacements != 1:
        parser.error('expected one PHYLIB equality in the actual NI stanza')
    cases = [('production', actual, state, expected)
             for state, expected in (('n', 'n'), ('m', 'n'), ('y', 'y'))]
    cases.append(('bare_phylib_negative_control', previous, 'm', 'y'))
    rows = []
    with tempfile.TemporaryDirectory(prefix='ni-kconfig-') as temporary:
        for index, (name, driver, phylib, expected) in enumerate(cases):
            work = Path(temporary) / str(index)
            work.mkdir()
            kconfig, seed, output = work / 'Kconfig', work / 'seed', work / '.config'
            kconfig.write_text(prefix + driver)
            seed.write_text('CONFIG_MODULES=y\n' +
                            (f'CONFIG_PHYLIB={phylib}\n' if phylib != 'n'
                             else '# CONFIG_PHYLIB is not set\n') +
                            'CONFIG_RTL9617C_XRAM_ETH=y\n')
            environment = os.environ.copy()
            environment['KCONFIG_CONFIG'] = str(output)
            run = subprocess.run([str(conf), '--defconfig=' + str(seed), str(kconfig)],
                                 cwd=work, env=environment, capture_output=True,
                                 text=True, timeout=30)
            if run.returncode or not output.is_file():
                raise RuntimeError(f'{name} PHYLIB={phylib}: real conf failed\n' +
                                   run.stdout + run.stderr)
            result = output.read_text()
            observed_phy = config_value(result, 'PHYLIB')
            observed_ni = config_value(result, 'RTL9617C_XRAM_ETH')
            if config_value(result, 'MODULES') != 'y' or observed_phy != phylib:
                raise AssertionError(f'{name}: test prerequisite changed: MODULES=' +
                                     config_value(result, 'MODULES') + f', PHYLIB={observed_phy}')
            if observed_ni != expected:
                raise AssertionError(f'{name} PHYLIB={phylib}: NI={observed_ni}, expected {expected}\n' +
                                     result + run.stdout + run.stderr)
            rows.append({'variant': name, 'PHYLIB': observed_phy,
                         'RTL9617C_XRAM_ETH': observed_ni})
            print(f'{name}: PHYLIB={phylib} -> RTL9617C_XRAM_ETH={observed_ni}')

    report = {
        'kernel_version': kernel_version,
        'stanza_source': relative,
        'stanza_sha256': hashlib.sha256(actual.encode()).hexdigest(),
        'conf_sha256': hashlib.sha256(conf.read_bytes()).hexdigest(),
        'conf_source_sha256': hashlib.sha256((kernel / 'scripts/kconfig/conf.c').read_bytes()).hexdigest(),
        'symbol_source_sha256': hashlib.sha256((kernel / 'scripts/kconfig/symbol.c').read_bytes()).hexdigest(),
        'actual_kconfig_execution': True,
        'minimal_surrounding_dependency_symbols': True,
        'negative_control_exposes_builtin_to_module_mismatch': True,
        'full_kernel_link_test': False,
        'cases': rows,
    }
    (project / 'logs').mkdir(exist_ok=True)
    (project / 'logs/ni-kconfig-test.json').write_text(json.dumps(report, indent=2) + '\n')
    print('NI Kconfig: real conf passed n/m/y linkage gate and reproduced former bare-PHYLIB bug')


if __name__ == '__main__':
    main()
