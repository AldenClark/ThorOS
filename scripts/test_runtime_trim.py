#!/usr/bin/env python3
"""Offline checks for production runtime reductions and preserved user settings."""
import ast
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / 'port/overlay/target/linux/rtl9617c/base-files'
LOG_DEFAULTS = BASE / 'etc/uci-defaults/88-tyfza1-logging'


class RuntimeTrimTests(unittest.TestCase):
    def test_logging_defaults_migrate_only_project_values(self):
        # Drive the real shell migration through a tiny UCI protocol stub.
        with tempfile.TemporaryDirectory(prefix='tyfza1-log-defaults-') as temporary:
            work = Path(temporary)
            state = work / 'system.json'
            uci = work / 'uci'
            uci.write_text('''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
p = Path(os.environ['TYFZA1_TEST_UCI'])
data = json.loads(p.read_text())
args = [arg for arg in sys.argv[1:] if arg != '-q']
command = args[0]
if command == 'get':
    if args[1] not in data: sys.exit(1)
    print(data[args[1]])
elif command == 'set':
    key, value = args[1].split('=', 1)
    data[key] = value
elif command == 'delete':
    if args[1] not in data: sys.exit(1)
    del data[args[1]]
elif command != 'commit':
    sys.exit(2)
p.write_text(json.dumps(data))
''')
            uci.chmod(0o755)
            env = dict(os.environ, TYFZA1_TEST_UCI=str(state),
                       PATH=str(work) + os.pathsep + os.environ['PATH'])
            prefix = 'system.@system[0].'
            cases = (
                ({}, {prefix + 'log_buffer_size': '128'}),
                ({prefix + 'log_buffer_size': '256',
                  prefix + 'log_file': '/tmp/log/tyfza1.log',
                  prefix + 'log_size': '2048'},
                 {prefix + 'log_buffer_size': '128'}),
                ({prefix + 'log_buffer_size': '512',
                  prefix + 'log_file': '/var/log/custom.log',
                  prefix + 'log_size': '4096'},
                 {prefix + 'log_buffer_size': '512',
                  prefix + 'log_file': '/var/log/custom.log',
                  prefix + 'log_size': '4096'}),
                ({prefix + 'log_buffer_size': '512',
                  prefix + 'log_file': '/tmp/log/tyfza1.log',
                  prefix + 'log_size': '4096'},
                 {prefix + 'log_buffer_size': '512', prefix + 'log_size': '4096'}),
            )
            for before, after in cases:
                state.write_text(json.dumps(before))
                for _ in range(2):
                    subprocess.run(['sh', str(LOG_DEFAULTS)], env=env, check=True)
                    self.assertEqual(json.loads(state.read_text()), after)

    def test_no_redundant_boot_logger(self):
        self.assertFalse((BASE / 'etc/init.d/tyfza1-bootlog').exists())
        factory = (BASE / 'etc/init.d/tyfza1-factory').read_text()
        self.assertIn('rm -f /tmp/log/tyfza1-factory.log', factory)

    def test_led_monitor_only_runs_when_leds_enabled(self):
        service = (BASE / 'etc/init.d/tyfza1-leds').read_text()
        self.assertLess(service.index('[ "$mode" != 0 ] || return 0'),
                        service.index('procd_open_instance'))
        self.assertIn('reload_service() {\n\t#', service)
        self.assertIn('\tstart\n}', service)

    def test_production_kernel_needs_no_device_mapper(self):
        config = (ROOT / 'port/overlay/target/linux/rtl9617c/config-6.18').read_text()
        for symbol in ('MD', 'BLK_DEV_DM', 'IO_URING_ZCRX'):
            self.assertIn(f'# CONFIG_{symbol} is not set', config)
            self.assertNotIn(f'CONFIG_{symbol}=y', config)
        # PHYLIB + INET select NET_SELFTESTS through an unprompted Kconfig
        # default. A requested "not set" here never survives olddefconfig.
        self.assertNotIn('# CONFIG_NET_SELFTESTS is not set', config)
        fit = (ROOT / 'scripts/make_ubi_fit.py').read_text()
        self.assertIn('root=${tyfza1_block} rootfstype=squashfs', fit)
        self.assertNotIn('dm-mod.create=', fit)

    def test_board_verifier_no_longer_calls_deleted_pe_test(self):
        path = ROOT / 'scripts/test_board_variants.py'
        source = path.read_text()
        ast.parse(source)
        self.assertNotIn('test_pe_physical_reset.py', source)
        self.assertIn('pe_shadow_windows', source)
        workflow = (ROOT / '.github/workflows/build-release.yml').read_text()
        self.assertIn('set -o pipefail', workflow)
        self.assertIn('verify_release_kernel.py', workflow)

    def test_built_kernel_and_router_package_guard(self):
        with tempfile.TemporaryDirectory(prefix='tyfza1-kernel-guard-') as temporary:
            root = Path(temporary)
            manifest = root / 'release.manifest'
            needed = ('tyfza1-pon-control', 'luci-app-tyfza1-pon',
                      'kmod-tun', 'kmod-wireguard', 'kmod-nft-socket', 'kmod-nft-tproxy',
                      'ppp', 'ppp-mod-pppoe', 'firewall4', 'dnsmasq')
            manifest.write_text(''.join(name + ' 1\n' for name in needed))
            config = root / '.config'
            config.write_text('# CONFIG_BLK_DEV_DM is not set\nCONFIG_PHYLIB=y\n'
                              'CONFIG_INET=y\nCONFIG_NET_SELFTESTS=y\n')
            command = [sys.executable, str(ROOT / 'scripts/verify_release_kernel.py'),
                       '--kernel', str(root), '--manifest', str(manifest)]
            self.assertEqual(subprocess.run(command, capture_output=True).returncode, 0)
            config.write_text('CONFIG_DM_VERITY=m\n')
            self.assertNotEqual(subprocess.run(command, capture_output=True).returncode, 0)
            config.write_text('# CONFIG_BLK_DEV_DM is not set\n')
            manifest.write_text(''.join(name + ' 1\n' for name in needed if name != 'kmod-wireguard'))
            self.assertNotEqual(subprocess.run(command, capture_output=True).returncode, 0)


if __name__ == '__main__':
    unittest.main()
