#!/usr/bin/env python3
"""Reject full builds that silently restore trimmed kernel code or lose VPN support."""
import argparse
from pathlib import Path


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--kernel', required=True, type=Path)
parser.add_argument('--manifest', required=True, type=Path)
args = parser.parse_args()

config = (args.kernel / '.config').read_text().splitlines()
selected = set(config)
# NET_SELFTESTS is a PHYLIB/INET Kconfig dependency (def_tristate PHYLIB),
# not an independently removable selftest suite on this network appliance.
removed = ('BLK_DEV_DM', 'MD', 'DM_VERITY', 'IO_URING_ZCRX')
for name in removed:
    if f'CONFIG_{name}=y' in selected or f'CONFIG_{name}=m' in selected:
        parser.error(f'unexpected compiled kernel feature: {name}')

packages = {line.split()[0] for line in args.manifest.read_text().splitlines() if line.strip()}
retained = ('tyfza1-pon-control', 'luci-app-tyfza1-pon',
            'kmod-tun', 'kmod-wireguard', 'kmod-nft-socket', 'kmod-nft-tproxy',
            'ppp', 'ppp-mod-pppoe', 'firewall4', 'dnsmasq')
missing = set(retained) - packages
if missing:
    parser.error(f'missing essential router/ONU packages: {sorted(missing)}')

print('Built kernel trim and retained router/ONU package manifest verified')
