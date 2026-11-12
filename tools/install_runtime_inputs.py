#!/usr/bin/env python3
"""Install common vendor firmware only; per-unit data is read on the target."""
import argparse
from pathlib import Path
import shutil

root = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('inputs', type=Path)
parser.add_argument('output', type=Path)
args = parser.parse_args()
firmware = args.inputs / 'lib/firmware/realtek/rtl9617c'
# The upstream bundle includes optional radio blobs. Install only PON SerDes.
for mode in ('epon', 'epon_d10g', 'epon_bi10g', 'gpon', 'xgpon', 'xgspon'):
    source = firmware / f'pon_serdes_{mode}.bin'
    if not source.is_file():
        raise ValueError(f'Missing common SerDes firmware: {mode}')
    destination = args.output / 'lib/firmware/realtek/rtl9617c' / source.name
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    destination.chmod(0o644)
config = args.output / 'etc/config/pon'
config.parent.mkdir(parents=True, exist_ok=True)
shutil.copyfile(root / 'port/overlay/target/linux/rtl9617c/base-files/etc/config/pon', config)
config.chmod(0o600)
print('Installed common runtime inputs; subscriber configuration remains empty')
