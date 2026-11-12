#!/usr/bin/env python3
"""Ensure release packaging tracks and verifies OpenWrt's U-Boot archive."""
import hashlib
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
helper = root / 'scripts/resolve_uboot_archive.sh'

with tempfile.TemporaryDirectory(prefix='uboot-archive-') as directory:
    tree = Path(directory)
    makefile = tree / 'package/boot/uboot-tools/Makefile'
    makefile.parent.mkdir(parents=True)
    archive = tree / 'dl/u-boot-2026.10.tar.bz2'
    archive.parent.mkdir()
    payload = b'synthetic U-Boot package archive fixture\n'
    digest = hashlib.sha256(payload).hexdigest()
    makefile.write_text(f'PKG_VERSION:=2026.10\nPKG_HASH:={digest}\n')

    def resolve():
        return subprocess.run(['sh', str(helper), str(tree)],
                              capture_output=True, text=True)

    assert resolve().returncode != 0, 'missing archive must fail before build'
    archive.write_bytes(payload)
    result = resolve()
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == str(archive), result.stdout
    archive.write_bytes(payload + b'corruption')
    assert resolve().returncode != 0, 'archive hash mismatch must fail'
    archive.write_bytes(payload)
    makefile.write_text(f'PKG_VERSION:=../2026.10\nPKG_HASH:={digest}\n')
    assert resolve().returncode != 0, 'unsafe version must fail'
    makefile.write_text('PKG_VERSION:=2026.10\nPKG_HASH:=not-a-hash\n')
    assert resolve().returncode != 0, 'invalid hash must fail'

print('PASS: U-Boot archive version, missing/corrupt archive and invalid metadata')
