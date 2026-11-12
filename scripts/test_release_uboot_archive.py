#!/usr/bin/env python3
"""Ensure release packaging tracks and verifies OpenWrt's U-Boot archive."""
import hashlib
import io
from pathlib import Path
import subprocess
import tarfile
import tempfile

root = Path(__file__).resolve().parents[1]
helper = root / 'scripts/resolve_uboot_archive.sh'

with tempfile.TemporaryDirectory(prefix='uboot-archive-') as directory:
    tree = Path(directory)
    makefile = tree / 'package/boot/uboot-tools/Makefile'
    makefile.parent.mkdir(parents=True)
    archive = tree / 'dl/u-boot-2026.10.tar.bz2'
    archive.parent.mkdir()
    expected_makefile = b'obj-y := tools\n'
    # Reproduce the upstream U-Boot v-prefixed tar root that cannot be
    # referenced directly as the archive's u-boot-2026.10 basename.
    with tarfile.open(archive, 'w:bz2') as source:
        info = tarfile.TarInfo('u-boot-v2026.10/Makefile')
        info.size = len(expected_makefile)
        source.addfile(info, io.BytesIO(expected_makefile))
    payload = archive.read_bytes()
    digest = hashlib.sha256(payload).hexdigest()
    makefile.write_text(f'PKG_VERSION:=2026.10\nPKG_HASH:={digest}\n')

    def resolve():
        return subprocess.run(['sh', str(helper), str(tree)],
                              capture_output=True, text=True)

    missing = archive.with_name(archive.name + '.missing')
    archive.rename(missing)
    assert resolve().returncode != 0, 'missing archive must fail before build'
    missing.rename(archive)
    result = resolve()
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == str(archive), result.stdout
    package_script = (root / 'scripts/package_release.sh').read_text()
    assert 'tar -xjf "$ARCHIVE" --strip-components=1 -C "$SOURCE"' in package_script
    output = tree / 'extracted/u-boot-2026.10'
    output.mkdir(parents=True)
    subprocess.run(['tar', '-xjf', str(archive), '--strip-components=1',
                    '-C', str(output)], check=True)
    assert (output / 'Makefile').read_bytes() == expected_makefile
    archive.write_bytes(payload + b'corruption')
    assert resolve().returncode != 0, 'archive hash mismatch must fail'
    archive.write_bytes(payload)
    makefile.write_text(f'PKG_VERSION:=../2026.10\nPKG_HASH:={digest}\n')
    assert resolve().returncode != 0, 'unsafe version must fail'
    makefile.write_text('PKG_VERSION:=2026.10\nPKG_HASH:=not-a-hash\n')
    assert resolve().returncode != 0, 'invalid hash must fail'

print('PASS: U-Boot archive metadata, v-prefixed extraction, missing/corrupt archive')
