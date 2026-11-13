#!/usr/bin/env python3
"""Apply the OpenWrt host patch and inject UBI EIO without touching flash."""
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile

root = Path(__file__).resolve().parents[1]
locked = json.loads((root / 'port/sources.lock.json').read_text())['openwrt']['commit']
assert locked == 'ada52cc7ed401153a8d0b026d1edf918bfc04c45', (
    'Update the pinned nand_upgrade_tar fixture with the OpenWrt lock')
fixture = root / 'scripts/fixtures/nand_upgrade_tar-ada52cc7.sh'
patch = root / 'port/openwrt-patches/161-nand-upgrade-ubi-write-errors.patch'
target = 'package/base-files/files/lib/upgrade/nand.sh'

# Only these functions are substituted; nand_upgrade_tar itself is the
# pinned upstream implementation, modified using the actual shipped patch.
harness = r'''
CI_KERNPART=ubi_k0
CI_ROOTPART=ubi_r0
CI_UBIPART=ubi_device
find_mtd_index() { :; }
identify_tar() { printf 'squashfs\n'; }
nand_upgrade_prepare_ubi() { return 0; }
nand_find_ubi() { printf 'ubi0\n'; }
nand_find_volume() {
    case "$2" in
        ubi_r0) printf 'ubi0_0\n' ;;
        ubi_k0) printf 'ubi0_1\n' ;;
        *) return 1 ;;
    esac
}
ubiupdatevol() {
    case "$1" in
        /dev/ubi0_0) name=root ;;
        /dev/ubi0_1) name=kernel ;;
        *) return 2 ;;
    esac
    cat > /dev/null
    printf '%s\n' "$name" >> "$CALLS"
    [ "$name" != "$TEST_FAIL" ]
}
. "$1"
nand_upgrade_tar "$2"
'''

with tempfile.TemporaryDirectory(prefix='tyfza1-nand-eio-') as tmp:
    work = Path(tmp)
    upstream = work / 'unpatched.sh'
    shutil.copyfile(fixture, upstream)
    patched = work / target
    patched.parent.mkdir(parents=True)
    shutil.copyfile(fixture, patched)
    subprocess.run(['git', 'apply', '--check', str(patch)], cwd=work, check=True)
    subprocess.run(['git', 'apply', str(patch)], cwd=work, check=True)
    assert upstream.read_bytes() != patched.read_bytes()

    image = work / 'sysupgrade.tar'
    with tarfile.open(image, 'w') as archive:
        directory = tarfile.TarInfo('sysupgrade-tianyi_tyfza1/')
        directory.type = tarfile.DIRTYPE
        archive.addfile(directory)
        for name, payload in [('root', b'hsqsroot'), ('kernel', b'kernel')]:
            info = tarfile.TarInfo('sysupgrade-tianyi_tyfza1/' + name)
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))

    script = work / 'harness.sh'
    script.write_text(harness)

    def exercise(source, failing):
        calls = work / 'calls'
        calls.write_text('')
        result = subprocess.run(['sh', str(script), str(source), str(image)],
                                env=dict(os.environ, CALLS=str(calls), TEST_FAIL=failing),
                                capture_output=True, text=True)
        return result.returncode, calls.read_text().splitlines(), result.stderr

    # A negative control proves that merely exercising the fixture cannot
    # pass the test: the locked upstream swallows both write failures.
    for failing in ('root', 'kernel'):
        code, calls, stderr = exercise(upstream, failing)
        assert code == 0 and calls == ['root', 'kernel'], (failing, code, calls, stderr)

    for failing, expected_calls in [('', ['root', 'kernel']),
                                    ('root', ['root']), ('kernel', ['root', 'kernel'])]:
        code, calls, stderr = exercise(patched, failing)
        assert (code == 0) == (not failing), (failing, code, calls, stderr)
        assert calls == expected_calls, (failing, calls, stderr)

print('PASS: pinned NAND patch propagates root/kernel UBI EIO and stops after root failure')
