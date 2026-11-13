#!/usr/bin/env python3
"""Exercise the production build stamp: source identity, dirty state and privacy."""
from pathlib import Path
import hashlib
import os
import shutil
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
producer = root / 'port/scripts/write-build-info.sh'
sync = (root / 'port/scripts/sync-overlay.sh').read_text()
assert 'sh "$PORT/scripts/write-build-info.sh" "$TREE/files/etc/thoros-build-info"' in sync


def git(path, *args):
    return subprocess.check_output(['git', '-C', str(path), *args], text=True).strip()


def source_tree(path):
    (path / 'port/scripts').mkdir(parents=True)
    shutil.copyfile(producer, path / 'port/scripts/write-build-info.sh')
    (path / 'VERSION').write_text('0.8.5-beta\n')
    (path / 'port/sources.lock.json').write_text('{"schema":1,"openwrt":{"commit":"fixture"}}\n')


with tempfile.TemporaryDirectory(prefix='thoros-build-info-') as temporary:
    work = Path(temporary)
    project = work / 'project'
    source_tree(project)
    git(project, 'init', '-q')
    git(project, 'add', 'VERSION', 'port')
    git(project, '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
        'commit', '-qm', 'fixture source')
    head = git(project, 'rev-parse', 'HEAD')
    output = work / 'openwrt/files/etc/thoros-build-info'
    env = dict(os.environ, GH_TOKEN='PRIVATE_GH_TOKEN', FIT_SIGNING_KEY='PRIVATE_KEY',
               RELEASE_TAG='PRIVATE_UNVALIDATED_LABEL')

    def stamp(tree=project):
        subprocess.run(['sh', str(tree / 'port/scripts/write-build-info.sh'), str(output)],
                       env=env, check=True, capture_output=True, timeout=10)
        content = output.read_text()
        assert 'PRIVATE_' not in content and str(work) not in content
        values = dict(line.split('=', 1) for line in content.splitlines())
        assert set(values) == {'schema', 'project_version', 'project_commit',
                               'project_dirty', 'sources_lock_sha256'}
        assert values['sources_lock_sha256'] == hashlib.sha256(
            (tree / 'port/sources.lock.json').read_bytes()).hexdigest()
        assert output.stat().st_mode & 0o777 == 0o644
        assert not list(output.parent.glob('thoros-build-info.*'))
        return values, content

    values, before = stamp()
    assert values['project_commit'] == head and values['project_dirty'] == '0'
    assert values['project_version'] == '0.8.5-beta'
    assert stamp()[1] == before

    # Standard ignored/build/reference folders must not make every release
    # permanently dirty, even when a minimal checkout has no .gitignore file.
    for folder in ('sources/openwrt', 'artifacts', 'logs', 'evidence/private', 'analysis'):
        directory = project / folder
        directory.mkdir(parents=True)
        (directory / 'private').write_text('PRIVATE_MATERIAL')
    assert stamp()[0]['project_dirty'] == '0'

    (project / 'VERSION').write_text('0.8.6-candidate\n')
    values, _ = stamp()
    assert values['project_dirty'] == '1' and values['project_version'] == '0.8.6-candidate'
    (project / 'VERSION').write_text('0.8.5-beta\n')
    (project / 'port/untracked.c').write_text('/* new source must count */\n')
    assert stamp()[0]['project_dirty'] == '1'
    (project / 'port/untracked.c').unlink()
    assert stamp()[0]['project_dirty'] == '0'

    # Missing git metadata is explicit, not a guessed clean release or an
    # unrelated parent repository's SHA.
    archive = project / 'analysis/source-archive'
    source_tree(archive)
    values, _ = stamp(archive)
    assert values['project_commit'] == values['project_dirty'] == 'unknown'

    # Linked worktrees use a .git file and are still correctly attributed.
    worktree = work / 'linked-worktree'
    git(project, 'worktree', 'add', '--detach', '-q', str(worktree), head)
    values, _ = stamp(worktree)
    assert values['project_commit'] == head and values['project_dirty'] == '0'

    # A malicious/multiline VERSION is not executed and cannot inject extra
    # public fields. Validation happens before overwriting the previous stamp.
    before = output.read_bytes()
    for invalid in ('1\nsecret=PRIVATE_VALUE\n', '$(touch injected)\n', 'x' * 65 + '\n'):
        (project / 'VERSION').write_text(invalid)
        result = subprocess.run(['sh', str(project / 'port/scripts/write-build-info.sh'), str(output)],
                                env=env, capture_output=True, timeout=10)
        assert result.returncode != 0 and output.read_bytes() == before
        assert not (project / 'injected').exists()

print('Firmware identity: exact source SHA, dirty/untracked code, deterministic lock hash, '
      'archives/worktrees, atomic writes and no secrets passed')
