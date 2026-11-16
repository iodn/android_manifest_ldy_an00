# SPDX-License-Identifier: Apache-2.0
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from verify_patch_coverage import verify


class PatchCoverageTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / 'source'
        self.patches = self.root / 'patches'
        self.patches.mkdir()
        self.series = self.patches / 'series.json'
        self.lock = self.root / 'source-lock.json'
        self.rows = []
        for index, name in enumerate(('packages/modules/adb', 'packages/apps/Aperture')):
            project = self.source / name
            project.mkdir(parents=True)
            self.git(project, 'init', '-q')
            self.git(project, 'config', 'user.name', 'iodn')
            self.git(project, 'config', 'user.email', '114117719+iodn@users.noreply.github.com')
            (project / 'feature').write_text(name + ': upstream\n')
            self.commit(project, 'Base')
            base = self.git(project, 'rev-parse', 'HEAD')
            (project / 'feature').write_text(name + ': maintained integration\n')
            self.commit(project, 'Device integration')
            patch = self.patches / (str(index) + '.patch')
            patch.write_text(self.git(project, 'diff', base, 'HEAD') + '\n')
            tree = self.git(project, 'rev-parse', 'HEAD^{tree}')
            self.rows.append({'path': name, 'base_revision': base, 'patch': patch.name,
                              'patch_sha256': hashlib.sha256(patch.read_bytes()).hexdigest(),
                              'tree': tree, 'target_snapshot_tree': tree})
        self.save()
        self.lock.write_text(json.dumps({'projects': [dict(row, patch='patches/' + row['patch']) for row in self.rows]}))

    def git(self, project, *args):
        return subprocess.check_output(['git', '-C', str(project), *args], text=True).strip()

    def commit(self, project, message):
        self.git(project, 'add', 'feature')
        self.git(project, '-c', 'commit.gpgSign=false', 'commit', '-qm', message)

    def save(self):
        self.series.write_text(json.dumps({'projects': self.rows}))

    def test_all_actual_patched_projects_pass(self):
        self.assertEqual([row['path'] for row in self.rows],
                         [row['path'] for row in verify(self.source, self.series, self.lock)])

    def test_default_upstream_instead_of_adb_override_fails(self):
        row = self.rows[0]
        self.git(self.source / row['path'], 'reset', '--hard', row['base_revision'])
        with self.assertRaisesRegex(ValueError, 'Actual source tree'):
            verify(self.source, self.series, self.lock)

    def test_missing_aperture_override_fails(self):
        shutil.rmtree(self.source / self.rows[1]['path'])
        with self.assertRaisesRegex(ValueError, 'Missing actual project'):
            verify(self.source, self.series, self.lock)

    def test_uncommitted_tracked_change_fails(self):
        (self.source / self.rows[0]['path'] / 'feature').write_text('unreviewed\n')
        with self.assertRaisesRegex(ValueError, 'Dirty source'):
            verify(self.source, self.series, self.lock)

    def test_untracked_source_fails(self):
        (self.source / self.rows[0]['path'] / 'unreviewed.cpp').write_text('code')
        with self.assertRaisesRegex(ValueError, 'Dirty source'):
            verify(self.source, self.series, self.lock)

    def test_changed_patch_digest_fails(self):
        (self.patches / self.rows[0]['patch']).write_text('changed')
        with self.assertRaisesRegex(ValueError, 'patch digest'):
            verify(self.source, self.series, self.lock)

    def test_conflicting_target_snapshot_fails(self):
        self.rows[0]['target_snapshot_tree'] = '0' * 40
        self.save()
        with self.assertRaisesRegex(ValueError, 'snapshot tree'):
            verify(self.source, self.series, self.lock)

    def test_duplicate_project_inventory_fails(self):
        self.rows.append(self.rows[0])
        self.save()
        with self.assertRaisesRegex(ValueError, 'duplicated'):
            verify(self.source, self.series, self.lock)

    def test_missing_maintained_source_lock_entry_fails(self):
        data = json.loads(self.lock.read_text())
        data['projects'].pop(0)
        self.lock.write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError, 'absent from source-lock'):
            verify(self.source, self.series, self.lock)

    def test_stale_source_lock_tree_fails(self):
        data = json.loads(self.lock.read_text())
        data['projects'][0]['tree'] = '0' * 40
        self.lock.write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError, 'Source-lock disagrees'):
            verify(self.source, self.series, self.lock)

    def test_project_cannot_escape_workspace(self):
        self.rows[0]['path'] = '../elsewhere'
        self.save()
        with self.assertRaisesRegex(ValueError, 'Invalid maintained project path'):
            verify(self.source, self.series, self.lock)


if __name__ == '__main__':
    unittest.main()
