#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run the actual Updater repository method with JVM stubs and real coroutines."""
import argparse
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--android-root', type=Path, required=True)
    parser.add_argument('--updater-root', type=Path, help='Optional maintained Updater checkout')
    args = parser.parse_args()
    root = args.android_root.resolve()
    updater = args.updater_root or root / 'packages/apps/Updater'
    production = updater / 'app/src/main/java/org/lineageos/updater/data/UpdatesRepository.kt'
    notes = updater / 'app/src/main/java/org/lineageos/updater/util/ReleaseNotes.kt'
    kotlin = root / 'external/kotlinc'
    jdk = root / 'prebuilts/jdk/jdk21/linux-x86'
    stdlib = kotlin / 'lib/kotlin-stdlib.jar'
    coroutines = kotlin / 'lib/kotlinx-coroutines-core-jvm.jar'
    for path in (production, notes, stdlib, coroutines, jdk / 'bin/java', kotlin / 'lib/kotlin-compiler.jar'):
        if not path.is_file():
            parser.error('Required existing input is missing: ' + str(path))
    digest = hashlib.sha256(production.read_bytes()).hexdigest()
    notes_digest = hashlib.sha256(notes.read_bytes()).hexdigest()
    print('Actual UpdatesRepository.kt SHA256: ' + digest, flush=True)
    print('Actual ReleaseNotes.kt SHA256: ' + notes_digest, flush=True)
    env = dict(os.environ, JAVA_HOME=str(jdk), PYTHONDONTWRITEBYTECODE='1')
    classpath = os.pathsep.join(map(str, (stdlib, coroutines)))
    sources = sorted(Path(__file__).resolve().parent.glob('*.kt'))
    with tempfile.TemporaryDirectory(prefix='updater-notifications-') as temporary:
        jar = Path(temporary) / 'tests.jar'
        command = [str(jdk / 'bin/java'), '-Xmx2g', '-cp', str(kotlin / 'lib/*'),
                   'org.jetbrains.kotlin.cli.jvm.K2JVMCompiler', '-no-stdlib', '-no-reflect',
                   '-jvm-target', '21', '-classpath', classpath, '-d', str(jar),
                   str(production), str(notes), *map(str, sources)]
        subprocess.run(command, env=env, check=True)
        subprocess.run([str(jdk / 'bin/java'), '-cp', str(jar) + os.pathsep + classpath,
                        'MainKt'], env=env, check=True)
    if (hashlib.sha256(production.read_bytes()).hexdigest() != digest
            or hashlib.sha256(notes.read_bytes()).hexdigest() != notes_digest):
        raise RuntimeError('Production source changed during the test')


if __name__ == '__main__':
    main()
