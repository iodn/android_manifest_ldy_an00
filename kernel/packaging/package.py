#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Package rebuilt kernel/modules with user-supplied stock inputs and AVB key.

Produces boot, system_dlkm and vbmeta_system_dlkm; parent AVB images must also
be assembled with the same key by the release tooling before installation.
Fresh module signing keys make rebuilt kernel/module bytes differ from release.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import struct
import subprocess
import sys
from erofs_metadata import metadata
from kmi import parse_kmi


def run(*args):
    subprocess.run([str(a) for a in args], check=True)


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def verify_auxiliary_tree(tree, expected):
    """Bind retained non-module inputs before copying or overwriting the module tree."""
    actual = {str(p.relative_to(tree)): p for p in tree.rglob('*') if not p.name.endswith('.ko')}
    if set(actual) != {row['path'] for row in expected}:
        raise ValueError('Unexpected auxiliary system_dlkm inventory')
    for row in expected:
        path = actual[row['path']]
        if row['type'] == 'symlink':
            valid = path.is_symlink() and str(path.readlink()) == row['target']
        elif row['type'] == 'directory':
            valid = not path.is_symlink() and path.is_dir()
        else:
            valid = not path.is_symlink() and path.is_file() and sha(path) == row['sha256']
        if not valid:
            raise ValueError('Unexpected auxiliary system_dlkm input: ' + row['path'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace', type=Path, required=True)
    parser.add_argument('--stock-boot', type=Path, required=True)
    parser.add_argument('--stock-system-dlkm', type=Path, required=True)
    parser.add_argument('--stock-system-dlkm-tree', type=Path, required=True)
    parser.add_argument('--avb-key', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    workspace = args.workspace.resolve()
    output = args.output.resolve()
    output.mkdir()  # Refuse to overwrite an earlier output or input tree.
    source = workspace / 'bazel-bin/common/kernel_aarch64'
    recipe = Path(__file__).resolve().parent
    tools = workspace / 'prebuilts/kernel-build-tools/linux-x86/bin'
    avb_path = workspace / 'external/avb/avbtool.py'
    avb_key = args.avb_key.resolve()
    spec = importlib.util.spec_from_file_location('avbtool', avb_path)
    avb = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(avb)
    (output / 'avbtool').symlink_to(avb_path)
    os.environ['PATH'] = str(output) + os.pathsep + str(tools) + os.pathsep + os.environ['PATH']
    sys.path.insert(0, str(workspace / 'tools/mkbootimg'))
    from gki.certify_bootimg import add_certificate

    release = (source / 'include/config/kernel.release').read_text().strip()
    expected_release = '6.12.38-LDY-AN00-android16-5-gd8eddc5fb80b-4k'
    if release != expected_release:
        raise ValueError('Unexpected kernel release')
    if parse_kmi((source / 'Image').read_bytes()) != 'android16-6.12':
        raise ValueError('Rebuilt kernel GKI interface is not recognizable')
    config = source / 'kernel_aarch64_dot_config'
    if sha(config) != 'cfd4c412605ce7d87f19d613baa7a5029702a39bcca30b32436c36709e9d80e5':
        raise ValueError('Unexpected kernel configuration')
    stock = args.stock_boot.read_bytes()
    if sha(args.stock_boot) != '06e2c95bbce04724c7ca3b4e5b7953a2ed3169ddceb8346de9078b2c31312702':
        raise ValueError('Requires the qualified stock boot input')
    footer = avb.AvbFooter(stock[-64:])
    blob = stock[footer.vbmeta_offset:footer.vbmeta_offset + footer.vbmeta_size]
    header = avb.AvbVBMetaHeader(blob[:256])
    aux = 256 + header.authentication_data_block_size
    properties = [d for d in avb.parse_descriptors(blob[aux + header.descriptors_offset:
                  aux + header.descriptors_offset + header.descriptors_size])
                  if isinstance(d, avb.AvbPropertyDescriptor)]
    ramdisk = output / 'ramdisk'
    ramdisk.write_bytes(b'')
    boot = output / 'boot.img'
    run(sys.executable, workspace / 'tools/mkbootimg/mkbootimg.py', '--header_version', '4',
        '--kernel', source / 'Image.lz4', '--ramdisk', ramdisk, '--cmdline', '', '--output', boot)
    prefix = boot.read_bytes()
    if prefix[:8] != stock[:8] or prefix[12:4096] != stock[12:4096]:
        raise ValueError('Rebuilt boot header differs from stock layout')
    add_certificate(str(boot), 'SHA256_RSA4096', str(avb_key),
                    ['--prop', 'ARCH:arm64', '--prop', 'BRANCH:', '--prop', 'KERNEL_RELEASE:' + release])
    command = [sys.executable, avb_path, 'add_hash_footer', '--image', boot,
               '--partition_name', 'boot', '--partition_size', '67108864', '--algorithm',
               'SHA256_RSA4096', '--key', avb_key, '--salt', sha(source / 'Image.lz4'),
               '--flags', str(header.flags), '--rollback_index', str(header.rollback_index),
               '--rollback_index_location', str(header.rollback_index_location)]
    for prop in properties:
        command += ['--prop', prop.key + ':' + prop.value.decode()]
    run(*command)

    expected = json.loads((recipe / 'system-dlkm-metadata.json').read_text())
    if metadata(args.stock_system_dlkm) != expected:
        raise ValueError('Stock system_dlkm metadata differs from the qualified layout')
    verify_auxiliary_tree(args.stock_system_dlkm_tree,
                          json.loads((recipe / 'auxiliary-files.json').read_text()))
    tree = output / 'system_dlkm-tree'
    shutil.copytree(args.stock_system_dlkm_tree, tree, symlinks=True)
    modules = json.loads((recipe / 'modules.json').read_text())
    if {str(p.relative_to(tree)) for p in tree.rglob('*.ko')} != {r['path'] for r in modules}:
        raise ValueError('Unexpected stock module inventory')
    for row in modules:
        original = tree / row['path']
        if original.is_symlink() or not original.is_file() or sha(original) != row['old_sha256']:
            raise ValueError('Unexpected stock module: ' + row['path'])
        shutil.copyfile(source / row['source'], original)
    for row in expected['inodes']:
        path = tree / row['path']
        os.chmod(path, stat.S_IMODE(row['mode']))
        stamp = row['mtime'] * 10**9 + row['mtime_nsec']
        os.utime(path, ns=(stamp, stamp))
    contexts = output / 'file_contexts'
    contexts.write_text('/system_dlkm(/.*)? u:object_r:system_dlkm_file:s0\n')
    fs_config = output / 'fs_config'
    fs_config.write_text(''.join(('system_dlkm/' + r['path'] if r['path'] else '/') + ' '
        + str(r['uid']) + ' ' + str(r['gid']) + ' ' + format(stat.S_IMODE(r['mode']), 'o')
        + '\n' for r in expected['inodes']))
    image = output / 'system_dlkm.img'
    run(tools / 'mkfs.erofs', '-b4096', '-zlz4hc,level=9', '-T' + str(expected['build_time']),
        '-U' + expected['uuid'], '--mount-point=/system_dlkm', '--file-contexts=' + str(contexts),
        '--fs-config-file=' + str(fs_config), image, tree)
    if metadata(image)['inodes'] != expected['inodes']:
        raise ValueError('Rebuilt filesystem metadata differs')
    child = output / 'vbmeta_system_dlkm.img'
    run(sys.executable, avb_path, 'add_hashtree_footer', '--image', image, '--partition_name',
        'system_dlkm', '--partition_size', '33554432', '--algorithm', 'SHA256_RSA4096',
        '--key', avb_key, '--hash_algorithm', 'sha256', '--salt',
        '71aeae77bf41b259995ba09c38dbc0bd3db20af76781b7763a32a4d60c9c9531',
        '--fec_num_roots', '2', '--rollback_index', '0', '--flags', '0',
        '--prop', 'com.oem.base_version:LDY-LGRP1-CHN 10.0.0.113',
        '--prop', 'com.android.build.system_dlkm.os_version:16',
        '--prop', 'com.android.build.system_dlkm.fingerprint:alps/krn_mgk_64_k612/mgk_64_k612:16/BP2A.250605.031.A3/eng.root:user/release-keys',
        '--output_vbmeta_image', child)
    if child.stat().st_size > 1048576:
        raise ValueError('Child AVB image exceeds partition')
    child.write_bytes(child.read_bytes().ljust(1048576, b'\0'))
    for name, size in [('boot.img', 67108864), ('system_dlkm.img', 33554432),
                       ('vbmeta_system_dlkm.img', 1048576)]:
        path = output / name
        if path.stat().st_size != size:
            raise ValueError('Incorrect partition size: ' + name)
        run(sys.executable, avb_path, 'verify_image', '--image', path, '--key', avb_key)
    print(json.dumps({n: sha(output / n) for n in ['boot.img', 'system_dlkm.img',
                                                 'vbmeta_system_dlkm.img']}, indent=2))


if __name__ == '__main__':
    main()
