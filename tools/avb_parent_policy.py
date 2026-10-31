#!/usr/bin/env python3
"""Build authenticated top-level AVB parents for optional recovery-installed add-ons.

Flags are exactly HASHTREE_DISABLED (1), never VERIFICATION_DISABLED (2).
This disables runtime filesystem verity globally, including retained vendor roots.
It does not establish OEM verified-boot trust on a patched bootloader.
"""
import argparse
from collections import Counter
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

POLICY = 'lineage-optional-gapps-hashtree-disabled-v1'
OWNER_PUBLIC_KEY_SHA256 = '1595b33c834e1b0b29174c4aececd21cadd3d9fae9c3c3f95dacd7173c73f99c'
GOLDEN = {'vbmeta.img': '64264b3e85d69f710b5937151c214f0aa4b612990b26f3b82300cbd56313eecd',
          'recovery_vbmeta.img': '5fa34f2db7211b644009ffce42e467ad42ce231c4b1481098a70e1a4ef6640fd'}


def parse(avb, data):
    h = avb.AvbVBMetaHeader(data[:256])
    if not avb.verify_vbmeta_signature(h, data):
        raise ValueError('Invalid parent RSA authentication')
    start = 256 + h.authentication_data_block_size
    descriptors = avb.parse_descriptors(data[start + h.descriptors_offset:
        start + h.descriptors_offset + h.descriptors_size])
    return h, descriptors


def public_key_sha256(header, data):
    start = 256 + header.authentication_data_block_size + header.public_key_offset
    return hashlib.sha256(data[start:start + header.public_key_size]).hexdigest()


def validate_metadata(avb, data, role, expected_key_sha256):
    """Authenticate metadata and exact role flags; payload verification is a separate gate."""
    if role not in ('main', 'recovery', 'child'):
        raise ValueError('Unknown AVB metadata role')
    header, descriptors = parse(avb, data)
    expected_flags = 0 if role == 'child' else 1
    if header.flags != expected_flags:
        raise ValueError('Incorrect AVB flags for role: ' + role)
    if role != 'child' and header.algorithm_type != 2:
        raise ValueError('Top-level parents require SHA256_RSA4096')
    if public_key_sha256(header, data) != expected_key_sha256:
        raise ValueError('Unexpected AVB signing key')
    return header, descriptors


def validate_successor(avb, old, descriptors, data, expected_owner_sha256=OWNER_PUBLIC_KEY_SHA256):
    new, actual = validate_metadata(avb, data, 'main', expected_owner_sha256)
    if len(data) != 1048576 or new.flags != 1 or new.flags & 2:
        raise ValueError('Minimum hashtree-only policy violated')
    for field in ['algorithm_type', 'rollback_index', 'rollback_index_location',
                  'required_libavb_version_major', 'required_libavb_version_minor', 'release_string']:
        if getattr(new, field) != getattr(old, field):
            raise ValueError('Unexpected header change: ' + field)
    if Counter(d.encode() for d in actual) != Counter(d.encode() for d in descriptors):
        raise ValueError('Descriptor or chain-key change')
    return new, actual


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--avbtool', type=Path, required=True)
    p.add_argument('--inputs', type=Path, required=True)
    p.add_argument('--key', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    spec = importlib.util.spec_from_file_location('avbtool', args.avbtool)
    avb = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(avb)
    sources = {}
    for name, expected in GOLDEN.items():
        data = (args.inputs / name).read_bytes()
        if len(data) != 1048576 or hashlib.sha256(data).hexdigest() != expected:
            raise ValueError('Unqualified source parent: ' + name)
        header, descriptors = parse(avb, data)
        if header.flags != 0 or header.algorithm_type != 2:
            raise ValueError('Expected signed flags-zero source')
        if public_key_sha256(header, data) != OWNER_PUBLIC_KEY_SHA256:
            raise ValueError('Source parent is not signed by the release owner')
        sources[name] = (header, descriptors)
    args.output.mkdir()
    results = {}
    for name, (old, descriptors) in sources.items():
        path = args.output / name
        cmd = [sys.executable, str(args.avbtool), 'make_vbmeta_image', '--output', str(path),
            '--padding_size', '1048576', '--algorithm', 'SHA256_RSA4096', '--key', str(args.key),
            '--rollback_index', str(old.rollback_index), '--rollback_index_location',
            str(old.rollback_index_location), '--include_descriptors_from_image',
            str(args.inputs / name), '--flags', '1']
        subprocess.run(cmd, check=True)
        data = path.read_bytes()
        new, actual = validate_successor(avb, old, descriptors, data)
        verify = [sys.executable, str(args.avbtool), 'verify_image', '--image', str(path),
                  '--key', str(args.key)]
        for descriptor in descriptors:
            if isinstance(descriptor, avb.AvbChainPartitionDescriptor):
                public = args.output / (name + '.' + descriptor.partition_name + '.avbpubkey')
                public.write_bytes(descriptor.public_key)
                verify += ['--expected_chain_partition', descriptor.partition_name + ':'
                           + str(descriptor.rollback_index_location) + ':' + str(public)]
        subprocess.run(verify, check=True)
        results[name] = {'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data),
                         'flags': new.flags, 'descriptor_count': len(actual),
                         'all_descriptors_and_chain_keys_unchanged': True,
                         'rollback_and_version_metadata_unchanged': True}
    (args.output / 'RESULT.json').write_text(json.dumps({'policy': POLICY, 'required_cohort_format': 2, 'results': results,
        'security_scope': 'Runtime hashtree verification disabled globally, including retained vendor children. Metadata RSA and boot HASH code paths remain present; patched LK allow-error behavior is an existing separate limitation.',
        'requires_combined_child_and_payload_verification_before_installation': True}, indent=2) + '\n')
    print('FLAG1_BOTH_PARENTS_SAME_CHAIN_METADATA_CRYPTO_PASS')


if __name__ == '__main__':
    main()
