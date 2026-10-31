#!/usr/bin/env python3
"""Host cryptographic policy regression tests; uses only a disposable test key."""
import argparse
import copy
import hashlib
import importlib.util
from pathlib import Path
import subprocess
import tempfile

from avb_parent_policy import GOLDEN, OWNER_PUBLIC_KEY_SHA256, parse, public_key_sha256, validate_metadata, validate_successor


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--avbtool', type=Path, required=True)
    parser.add_argument('--inputs', type=Path, required=True)
    args = parser.parse_args()
    spec = importlib.util.spec_from_file_location('avbtool', args.avbtool)
    avb = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(avb)
    checks = []

    def rejects(operation, label):
        try:
            operation()
        except (ValueError, avb.AvbError):
            checks.append(label)
            return
        raise AssertionError('Unexpected acceptance: ' + label)

    with tempfile.TemporaryDirectory(prefix='avb-parent-policy-') as directory:
        key = Path(directory) / 'test.pem'
        subprocess.run(['openssl', 'genrsa', '-out', str(key), '4096'], check=True, capture_output=True)
        public = avb.RSAPublicKey(str(key)).encode()
        test_digest = hashlib.sha256(public).hexdigest()
        assert test_digest != OWNER_PUBLIC_KEY_SHA256
        for name, digest in GOLDEN.items():
            source = (args.inputs / name).read_bytes()
            assert hashlib.sha256(source).hexdigest() == digest
            old, descriptors = parse(avb, source)
            assert public_key_sha256(old, source) == OWNER_PUBLIC_KEY_SHA256

            def generate(flags=1, ds=None, rollback=None):
                blob = avb.Avb()._generate_vbmeta_blob(
                    algorithm_name='SHA256_RSA4096', key_path=str(key),
                    public_key_metadata_path=None, descriptors=descriptors if ds is None else ds,
                    chain_partitions_use_ab=None, chain_partitions_do_not_use_ab=None,
                    rollback_index=old.rollback_index if rollback is None else rollback,
                    flags=flags, rollback_index_location=old.rollback_index_location,
                    props=None, props_from_file=None, kernel_cmdlines=None,
                    setup_rootfs_from_kernel=None, ht_desc_to_setup=None,
                    include_descriptors_from_image=None, signing_helper=None,
                    signing_helper_with_files=None, release_string=old.release_string,
                    append_to_release_string=None,
                    required_libavb_version_minor=old.required_libavb_version_minor)
                return blob.ljust(1048576, b'\0')

            data = generate()
            validate_successor(avb, old, descriptors, data, test_digest)
            validate_metadata(avb, data, 'recovery', test_digest)
            checks.append(name + ': authenticated flags1 accepted for both parent roles')
            rejects(lambda: validate_successor(avb, old, descriptors, data), name + ': temporary key rejected by owner policy')
            for flags in [0, 2, 3]:
                bad = generate(flags)
                rejects(lambda: validate_successor(avb, old, descriptors, bad, test_digest), name + ': signed flags' + str(flags))
            for offset in [123, 300]:
                bad = bytearray(data)
                bad[offset] ^= 1
                rejects(lambda: validate_successor(avb, old, descriptors, bytes(bad), test_digest), name + ': unsigned tamper ' + str(offset))
            rejects(lambda: validate_successor(avb, old, descriptors, data[:4096], test_digest), name + ': truncated partition')
            bad = generate(rollback=old.rollback_index + 1)
            rejects(lambda: validate_successor(avb, old, descriptors, bad, test_digest), name + ': changed rollback')
            changed = copy.deepcopy(descriptors)
            chain = next(d for d in changed if isinstance(d, avb.AvbChainPartitionDescriptor))
            chain.public_key = bytes([chain.public_key[0] ^ 1]) + chain.public_key[1:]
            bad = generate(ds=changed)
            rejects(lambda: validate_successor(avb, old, descriptors, bad, test_digest), name + ': changed authenticated chain key')
            child = generate(flags=0)
            validate_metadata(avb, child, 'child', test_digest)
            checks.append(name + ': authenticated flags0 child accepted')
            rejects(lambda: validate_metadata(avb, data, 'child', test_digest), name + ': flags1 child refused')
    print('AVB_PARENT_POLICY_PASS ' + str(len(checks)))


if __name__ == '__main__':
    main()
