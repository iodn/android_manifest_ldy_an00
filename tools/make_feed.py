#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Generate an Updater entry from the actual signed OTA; never publish it."""
import argparse
import hashlib
import json
from pathlib import Path
from urllib.parse import urlparse
import zipfile

import validate_ota_vendor_retention


def entry(package, url, *, kernel_admission=None, kernel_admission_sha256=None):
    if urlparse(url).scheme != 'https' or not urlparse(url).netloc:
        raise ValueError('An absolute HTTPS release-asset URL is required')
    authenticated = None
    if kernel_admission is None and kernel_admission_sha256 is None:
        validate_ota_vendor_retention.validate_zip(package)
    elif kernel_admission is not None and kernel_admission_sha256 is not None:
        from validate_ota_kernel_cohort import validate_zip
        authenticated = validate_zip(package, kernel_admission, kernel_admission_sha256)
    else:
        raise ValueError("Kernel admission and expected SHA256 must be supplied together")
    with zipfile.ZipFile(package) as archive:
        metadata = dict(line.split('=', 1) for line in
                        archive.read('META-INF/com/android/metadata').decode().splitlines()
                        if '=' in line)
        properties = archive.read('payload_properties.txt').decode()
        if metadata['ota-type'] != 'AB' or metadata['pre-device'] != 'ldy_an00':
            raise ValueError('Wrong OTA type or device')
        if 'FILE_HASH=' not in properties or 'METADATA_HASH=' not in properties:
            raise ValueError('Incomplete payload properties')
    with package.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    if authenticated is not None and digest != authenticated['ota_sha256']:
        raise ValueError('OTA changed after authenticated kernel admission')
    return [{
        'datetime': int(metadata['post-timestamp']),
        'files': [{
            'filename': package.name,
            'os_patch_level': metadata['post-security-patch-level'],
            'os_sdk_level': int(metadata['post-sdk-level']),
            'ota_property_files': metadata['ota-property-files'],
            'sha256': digest,
            'size': package.stat().st_size,
            'url': url,
        }],
        'type': 'UNOFFICIAL',
        'version': '24.0',
    }]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('package', type=Path)
    parser.add_argument('--url', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--kernel-admission', type=Path)
    parser.add_argument('--kernel-admission-sha256')
    args = parser.parse_args()
    result = entry(args.package, args.url, kernel_admission=args.kernel_admission,
                   kernel_admission_sha256=args.kernel_admission_sha256)
    with args.output.open('x') as stream:
        json.dump(result, stream, indent=2)
        stream.write('\n')


if __name__ == '__main__':
    main()
