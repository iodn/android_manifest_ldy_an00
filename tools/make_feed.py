#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Generate an Updater entry from the actual signed OTA; never publish it."""
import argparse
import hashlib
import json
from pathlib import Path
from urllib.parse import urlparse
import zipfile


def entry(package, url):
    if urlparse(url).scheme != 'https' or not urlparse(url).netloc:
        raise ValueError('An absolute HTTPS release-asset URL is required')
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
    args = parser.parse_args()
    result = entry(args.package, args.url)
    with args.output.open('x') as stream:
        json.dump(result, stream, indent=2)
        stream.write('\n')


if __name__ == '__main__':
    main()
