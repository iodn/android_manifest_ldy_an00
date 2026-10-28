# LineageOS for HONOR LDY-AN00

Unofficial **LineageOS 24.0 / Android 17** for **HONOR LDY-AN00**.
This repository hosts the installation tools, build manifest and update feed.
Firmware downloads will be published under [Releases](https://github.com/iodn/android_manifest_ldy_an00/releases).

> **Preview — installation package not released yet.** Native RC3 boot and signed
> OTA merge have passed. The automated first-install package is under validation and still
> requires end-to-end hardware qualification. Do not use the
> current image files as a ready-to-run installation package.

## Requirements

- HONOR **LDY-AN00**; stock codename **HNLDY-M**.
- Stock firmware **10.0.0.113(C00E100R101P1)**.
- The exact supported **512 GB** partition layout.
- The qualified LK patch installed in **both boot slots**.
- A Linux x86_64 computer with USB access and space for recovery backups.

The firmware retains Honor's kernel and vendor components. Its system security
patch is 2026-10-01; the retained vendor patch is 2025-12-01. Do not relock the
bootloader or install an Honor OTA over this installation.

## First installation

The intended release will contain one installer ZIP with the required images,
tools and a guided `flash.sh`. Once that package is qualified and published:

1. Back up personal files. Installation erases the phone's user data.
2. Download the installer ZIP from the matching release and verify its checksum.
3. Extract it and run `bash flash.sh` from the extracted folder.
4. Follow its checks and confirmations; reboot only after verification succeeds.

**That qualified package is not available yet.** `flash.sh` and
`tools/first_install.py` are under validation. Run the installer only from the
complete signed release package; a source checkout has no installation assets.
The installer must check the device, firmware and partition layout, preserve
recovery backups, stop on errors and verify written data before offering a reboot.

## Updates

After a compatible native installation, updates will use
**Settings > System > Updater**. A reboot is required to run the new version;
Virtual A/B merge completes afterward. Do not switch slots manually after merge.
The update feed remains empty until qualified signed releases are available.

## Source

| Repository | Purpose |
| --- | --- |
| This repository | Manifest, upstream adaptations, installation tools and releases |
| [Device tree](https://github.com/iodn/android_device_honor_ldy_an00) | Device configuration and device-specific IMS integration |
| [Vendor configuration](https://github.com/iodn/android_vendor_honor_ldy_an00) | Required proprietary-input definitions and inventories |

<details>
<summary>Build integration and release maintenance</summary>

For a new, suitably provisioned Android source checkout:

```sh
repo init -u https://github.com/iodn/android_manifest_ldy_an00 -b main
repo sync -c
python3 .repo/manifests/patches/apply.py --source . --check
python3 .repo/manifests/patches/apply.py --source . --apply
```

The patch runner checks pinned upstream bases, patch hashes and resulting Git
source trees. It does not commit or push. Preserve applied changes before syncing.
Supply the excluded, matching proprietary inputs before building. The pinned
repository layout has passed a cached integration rebuild. Signed first-install
hardware qualification is required before publication.

Use `lineage_ldy_an00_native` as the native product, `ldy_an00` as the source
codename and `LDY-AN00` as the displayed model. Keep the existing signing
identities for compatible updates. Tag immutable source revisions and publish
verified assets through GitHub Releases; keep images and private keys out of Git.

The installed update endpoint stays at
`https://raw.githubusercontent.com/iodn/android_manifest_ldy_an00/main/ota/ldy_an00.json`.
Publish and test signed assets before adding an entry. The Updater protocol uses
an array containing `files[]`. `tools/make_feed.py` prepares an entry from a signed OTA.

Run host checks with:

```sh
python3 -m unittest discover -s tools -p 'test_*.py'
```

New standalone documentation/tools use Apache-2.0. Upstream adaptations retain
their existing licenses and notices. Review proprietary-component redistribution
terms before publishing binary releases.

</details>

## Reporting a problem

Provide the build identifier and reproduction steps. Remove phone numbers,
subscriber identifiers, eSIM activation codes, credentials and personal data from
logs before sharing them. This is an unofficial project, independent of HONOR
and the LineageOS project.
