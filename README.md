# LineageOS for HONOR LDY-AN00

Unofficial **LineageOS 24.0 / Android 17** for **HONOR LDY-AN00**.
This repository hosts the installation tools, build manifest and update feed.
Versioned firmware downloads are published under [Releases](https://github.com/iodn/android_manifest_ldy_an00/releases).

**Current release:** [LineageOS 24.0 - 2026-10-28](https://github.com/iodn/android_manifest_ldy_an00/releases/tag/lineage-24.0-20261028-UNOFFICIAL-ldy_an00).

This unofficial release has passed a fresh installation and boot test, signing
checks and partition readback verification. SELinux is enforcing.

## Compatibility

This release supports the following installation baseline:

| Item | Supported configuration |
| --- | --- |
| Device | HONOR LDY-AN00 (stock codename HNLDY-M) |
| Storage layout | Verified 512 GB variant |
| Installed stock firmware | 10.0.0.113(C00E100R101P1) |
| Bootloader | Qualified LK unlock patch installed and boot-tested on both slots |

The storage requirement refers to the partition layout checked by this installer,
not an Android storage-capacity limit. Other capacities and stock firmware versions
have not been validated and are not currently supported by this package. The
installer stops if their layout or partition hashes differ; do not bypass those
checks or downgrade firmware solely to satisfy them.

An unlocked bootloader is necessary, but does not by itself establish
compatibility. This package installs the Android system while retaining Honor's
kernel, vendor firmware and other device-specific components. The stock version
therefore matters. Broader support requires validating those components and the
installation layout for each additional configuration.

The Android system security patch is **2026-10-01**; the retained vendor patch is
**2025-12-01**. The system patch level does not upgrade retained kernel/vendor
security fixes. Do not relock the bootloader or install an Honor OTA over this
installation.

## Installation requirements

- Linux x86_64 with USB access and at least 22 GB free for the stock recovery set.
- Python 3.11 or newer, OpenSSL, PyUSB and ADB.
- Authorized USB debugging and existing Android root for the read-only layout check.

Installation erases user data. Back up personal files before starting.

## First installation

Download the complete installer ZIP and `SHA256SUMS` from the matching
[GitHub release](https://github.com/iodn/android_manifest_ldy_an00/releases).
A source checkout does not contain installation images.

1. Save personal files; installation erases user data.
2. Verify the downloaded ZIP with `sha256sum -c SHA256SUMS`.
3. Extract the ZIP and open a terminal in its folder. Connect the phone while
   stock Android is running with USB debugging authorized and root available.
4. Run the layout check, then enter bootloader fastboot and install:

```sh
python3 tools/prepare_layout.py --root-broker /data/local/tmp/su
# Continue only after LAYOUT_VERIFIED.
adb reboot bootloader
bash flash.sh
```

Use the actual root-broker path from the unlock procedure. If ADB itself is
already root, omit `--root-broker /data/local/tmp/su`. The read-only layout
receipt expires after one hour and is bound to the device and selected slot.

Read the confirmation and type `INSTALL` to accept data erasure. Wait for
`INSTALL_VERIFIED` and automatic reboot, then complete Android setup.
Full partition readbacks can take about 30 minutes each; keep USB connected.
If installation stops, preserve the journal and follow the packaged README;
do not blindly retry, reboot or switch slots.

The installer verifies the signed package, exact stock baseline and written
partitions. It keeps one stock recovery set and preserves LK, the kernel,
vendor firmware and calibration/security partitions.

## Updates

After a compatible native installation, updates will use
**Settings > System > Updater**. A reboot is required to run the new version;
Virtual A/B merge completes afterward. Do not switch slots manually after merge.
The initial installer is not an OTA ZIP. The feed remains empty until a
compatible signed OTA package has passed testing.

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
repository layout has passed a cached integration rebuild. Every new release
requires signature checks and hardware qualification before publication.

Use `lineage_ldy_an00_native` as the native product, `ldy_an00` as the source
codename and `LDY-AN00` as the displayed model. Keep the existing signing
identities for compatible updates. Give every release a unique build date and
increasing timestamp; never replace published images under an existing version.
Tag immutable source revisions and publish verified assets through GitHub Releases; keep images and private keys out of Git.

The installed update endpoint stays at
`https://raw.githubusercontent.com/iodn/android_manifest_ldy_an00/main/ota/ldy_an00.json`.
Publish and test signed assets before adding an entry. The Updater protocol uses
an array containing `files[]`. `tools/make_feed.py` prepares an entry from a signed OTA.
The feed tool checks the OTA partition scope; verify release signatures separately.

Run host checks with:

```sh
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -r tools/requirements.txt
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

The first-install tool keeps one stock recovery set per device. Completed runs
record it for reuse; unchanged boot-chain partitions are verified without backup
copies. An existing verified set can be selected with `--stock-backup`.

First installation requires a fresh layout receipt from `tools/prepare_layout.py`
while Android root is available, before entering bootloader fastboot. The tool
validates the GPT and exact partition sizes without another firmware backup.
The install ZIP includes the complete instructions.
