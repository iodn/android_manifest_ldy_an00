# LineageOS for HONOR LDY-AN00

Unofficial **LineageOS 24.0 / Android 17** for **HONOR LDY-AN00**.
This repository hosts the installation tools, build manifest and update feed.
Versioned firmware downloads are published under [Releases](https://github.com/iodn/android_manifest_ldy_an00/releases).

**Current release:** [LineageOS 24.0 - 2026-10-31](https://github.com/iodn/android_manifest_ldy_an00/releases/tag/lineage-24.0-20261031-UNOFFICIAL-ldy_an00).

Fresh installation and boot have been tested with optional Google apps.
The release is signed, and SELinux is enforcing.

## Compatibility

This release supports the following installation baseline:

| Item | Supported configuration |
| --- | --- |
| Device | HONOR LDY-AN00 (stock codename HNLDY-M) |
| Storage layout | Verified 512 GB variant |
| Tested stock baseline | 10.0.0.113(C00E100R101P1) |
| Bootloader | [Qualified LK patch](https://github.com/iodn/honor-ldy-an00-lk-unlock) installed and boot-tested on both slots |

See the [GhostLock firmware table](https://github.com/iodn/honor-ldy-an00-ghostlock#firmware-downloads-and-ghostlock-status) for vulnerable versions.
ROM installation still requires the tested baseline above.

The installer requires the exact configuration above and stops on a mismatch.
It installs the maintained kernel, Lineage Recovery and Android system, while
retaining matching stock vendor firmware. Do not bypass its checks.

The Android system security patch is **2026-10-01**; the retained vendor patch is
**2025-12-01**. The Android patch level does not describe all retained vendor
components or kernel fixes. Do not relock the bootloader or install an Honor OTA over this
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
partitions. It keeps one stock recovery set and preserves your patched LK,
vendor firmware and calibration/security partitions.

## Optional Google apps

Google apps are not included. Use an **Android 17 / ARM64** package listed in
the [LineageOS guide](https://wiki.lineageos.org/gapps/). Verify its download
against the package publisher's checksum.

Run `bash flash.sh --reboot-recovery` instead of `bash flash.sh`. In recovery,
select **Apply update > Apply from ADB**, then run:

```sh
adb sideload <google-apps-package>.zip
```

Confirm the prompt for the verified add-on package, then select **Reboot system**.
Install Google apps **before the first Android boot**; adding them later requires
a factory reset. This release disables runtime filesystem verification globally
to support recovery add-ons.
Reported green/locked boot properties do not establish stock verified-boot security.

## Updates

After a compatible native installation, updates will use
**Settings > System > Updater**. A reboot is required to run the new version;
Virtual A/B merge completes afterward. Do not switch slots manually after merge.
The initial installer is not an OTA ZIP. The feed remains empty until a
compatible signed OTA package has passed testing.

## Source

| Repository | Purpose |
| --- | --- |
| This repository | Manifest, upstream adaptations, kernel recipes, installation tools and releases |
| [Device tree](https://github.com/iodn/android_device_honor_ldy_an00) | Device configuration and device-specific IMS integration |
| [Vendor configuration](https://github.com/iodn/android_vendor_honor_ldy_an00) | Required proprietary-input definitions and inventories |

The matching kernel source archive is included with each binary release.

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

Read-only container builds can use `tools/prepare_repo_config_cache.py` to redirect
`repo` JSON caches into the build output. Mount the generated adapter over
`.repo/repo/git_config.py` and this repository's `default.xml` as the active
manifest. Keep Android sources read-only and the output cache writable.

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
