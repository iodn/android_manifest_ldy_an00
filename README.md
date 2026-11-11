# LineageOS for HONOR LDY-AN00

Unofficial **LineageOS 24.0 / Android 17** for **HONOR LDY-AN00**.
This repository hosts the installation tools, build manifest and update feed.
Versioned firmware downloads are published under [Releases](https://github.com/iodn/android_manifest_ldy_an00/releases).

**First installation:** [2026-11-01 installer](https://github.com/iodn/android_manifest_ldy_an00/releases/tag/lineage-24.0-20261101-UNOFFICIAL-ldy_an00).
**Latest OTA:** [2026-11-11 update](https://github.com/iodn/android_manifest_ldy_an00/releases/tag/lineage-24.0-20261111-UNOFFICIAL-ldy_an00) (publication pending).

The November 1 installer was boot-tested with optional Google apps and enforcing
SELinux. The new OTA and kernel require their own verification; host checks do
not establish hardware qualification.

## Before you start

This release supports the following installation baseline:

| Item | Supported configuration |
| --- | --- |
| Device | HONOR LDY-AN00 (stock codename HNLDY-M) |
| Storage layout | Verified 512 GB variant |
| Tested stock baseline | 10.0.0.113(C00E100R101P1) |
| Bootloader | [Qualified LK patch](https://github.com/iodn/honor-ldy-an00-lk-unlock) installed and boot-tested on both slots |

ROM installation still requires the tested baseline above.

The installer requires the exact configuration above and stops on a mismatch.
It installs the maintained kernel, Lineage Recovery and Android system, while
retaining matching stock vendor firmware. Do not bypass its checks.

The November 1 installer has Android security patch **2026-10-01**; the new
November 11 OTA targets **2026-11-01**. The retained vendor patch remains
**2025-12-01**. The Android patch level does not describe all retained vendor
components or kernel fixes. Do not relock the bootloader or install an Honor OTA over this
installation.

- Linux x86_64 with USB access and at least 22 GB free for the stock recovery set.
- Python 3.11 or newer, OpenSSL, PyUSB and ADB.
- Authorized USB debugging and existing Android root for the read-only layout check.

Installation erases user data. Back up personal files before starting.

## First installation

Download the complete installer ZIP and `SHA256SUMS` from the
[November 1 first-install release](https://github.com/iodn/android_manifest_ldy_an00/releases/tag/lineage-24.0-20261101-UNOFFICIAL-ldy_an00).
The latest OTA ZIP is an update for an existing installation, not an installer.
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

The installed image already checks this repository's GitHub update feed through
**Settings > System > Updater**. Newer compatible releases appear after their
signed OTA package and feed entry are published. A reboot runs the new version;
Virtual A/B merge completes afterward. Do not switch slots manually after merge.

Each available update offers **Recent changes**, opening the notes for that
specific GitHub release before installation.

The first-install ZIP is for initial setup; future OTA packages are separate.
The repository and release assets must be public for normal on-device checks
and downloads.

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
requires signature and compatibility checks. State hardware-test coverage
separately; the new kernel's hardware trial is still pending.

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

[Official HONOR firmware downloads](https://github.com/iodn/honor-ldy-an00-ghostlock#firmware-downloads-and-ghostlock-status).

## Reporting a problem

Provide the build identifier and reproduction steps. Remove phone numbers,
subscriber identifiers, eSIM activation codes, credentials and personal data from
logs before sharing them. This is an unofficial project, independent of HONOR
and the LineageOS project.


## Owned-kernel OTA feed admission

The default make_feed.py invocation retains its exact system + vbmeta_system
metadata admission. It does not gain signature or kernel authorization implicitly.

The explicit owned-kernel invocation is:

    python3 tools/make_feed.py UPDATE.zip --url HTTPS_RELEASE_ASSET_URL \
      --kernel-admission REVIEWED_ADMISSION.json \
      --kernel-admission-sha256 REVIEWER_SUPPLIED_SHA256 \
      --output NEW_FEED.json

The expected admission digest must come from the release review, never the OTA.
No valid release admission is supplied with the source. No visibility, publishing,
device access or installation occurs in this tool.

The externally pinned admission uses schema ldy-kernel-ota-feed-v1 and contains:
- ota_sha256: actual final whole OTA SHA256.
- cohort: pinned existing owned-inputs JSON row; cohort_directory: exact three
  regular kernel images. Existing schema_version=1, inputs and all hash/size
  checks from kernel_cohort.cohort remain required.
- avb_proof: pinned independently reviewed cryptographic verification receipt.
- certificate: pinned public release certificate (DER identity remains CERT_SHA).
- signature_verifier: pinned official check_ota_package_signature.py.
- delta_generator: pinned official payload verifier executable.
- verifier_dependencies: pinned actual verifier runtime source closure, including
  its common.py. Dependencies must be determined from the actual chosen runtime.

A pinned file row has path, bytes, sha256. All are actual immutable artifacts,
not future placeholders. The external AVB receipt schema
ldy-owned-kernel-avb-chain-v1 has cohort_sha256, images keyed by the three
partitions (bytes, sha256), retained_parent (image pin, unchanged=true,
chains_verified=true), verified_inputs, verification_transcripts and
image_signature_verified for the exact three partitions. The release reviewer
must independently review the cryptographic commands/transcripts and retained
parent chain/key facts before authorizing this receipt digest. These fields are
not a substitute for running AVB verification; this tool rehashes that evidence
and does not implement another AVB verifier.

Admission authenticates whole ZIP and A/B payload/metadata signatures using the
official verifier and fixed public certificate. The payload must be exactly:
boot, system, system_dlkm, vbmeta_system, vbmeta_system_dlkm. Its kernel
new_partition_info hashes and sizes must equal the actual three trusted images.
The reviewed system postinstall is mandatory in FIVE mode; default TWO behavior
remains unchanged. Dynamic geometry remains the existing group size, members system and
system_dlkm only. FILE_HASH/SIZE and METADATA_HASH/SIZE are recomputed. Full
activation metadata length includes the CrAU2 signature bytes separately.

vendor_boot, init_boot, recovery, main vbmeta, LK, vendor, ODM and calibration
are outside this contract. A required expansion needs a separate reviewed
contract; it cannot be accomplished by changing the package's metadata.

Tests use synthetic images and explicit crypto boundary doubles. Their success
proves rejection/joins, not a real release's RSA/AVB verification. Actual release
signatures, module compatibility and retained parent trust remain separate
mandatory evidence. No runtime, OEM trust or universal addon.d/GApps survival
claim follows from feed admission.
