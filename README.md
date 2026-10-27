# LineageOS manifest for HONOR LDY-AN00

Pinned source integration for the unofficial LineageOS 24.0 / Android 17 port.
Source codename: `ldy_an00`. Native product: `lineage_ldy_an00_native`.

## Contents

- `default.xml`: pinned upstream projects and device/vendor source repositories.
- `patches/`: device adaptations against exact upstream base revisions.
- `source-lock.json`: original RC3 source identities and public snapshot mapping.
- `ota/ldy_an00.json`: update feed; empty until qualified hosted releases are available.

## Source checkout

For a new Android source checkout on a suitably provisioned build machine:

```sh
repo init -u https://github.com/iodn/android_manifest_ldy_an00 -b main
repo sync -c
python3 .repo/manifests/patches/apply.py --source . --check
python3 .repo/manifests/patches/apply.py --source . --apply
```

The referenced source repositories/commits must be published before this checkout
can succeed. The patch runner requires clean projects at the pinned bases and
verifies patch hashes and exact resulting Git trees. It does not commit or push.
Do not sync over uncommitted applied patches; preserve changes before updating.

Device-specific IMS source is included at `device/honor/ldy_an00/ims`. Proprietary
inputs are excluded; supply the matching stock113/derived inputs described by the
device and vendor inventories. OpenEUICC's lpac/cJSON dependencies are pinned.
The reorganized source layout still requires a clean-build qualification.

## Updates and releases

The native RC3 Updater endpoint is
`https://raw.githubusercontent.com/iodn/android_manifest_ldy_an00/main/ota/ldy_an00.json`.
Keep that path stable. Publish and test signed release assets before adding an
entry; the current protocol is an array with `files[]`.

User installation instructions and release assets belong in
[lineageos_releases_ldy_an00](https://github.com/iodn/lineageos_releases_ldy_an00).

## Licensing

New standalone tools/documentation use Apache-2.0. Upstream source patches retain
their original licenses and notices; the root LICENSE does not relicense them.
