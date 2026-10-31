# SPDX-License-Identifier: Apache-2.0
import unittest
from types import SimpleNamespace
from pathlib import Path
import postinstall_policy as policy


class PostinstallPolicyTest(unittest.TestCase):
    def test_exact_config(self):
        policy.validate_config(dict(policy.EXPECTED))
        policy.validate_config({})

    def test_missing_wrong_or_extra_metadata_refused(self):
        for key in policy.EXPECTED:
            for mode in ("missing", "wrong"):
                with self.subTest(key=key, mode=mode):
                    rows = dict(policy.EXPECTED)
                    if mode == "missing": del rows[key]
                    else: rows[key] = "unexpected"
                    with self.assertRaisesRegex(ValueError, "postinstall hooks"):
                        policy.validate_config(rows)
        for key in ["RUN_POSTINSTALL_vendor", "POSTINSTALL_PATH_boot"]:
            rows = dict(policy.EXPECTED); rows[key] = "false"
            with self.assertRaises(ValueError): policy.validate_config(rows)

    def test_exact_payload(self):
        part = SimpleNamespace(partition_name="system", run_postinstall=True,
                postinstall_path="system/bin/otapreopt_script", filesystem_type="ext4",
                postinstall_optional=True)
        policy.validate_partition(part)
        for key, value in [("partition_name", "vendor"), ("partition_name", "boot"),
                ("run_postinstall", False), ("postinstall_path", "../evil"),
                ("postinstall_path", "system/bin/backuptool_postinstall.sh"),
                ("filesystem_type", "erofs"), ("postinstall_optional", False)]:
            with self.subTest(key=key, value=value):
                wrong = SimpleNamespace(**vars(part)); setattr(wrong, key, value)
                with self.assertRaises(ValueError): policy.validate_partition(wrong)

    def test_no_hook_keeps_legacy_payload_compatible(self):
        policy.validate_partition(SimpleNamespace(partition_name="system", run_postinstall=False,
            postinstall_path="", filesystem_type="", postinstall_optional=False))


if __name__ == "__main__": unittest.main()
