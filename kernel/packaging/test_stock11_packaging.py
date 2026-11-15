# SPDX-License-Identifier: Apache-2.0
import hashlib
import json
import stat
import tempfile
import types
import unittest
from unittest.mock import patch
from pathlib import Path

from init_boot import encode_cpio,parse_cpio
import stock11_children as children
import stock11_parents as parents


def digest(data):
 return hashlib.sha256(data).hexdigest()


def entry(name,mode,data=b"",inode=1):
 return name,[inode,mode,0,0,1,123,len(data),0,0,0,0,len(name)+1,0],data


class Stock11PackagingTest(unittest.TestCase):
 def setUp(self):
  tmp=tempfile.TemporaryDirectory()
  self.addCleanup(tmp.cleanup)
  self.root=Path(tmp.name)
  self.overrides=self.root/"overrides"
  for name in children.OVERRIDES:
   path=self.overrides/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(b"new:"+name.encode())
  self.entries=[entry("dev",stat.S_IFDIR|0o755,inode=10),
                entry("dev",stat.S_IFDIR|0o755,inode=20),
                entry("lib/modules/rfkill.ko",stat.S_IFREG|0o644,b"old rfkill",30),
                entry("lib/modules/libarc4.ko",stat.S_IFREG|0o644,b"old libarc4",40),
                entry("lib/modules/keep.ko",stat.S_IFREG|0o644,b"retained module",50),
                entry("link",stat.S_IFLNK|0o777,b"/vendor/lib/modules",60),
                entry("TRAILER!!!",0,inode=0)]
  self.abi={"vendor_ramdisk/"+name:{"sha256":digest(data)} for name,_,data in self.entries}
  self.raw=encode_cpio(self.entries)

 def test_exact_two_ramdisk_modules_change_and_metadata_is_preserved(self):
  raw,names=children.replace_vendor_modules(self.raw,self.overrides,self.abi)
  actual=parse_cpio(raw)
  self.assertEqual({"lib/modules/rfkill.ko","lib/modules/libarc4.ko"},set(names))
  self.assertEqual(len(self.entries),len(actual))
  for before,after in zip(self.entries,actual):
   name,header,data=before
   if name not in names:
    self.assertEqual(before,after)
   else:
    updated=(self.overrides/"vendor_ramdisk"/name).read_bytes()
    expected=header.copy();expected[6]=len(updated)
    self.assertEqual((name,expected,updated),after)

 def test_wrong_stock_module_hash_is_refused(self):
  self.abi["vendor_ramdisk/lib/modules/rfkill.ko"]["sha256"]="0"*64
  with self.assertRaisesRegex(ValueError,"module mismatch"):
   children.replace_vendor_modules(self.raw,self.overrides,self.abi)

 def test_missing_replacement_is_refused(self):
  raw=encode_cpio([row for row in self.entries if row[0]!="lib/modules/rfkill.ko"])
  with self.assertRaisesRegex(ValueError,"scope"):
   children.replace_vendor_modules(raw,self.overrides,self.abi)

 def test_override_inventory_is_exactly_four_files(self):
  children.verify_overrides(self.overrides)
  extra=self.overrides/"extra.ko";extra.write_bytes(b"extra")
  with self.assertRaisesRegex(ValueError,"exact four"):
   children.verify_overrides(self.overrides)
  extra.unlink()
  (self.overrides/"vendor_dlkm/lib/modules/bluetooth.ko").unlink()
  with self.assertRaisesRegex(ValueError,"exact four"):
   children.verify_overrides(self.overrides)

 def test_stock_inventory_and_hashes_are_checked(self):
  rows=[]
  for name in ("dtbo","system_dlkm","vendor_dlkm","vendor_boot","vendor","odm","odm_dlkm"):
   path=self.root/"images"/(name+".img");path.parent.mkdir(exist_ok=True);data=name.encode();path.write_bytes(data)
   rows.append(dict(partition=name,bytes=len(data),sha256=digest(data)))
  manifest=self.root/"stock.json";manifest.write_text(json.dumps(rows))
  children.verify_stock_inputs(self.root,manifest)
  (self.root/"images/vendor.img").write_bytes(b"broken")
  with self.assertRaises(ValueError):children.verify_stock_inputs(self.root,manifest)
  manifest.write_text(json.dumps(rows[:-1]))
  with self.assertRaisesRegex(ValueError,"inventory"):children.verify_stock_inputs(self.root,manifest)

 def test_extraction_uses_image_and_ignores_modified_external_tree(self):
  image=self.root/"images/system_dlkm.img";image.parent.mkdir();image.write_bytes(b"verified image bytes")
  external=self.root/"content/system_dlkm";external.mkdir(parents=True)
  (external/"unchanged.ko").write_bytes(b"modified external module")
  destination=self.root/"private-work/system_dlkm";destination.parent.mkdir()
  def decode(arguments,check):
   self.assertTrue(check)
   self.assertEqual(str(image),arguments[-1])
   self.assertIn("--extract="+str(destination),arguments)
   destination.mkdir()
   (destination/"unchanged.ko").write_bytes(image.read_bytes())
  with patch.object(children.subprocess,"run",side_effect=decode) as tool:
   children.extract_tree(image,destination,"fsck.erofs",digest(image.read_bytes()))
   tool.assert_called_once()
  self.assertEqual(b"verified image bytes",(destination/"unchanged.ko").read_bytes())
  self.assertEqual(b"modified external module",(external/"unchanged.ko").read_bytes())

 def test_extraction_rejects_corrupt_image_and_changed_source(self):
  image=self.root/"system.img";image.write_bytes(b"verified")
  destination=self.root/"extracted"
  with patch.object(children.subprocess,"run") as tool:
   with self.assertRaisesRegex(ValueError,"hash mismatch"):
    children.extract_tree(image,destination,"fsck.erofs","0"*64)
   tool.assert_not_called()
  def change_source(arguments,check):
   destination.mkdir();image.write_bytes(b"changed")
  with patch.object(children.subprocess,"run",side_effect=change_source):
   with self.assertRaisesRegex(ValueError,"hash mismatch"):
    children.extract_tree(image,destination,"fsck.erofs",digest(b"verified"))

 def test_kernel_receipt_binds_release_source_and_artifacts(self):
  workspace=self.root/"workspace";dist=workspace/"dist";dist.mkdir(parents=True)
  release=dist/"include/config/kernel.release";release.parent.mkdir(parents=True)
  release.write_text("6.12.58-LDY-AN00-android16-6-gabcdef-4k")
  artifacts={}
  for name in ("Image","Image.lz4","vmlinux","kernel_aarch64_dot_config","Module.symvers"):
   data=name.encode();(dist/name).write_bytes(data);artifacts[name]=dict(bytes=len(data),sha256=digest(data))
  proof=dict(kernel_release=release.read_text(),source_commit="qualified",source_tree="tree",
             reference_artifacts=artifacts)
  receipt=self.root/"kernel.json";receipt.write_text(json.dumps(proof))
  with patch.object(children.subprocess,"check_output",side_effect=["qualified\ntree\n",""]):
   children.verify_kernel_receipt(workspace,dist,receipt)
  with patch.object(children.subprocess,"check_output",side_effect=["other\ntree\n",""]):
   with self.assertRaisesRegex(ValueError,"source identity"):
    children.verify_kernel_receipt(workspace,dist,receipt)
  (dist/"Image").write_bytes(b"other")
  with patch.object(children.subprocess,"check_output",side_effect=["qualified\ntree\n",""]):
   with self.assertRaisesRegex(ValueError,"hash mismatch"):
    children.verify_kernel_receipt(workspace,dist,receipt)
  release.write_text("6.12.38-LDY-AN00")
  with self.assertRaisesRegex(ValueError,"release"):
   children.verify_kernel_receipt(workspace,dist,receipt)

 def test_raw_radio_copy_does_not_modify_or_resign(self):
  source=self.root/"modem.img";data=b"opaque OEM-signed radio image";source.write_bytes(data)
  target=self.root/"copied.img"
  report=parents.copy_raw(source,target,digest(data))
  self.assertEqual(data,target.read_bytes())
  self.assertFalse(report["resigned"])
  with self.assertRaisesRegex(ValueError,"overwrite"):
   parents.copy_raw(source,target,digest(data))
  with self.assertRaisesRegex(ValueError,"hash mismatch"):
   parents.copy_raw(source,self.root/"bad.img","0"*64)
  self.assertFalse((self.root/"bad.img").exists())

 def test_only_required_parent_chain_keys_change(self):
  class Chain:
   def __init__(self,name,key):
    self.partition_name=name;self.public_key=key;self.rollback_index_location=7
  avb=types.SimpleNamespace(AvbChainPartitionDescriptor=Chain)
  keep=Chain("vbmeta_odm",b"OEM")
  records=[Chain(name,b"OEM") for name in ("vendor_boot","vbmeta_vendor_dlkm","init_boot")]
  property_record=object()
  descriptors=records+[keep,property_record]
  changed=parents.update_chain_keys(avb,descriptors,b"project")
  self.assertEqual(["vendor_boot","vbmeta_vendor_dlkm","init_boot"],changed)
  self.assertTrue(all(record.public_key==b"project" for record in records))
  self.assertEqual(b"OEM",keep.public_key)
  self.assertIs(property_record,descriptors[-1])
  self.assertTrue(all(record.rollback_index_location==7 for record in records+[keep]))
  self.assertEqual([],parents.update_chain_keys(avb,descriptors,b"project"))


if __name__=="__main__":
 unittest.main()
