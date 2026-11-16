import io,unittest,zipfile
import os, shutil, struct
import recovery_trust as f
LZ4 = os.environ.get("LZ4") or shutil.which("lz4")
def archive(rows):
    out=b""
    for name,mode,data in [*rows,("TRAILER!!!",0,b"")]:
        raw=name.encode()+b"\0"
        values=[0,mode,0,0,1,0,len(data),0,0,0,0,len(raw),0]
        out+=b"070701"+b"".join(f"{v:08x}".encode() for v in values)+raw
        out+=bytes((-len(out))%4)
        out+=data
        out+=bytes((-len(out))%4)
    return out

def image():
    d=bytearray(8192)
    d[:8]=b"ANDROID!"
    struct.pack_into("<4I",d,8,0,4,536871324,1584)
    struct.pack_into("<I",d,40,4)
    d[4096:4100]=bytes.fromhex("02214c18")
    return bytes(d)

def rows(scope=None):
    scope=scope or f.PARTITIONS
    props="\n".join(k+"="+scope for k in f.AB_PROPERTIES).encode()
    return [("prop.default",0o100644,props),("product",0o120777,b"/system/product"),("system/product/etc/build.prop",0o100644,props)]

class TrustFinalization(unittest.TestCase):
    def fixture(self):
        return archive(rows()+[(f.TARGET,0o100644,b"old certificates"),("symlink",0o120777,b"/absolute/path")])
    def test_only_public_certificate_and_preserved_other_records(self):
        result,before,after,_=f.replace(self.fixture(),b"PUBLIC CERT")
        self.assertEqual([x[0] for x in before],[x[0] for x in after])
        for a,b in zip(before,after):
            if a[0]!=f.TARGET:self.assertEqual(a[4],b[4])
        trust=next(x[3] for x in after if x[0]==f.TARGET)
        with zipfile.ZipFile(io.BytesIO(trust)) as z:
            self.assertEqual(z.namelist(),["ota.x509.pem"])
            self.assertEqual(z.read("ota.x509.pem"),b"PUBLIC CERT")
    def test_exact_synthetic_odm_line_removed_only(self):
        rs=rows();rs[0]=(rs[0][0],rs[0][1],rs[0][2]+b"\nro.odm.build.date.utc=1794793815\nother.timestamp=7\n")
        rs += [(f.TARGET,0o100644,b"old"),("vendor/props",0o100644,b"ro.odm.build.date.utc=123\n")]
        _,before,after,proof=f.replace(archive(rs),b"CERT",1794793815,True)
        self.assertTrue(proof["removed"])
        self.assertEqual(after[0][3],before[0][3].replace(b"ro.odm.build.date.utc=1794793815\n",b""))
        self.assertEqual(before[-2][4],after[-2][4])
        self.assertEqual([a[0] for a,b in zip(before,after) if a[4]!=b[4]],["prop.default",f.TARGET])
    def test_wrong_duplicate_or_unproved_odm_rejected(self):
        for value in [b"123",b"1794793815\nro.odm.build.date.utc=1794793815"]:
            rs=rows();rs[0]=(rs[0][0],rs[0][1],rs[0][2]+b"\nro.odm.build.date.utc="+value+b"\n")
            rs += [(f.TARGET,0o100644,b"old")]
            with self.assertRaises(ValueError):f.replace(archive(rs),b"CERT",1794793815,True)
        with self.assertRaisesRegex(ValueError,"proof"):f.replace(self.fixture(),b"CERT",1794793815,False)
    @unittest.skipUnless(LZ4, "lz4 executable required")
    def test_sorted_early_scope_and_contract_late_scope_are_equivalent(self):
        import struct,subprocess
        rs=rows();ordered=",".join(sorted(f.PARTITIONS.split(",")))
        rs[0]=(rs[0][0],rs[0][1],"\n".join(k+"="+ordered for k in f.AB_PROPERTIES).encode())
        rd=subprocess.run([LZ4,"-l","-12","-c"],input=archive(rs),capture_output=True,check=True).stdout
        h=bytearray(image()[:4096]);struct.pack_into("<I",h,12,len(rd));d=bytes(h)+rd;d+=bytes((-len(d))%4096)
        f.check_image(d,LZ4)
    @unittest.skipUnless(LZ4, "lz4 executable required")
    def test_duplicate_missing_extra_partition_rejected(self):
        import struct,subprocess
        parts=f.PARTITIONS.split(",")
        for bad in [parts+[parts[0]],parts[:-1],parts+["tee"],parts[:-1]+[parts[0]]]:
            with self.subTest(scope=bad):
                rd=subprocess.run([LZ4,"-l","-12","-c"],input=archive(rows(",".join(bad))),capture_output=True,check=True).stdout
                h=bytearray(image()[:4096]);struct.pack_into("<I",h,12,len(rd));d=bytes(h)+rd;d+=bytes((-len(d))%4096)
                with self.assertRaisesRegex(ValueError,"AB scope"):f.check_image(d,LZ4)
    def test_deterministic_zip(self):
        self.assertEqual(f.owner_zip(b"cert"),f.owner_zip(b"cert"))
    def test_missing_and_duplicate_target_rejected(self):
        with self.assertRaisesRegex(ValueError,"Exactly one"):f.replace(archive(rows()),b"cert")
        with self.assertRaisesRegex(ValueError,"Duplicate"):f.replace(archive([(f.TARGET,0o100644,b"x")]*2),b"cert")
    def test_target_symlink_rejected(self):
        with self.assertRaisesRegex(ValueError,"regular"):f.replace(archive([(f.TARGET,0o120777,b"x")]),b"cert")
    @unittest.skipUnless(LZ4, "lz4 executable required")
    def test_real_legacy_lz4_image_roundtrip(self):
        import struct,subprocess
        tool=LZ4
        ramdisk=subprocess.run([tool,"-l","-12","-c"],input=self.fixture(),capture_output=True,check=True).stdout
        header=bytearray(image()[:4096]);struct.pack_into("<I",header,12,len(ramdisk))
        source=bytes(header)+ramdisk;source+=bytes((-len(source))%4096)
        result,proof=f.finalize(source,b"PUBLIC CERT",tool)
        f.check_image(result,tool)
        self.assertEqual(source[:12],result[:12]);self.assertEqual(source[16:4096],result[16:4096])
        self.assertEqual(proof["changed_cpio_entries"],[f.TARGET])
if __name__=="__main__":unittest.main()
