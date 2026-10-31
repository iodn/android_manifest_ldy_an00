# SPDX-License-Identifier: Apache-2.0
"""Pinned official care-map operations only; no add_missing/image builder."""
import ast,hashlib,importlib.util,logging,os,subprocess,sys,tempfile
from pathlib import Path

def need(ok,why):
    if not ok:raise ValueError(why)

def sha(p):
    with Path(p).open("rb") as f:return hashlib.file_digest(f,"sha256").hexdigest()

def check(row):
    p=Path(row["path"]);need(sha(p)==row["sha256"],"Care-map tool/source pin mismatch");return p

def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m);return m

def functions(path,names,env):
    tree=ast.parse(path.read_text());nodes=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in names]
    need(len(nodes)==len(names),"Official functions not found")
    exec(compile(ast.Module(body=nodes,type_ignores=[]),str(path),"exec"),env)

def properties(data):
    return dict(line.split("=",1) for line in data.decode().splitlines() if "=" in line and not line.startswith("#"))

def generate(system,dlkm,system_props,tools,tmp):
    need(__debug__,"Official care-map assertion gates require normal Python")
    paths={k:check(v) for k,v in tools.items()}
    module("rangelib",paths["rangelib"])
    sparse=module("sparse_img",paths["sparse_img"])
    avb=module("avbtool",paths["avbtool"])
    env=dict(os=os,tempfile=tempfile,sparse_img=sparse,avbtool=avb,
        rangelib=sys.modules["rangelib"],logger=logging.getLogger(__name__),
        PARTITIONS_WITH_CARE_MAP=("system","system_dlkm"))
    functions(paths["common"],{"IsSparseImage"},env)
    functions(paths["add_img"],{"ParseAvbFooter","GetCareMap"},env)
    before={p:sha(img) for p,img in (("system",system),("system_dlkm",dlkm))}
    extraction=tmp/"dlkm"
    cmd=[str(paths["fsck.erofs"]),"--extract="+str(extraction),"--no-preserve","--no-xattrs",str(dlkm)]
    p=subprocess.run(cmd,capture_output=True,text=True)
    need(p.returncode==0,"Exact cohort EROFS extraction failed: "+p.stderr)
    prop=extraction/"etc/build.prop";need(prop.is_file() and not prop.is_symlink(),"Missing exact DLKM build.prop")
    data=prop.read_bytes();dp=properties(data)
    sp=system_props["SYSTEM/build.prop"]
    text=[];records=[]
    for part,img,props in (("system",system,sp),("system_dlkm",dlkm,dp)):
        pair=env["GetCareMap"](part,str(img));need(pair and pair[1],"Official care-map missing partition")
        ids=["ro."+part+".build.fingerprint","ro."+part+".build.thumbprint"]
        key=next((k for k in ids if props.get(k)),None)
        key,value=(key,props[key]) if key else ("unknown","unknown")
        text+=pair+[key,value]
        records.append(dict(partition=part,ranges=pair[1],property=key,fingerprint=value,image_sha256=before[part]))
    source=tmp/"care_map.txt";binary=tmp/"care_map.pb";parsed=tmp/"care_map.parsed.txt"
    source.write_text("\n".join(text))
    commands=[cmd]
    for args in ([str(paths["generator"]),str(source),str(binary)],
                 [str(paths["generator"]),"--parse_proto",str(binary),str(parsed)]):
        p=subprocess.run(args,capture_output=True,text=True);commands.append(args)
        need(p.returncode==0,"Official care-map generator failed: "+p.stderr)
    need(binary.is_file() and binary.stat().st_size>0 and parsed.read_text()=="\n".join(text),
         "Care-map roundtrip/coverage failed")
    for part,img in (("system",system),("system_dlkm",dlkm)):need(sha(img)==before[part],"Care-map modified an image")
    result=dict(partitions=records,sha256=sha(binary),dlkm_build_prop_sha256=hashlib.sha256(data).hexdigest(),
        tools=tools,commands=commands,scope="Official footer-bounded ranges; fingerprints copied only from real files; unknown is not new identity")
    return binary.read_bytes(),data,result
