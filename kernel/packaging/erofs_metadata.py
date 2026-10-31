# SPDX-License-Identifier: Apache-2.0
import pathlib, struct, stat, uuid

def metadata(p):
 b=pathlib.Path(p).read_bytes();s=b[1024:1152];bs=1<<s[12];base=struct.unpack_from('<I',s,40)[0]*bs;xb=struct.unpack_from('<I',s,44)[0]*bs;bt=struct.unpack_from('<Q',s,24)[0];root=struct.unpack_from('<H',s,14)[0];rows=[]
 def u(fmt,o):return struct.unpack_from('<'+fmt,b,o)
 def inode(n,path):
  off=base+n*32;fmt,xc,mode=u('HHH',off);ext=fmt&1;sz=u('Q' if ext else 'I',off+8)[0];raw=u('I',off+16)[0];uid,gid=u('II' if ext else 'HH',off+24);mt=u('Q',off+32)[0] if ext else bt;ns=u('I',off+40)[0] if ext else struct.unpack_from('<I',s,32)[0];links=u('I',off+44)[0] if ext else u('H',off+6)[0];isz=64 if ext else 32;xs=12+(xc-1)*4 if xc else 0;attrs={}
  def attr(pos):
   nl,ni,vl=u('BBH',pos);assert ni in (1,2,3,4,5,6),ni;name={1:'user.',2:'system.posix_acl_access',3:'system.posix_acl_default',4:'trusted.',5:'lustre.',6:'security.'}[ni]+b[pos+4:pos+4+nl].decode();val=b[pos+4+nl:pos+4+nl+vl];attrs[name]=val.hex();return (4+nl+vl+3)&~3
  if xs:
   xp=off+isz;sc=b[xp+4];cursor=xp+12+sc*4
   for i in range(sc):attr(xb+u('I',xp+12+i*4)[0]*4)
   while cursor<xp+xs:cursor+=attr(cursor)
  row=dict(path=path,mode=mode,uid=uid,gid=gid,mtime=mt,mtime_nsec=ns,nlink=links,xattrs=attrs);rows.append(row)
  layout=(fmt>>1)&7
  def content():
   assert layout in (0,2),(path,layout)
   full=sz//bs*bs
   return b[raw*bs:raw*bs+(sz if layout==0 else full)]+(b[off+isz+xs:off+isz+xs+sz%bs] if layout==2 else b'')
  if stat.S_ISDIR(mode):
   d=content()
   for start in range(0,len(d),bs):
    block=d[start:start+bs];cnt=struct.unpack_from('<H',block,8)[0]//12
    for i in range(cnt):
     nid,no,typ=struct.unpack_from('<QHB',block,i*12);end=struct.unpack_from('<H',block,(i+1)*12+8)[0] if i+1<cnt else len(block);name=block[no:end].split(b'\0',1)[0].decode()
     if name not in ('.','..'):inode(nid,path+'/'+name if path else name)
  elif stat.S_ISLNK(mode):row['target']=content().decode()
  return row
 inode(root,'');return {'block_size':bs,'compat':struct.unpack_from('<I',s,8)[0],'incompat':struct.unpack_from('<I',s,80)[0],'uuid':str(uuid.UUID(bytes=s[48:64])),'build_time':bt,'blocks':struct.unpack_from('<I',s,36)[0],'inodes':sorted(rows,key=lambda x:x['path'])}
