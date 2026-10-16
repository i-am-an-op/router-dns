#!/usr/bin/env python3
# Bounded off-router TLS/NTS-KE probe, never adjusts any clock or writes cookies.
import argparse,concurrent.futures,json,socket,ssl,struct,time,hashlib
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--seeds',type=Path,required=True);p.add_argument('--ca',type=Path,required=True);p.add_argument('--output',type=Path,required=True);args=p.parse_args();ca=args.ca;seeds=json.loads(args.seeds.read_text())['seeds']
def probe(item):
 name,addr=item;start=time.monotonic();r={'hostname':name,'seed_address':addr,'pass':False}
 try:
  ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT);ctx.load_verify_locations(cafile=str(ca));ctx.minimum_version=ssl.TLSVersion.TLSv1_3;ctx.set_alpn_protocols(['ntske/1']);deadline=start+7
  with socket.create_connection((addr,4460),timeout=5) as raw,ctx.wrap_socket(raw,server_hostname=name) as s:
   s.settimeout(max(.1,deadline-time.monotonic()));assert s.selected_alpn_protocol()=='ntske/1';r.update(tls=s.version(),certificate_sha256=hashlib.sha256(s.getpeercert(binary_form=True)).hexdigest(),authenticated_hostname=True)
   s.sendall(struct.pack('!HHHHHHHH',0x8001,2,0,0x8004,2,15,0x8000,0));data=b'';records=[]
   def read(n):
    out=b''
    while len(out)<n:
     s.settimeout(max(.1,deadline-time.monotonic()));chunk=s.recv(n-len(out))
     if not chunk:raise ValueError('early EOF')
     out+=chunk
    return out
   for i in range(64):
    kind,length=struct.unpack('!HH',read(4));payload=read(length);typ=kind&0x7fff;assert typ!=2,'NTS-KE error';assert not (kind&0x8000 and typ>7),'unknown critical record';records.append((typ,payload))
    if typ==0:
     assert kind==0x8000 and length==0;break
   else:raise ValueError('record limit exceeded')
   assert [p for t,p in records if t==1]==[b'\x00\x00'];assert [p for t,p in records if t==4]==[b'\x00\x0f'];cookies=sum(t==5 for t,p in records);assert cookies>0
   r.update({'pass':True,'ntp_protocol':0,'aead':15,'cookie_count':cookies,'cookies_retained':False})
 except Exception as e:r['failure_type']=type(e).__name__;r['error']=str(e)[:180]
 r['elapsed_seconds']=round(time.monotonic()-start,3);return r
with concurrent.futures.ThreadPoolExecutor(max_workers=6) as ex:results=list(ex.map(probe,[(n,a) for n,aa in seeds.items() for a in aa]))
r={'scope':'off-router numeric TCP4460 using supplied CA and current workstation time, original TLS identity and NTS-KE; underlying application routing uncontrolled; no NTP/time change/cookie retention/router action','rfc':'RFC8915 sections3,4.1.1,4.1.2,4.1.5,4.1.6','ca_sha256':hashlib.sha256(ca.read_bytes()).hexdigest(),'results':results,'passed':sum(x['pass'] for x in results),'total':len(results)}
args.output.write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r,indent=2))
