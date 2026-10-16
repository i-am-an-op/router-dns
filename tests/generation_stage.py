#!/usr/bin/env python3
"""Verify real private generations on temporary copies and keys, never on routers."""
import argparse,base64,hashlib,json,os,shutil,subprocess,tempfile
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
p=argparse.ArgumentParser(description=__doc__)
for n in ['candidates','controller','native-baseline','compose-baseline','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();os.umask(0o077);rows=[]
with tempfile.TemporaryDirectory(prefix='dns-real-generation-fixture-') as d:
 root=Path(d);host=root/'host';(host/'lib/apk/db').mkdir(parents=True);(host/'etc/apk').mkdir(parents=True)
 key=Ed25519PrivateKey.generate();pub=root/'TEST-ONLY.pub';pub.write_bytes(base64.b64encode(key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)))
 def baseline(src):
  for f,t in [('package-database.txt','lib/apk/db/installed'),('world.txt','etc/apk/world')]:shutil.copyfile(src/f,host/t)
 for candidate in sorted(a.candidates.iterdir()):
  src=candidate/'generation'
  if not src.is_dir():continue
  m=json.loads((src/'manifest.json').read_text());temp=root/candidate.name;shutil.copytree(src,temp);(temp/'review.sig').write_bytes(base64.b64encode(key.sign((temp/'manifest.json').read_bytes())))
  correct=a.compose_baseline if m['mode']=='compose' else a.native_baseline;wrong=a.native_baseline if m['mode']=='compose' else a.compose_baseline;baseline(correct)
  def run(label,ok,operation='stage',arch='arm64'):
   cmd=[str(a.controller.resolve()),'--offline','--architecture',arch,'--host-root',str(host),'--store',str(root/(candidate.name+'-'+label)),'--key',str(pub),operation]+([str(temp)] if operation=='stage' else [])
   r=subprocess.run(cmd,capture_output=True,text=True,timeout=45);passed=(r.returncode==0)==ok
   rows.append({'candidate':candidate.name,'case':label,'passed':passed,'accepted':r.returncode==0,'manifest_sha256':hashlib.sha256((src/'manifest.json').read_bytes()).hexdigest()})
   assert passed,(candidate.name,label,r.stderr)
  run('valid-real-candidate',True);run('offline-refuses-runtime',False,'boot');run('wrong-target-architecture',False,arch='amd64')
  baseline(wrong);run('wrong-package-baseline',False);baseline(correct)
  f=temp/m['profile'];original=f.read_bytes();f.write_bytes(original+b'\n');run('corrupt-signed-payload',False);f.write_bytes(original)
  f=temp/m['core'];f.unlink();run('missing-core-payload',False)
assert rows, 'No candidate generations were tested'
r={'scope':'real released controller and real private candidate bytes, actual cryptography/file/compatibility checks; temporary copies/ephemeral signatures only; no router/runtime operation','controller_sha256':hashlib.sha256(a.controller.read_bytes()).hexdigest(),'production_signature_added':False,'passed':sum(x['passed'] for x in rows),'total':len(rows),'cases':rows}
a.output.write_text(json.dumps(r,indent=2)+'\n');print(json.dumps({'passed':r['passed'],'total':r['total'],'router_action':False}))
