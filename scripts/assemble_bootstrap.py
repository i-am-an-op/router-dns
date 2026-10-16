#!/usr/bin/env python3
"""Create an off-router bootstrap tree and review inventory. No router actions.
No signing key is invented. Without --review-key installation remains blocked.
"""
import argparse,hashlib,json,os,shutil,tarfile
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['generation','controller','output']:p.add_argument('--'+n,type=Path,required=True)
p.add_argument('--review-key',type=Path);a=p.parse_args();os.umask(0o077)
a.output.mkdir(parents=True,exist_ok=False,mode=0o700);root=a.output/'root';root.mkdir()
HERE=Path(__file__).resolve().parents[1]
def put(src,rel,mode):
 d=root/rel;d.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(src,d);d.chmod(mode)
put(a.controller,'usr/libexec/dnsctl',0o755)
for src,dest in [('dns-core-guard','usr/libexec/dns-core-guard'),('dns-core-gate.init','etc/init.d/dns-core-gate')]:put(HERE/'runtime'/src,dest,0o755)
v=json.loads((a.generation/'manifest.json').read_text())
for m in v['mounts']:(root/m['target'].lstrip('/')).parent.mkdir(parents=True,exist_ok=True)
for d in ['etc/dns-core','opt/dns-core/generations','etc/rc.d','opt/dns-evaluation/20261016-rc1/state','opt/dns-evaluation/20261016-rc1/empty-certs','opt/dns-evaluation/20261016-rc1/native-payload/empty-certs']:(root/d).mkdir(parents=True,exist_ok=True)
if a.review_key:put(a.review_key,'etc/dns-core/review.pub',0o644)
else:(a.output/'REVIEW-KEY-REQUIRED.txt').write_text('No accepted review key. This tree cannot activate a generation. Do not replace this gate with a test key.\n')
(root/'etc/rc.d/S98dns-core-gate').symlink_to('../init.d/dns-core-gate')
# A proposed rc.d removal is recorded, never performed against the host/router.
record={'remove_after_backup':['/etc/rc.d/S99openclash'],'requires_review_key':not bool(a.review_key),'requires_signed_generation':True,'no_service_started':True,'no_router_action':True,'mount_parents':[str(x['target']) for x in v['mounts']],'controller_sha256':hashlib.sha256(a.controller.read_bytes()).hexdigest(),'generation_manifest_sha256':hashlib.sha256((a.generation/'manifest.json').read_bytes()).hexdigest()}
(a.output/'bootstrap-review.json').write_text(json.dumps(record,indent=2)+'\n')
with tarfile.open(str(a.output)+'.tar.gz','w:gz') as tf:
 for f in sorted(root.rglob('*')):
  rel=str(f.relative_to(root));info=tf.gettarinfo(str(f),rel);info.uid=0;info.gid=65534 if rel.startswith('opt/dns-evaluation/') else 0;info.uname=info.gname='';info.mtime=0
  if f.is_dir():info.mode=0o750 if rel.startswith('opt/dns-evaluation/') else 0o755
  if f.is_file():
   with f.open('rb') as data:tf.addfile(info,data)
  else:tf.addfile(info)
print(json.dumps({'bootstrap_assembled':True,'installable':False,'requires_review_key':not bool(a.review_key)}))
