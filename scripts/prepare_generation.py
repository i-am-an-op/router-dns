#!/usr/bin/env python3
"""Prepare concrete private generation plans using verified payloads, no live work.
The resulting manifest is unsigned. Review key/activation remain separate decisions.
"""
import argparse,hashlib,json,os,shutil,subprocess
from pathlib import Path
import yaml
HERE=Path(__file__).resolve().parents[1];BASE='/opt/dns-evaluation/20261016-rc1'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
p=argparse.ArgumentParser(description=__doc__)
for n in ['pair','overlay','baseline','frontend','core','controller','receipt','bundle','output']:p.add_argument('--'+n,type=Path,required=True)
p.add_argument('--mode',choices=['native','compose'],required=True);p.add_argument('--transport',choices=['shared','separate'],required=True);p.add_argument('--id',required=True);a=p.parse_args();os.umask(0o077)
a.output.mkdir(parents=True,exist_ok=False,mode=0o700);prepared=a.output/'inputs';prepared.mkdir()
copy=[];mounts=[]
def add(src,rel,mode=0o644,target=None):
 copy.append({'source':str(src.resolve()),'path':rel,'mode':mode})
 if target:mounts.append({'source':rel,'target':target})
add(a.core,'bin/clash_meta',0o755,'/etc/openclash/core/clash_meta');add(a.frontend,'config/frontend.yaml',0o600)
for f in (HERE/'runtime').glob('*'):
 if f.is_file():add(f,'runtime/'+f.name,0o755)
for row in json.loads((a.overlay/'overlay.json').read_text())['files']:
 rel=row['path'];add(a.overlay/rel,'overlay/'+rel,0o644 if rel.endswith('.lua') else 0o755,'/'+rel)
# Entire common added-stack payload/config is generation-owned; mutable state is
# deliberately excluded. Both modes expose the same targets for whole rollback.
for tree in ['bin','root','config']:
 for f in sorted((a.pair/tree).rglob('*')):
  if f.is_file():
   rel=str(f.relative_to(a.pair));src=f
   if rel=='config/Corefile':
    src=prepared/'Corefile';text=f.read_text().replace('bind 127.0.0.1 ::1','bind 127.0.0.1 ::1 192.168.2.2');src.write_text(text)
   add(src,'stack/'+rel,0o755 if f.stat().st_mode&0o111 else 0o644,BASE+'/'+rel)
add(a.pair/'root/etc/ssl/certs/ca-certificates.crt','stack/compose-ca.crt',0o644,BASE+'/native-payload/root/etc/ssl/certs/ca-certificates.crt')
# Root-only native integration/API credential stays outside world-readable stack.
front=yaml.safe_load(a.frontend.read_text());secret=front.get('secret','');controller=front.get('external-controller','127.0.0.1:9090')
if '\n' in secret or '\r' in secret:raise SystemExit('invalid controller credential')
if controller.startswith('0.0.0.0:'):controller='127.0.0.1:'+controller.split(':')[-1]
api=prepared/'api-check.curl';api.write_text('url = '+json.dumps('http://'+controller+'/configs')+'\nrequest = "PATCH"\nheader = '+json.dumps('Authorization: Bearer '+secret)+'\nheader = "Content-Type: application/json"\ndata = "{}"\n')
add(api,'config/api-check.curl',0o600)
for n in ['root-seed.key','dns-integrity.nft']:
 add(a.pair/'config/root-seed.key' if n=='root-seed.key' else HERE/'runtime/dns-integrity.nft','config/'+n)
for n in ['aux-image-id','coredns-image-id']:add(a.pair/n,'config/'+n)
compose=yaml.safe_load((a.pair/'compose.yaml').read_text());native=json.loads((a.pair/'native-services.json').read_text())
if a.transport=='shared':
 compose['services'].pop('transport');native['instances'].pop('transport')
 for s in compose['services'].values():s.get('depends_on',{}).pop('transport',None)
for s in compose['services'].values():s['restart']='on-failure:3'
for s in native['instances'].values():s['respawn']=[300,5,3]
for name,value,writer in [('compose.yaml',compose,lambda v:yaml.safe_dump(v,sort_keys=False)),('native-services.json',native,lambda v:json.dumps(v,indent=2)+'\n')]:
 dest=prepared/name;dest.write_text(writer(value));add(dest,'config/'+name,0o600)
add(HERE/'runtime/dns-integrity.nft','overlay/dns-integrity.nft',0o644,'/usr/share/nftables.d/ruleset-post/90-dns-core-integrity.nft')
plan={'id':a.id,'architecture':'arm64','openclash':'0.48.002','mode':a.mode,'transport':a.transport,'core':'bin/clash_meta','profile':'config/frontend.yaml','adapter':'runtime/adapter.sh','probe_seconds':60,'copy':copy,'mounts':mounts,'host_pins':[{'path':'/lib/apk/db/installed','sha256':sha(a.baseline/'package-database.txt')},{'path':'/etc/apk/world','sha256':sha(a.baseline/'world.txt')}],'readiness':json.loads((a.pair/'readiness.json').read_text())}
planfile=a.output/'plan.json';planfile.write_text(json.dumps(plan,indent=2)+'\n')
subprocess.run(['python3',str(HERE/'scripts/assemble_generation.py'),'--plan',str(planfile),'--output',str(a.output/'generation'),'--controller',str(a.controller),'--receipt',str(a.receipt),'--bundle',str(a.bundle)],check=True)
print(json.dumps({'generation':a.id,'mode':a.mode,'transport':a.transport,'unsigned':True,'mount_targets':len(mounts),'router_action':False}))
