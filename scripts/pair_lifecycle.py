#!/usr/bin/env python3
"""Complete an existing byte-matched pair with common runtime/test machinery.
Private output only, no SSH, package install, daemon, or service execution.
"""
import argparse,hashlib,json,os,shutil,tarfile
from pathlib import Path
BASE='/opt/dns-evaluation/20261016-rc1'
HERE=Path(__file__).resolve().parents[1]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--pair',type=Path,required=True);p.add_argument('--controller',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();os.umask(0o077)
 a.output.mkdir(parents=True,mode=0o700,exist_ok=False);o=a.output
 for x in ('config','state-native','state-compose'):shutil.copytree(a.pair/x,o/x)
 for x in ('bin','root','empty-certs'):shutil.copytree(a.pair/'native-payload'/x,o/x)
 shutil.copyfile(a.controller,o/'bin/dnsctl');(o/'bin/dnsctl').chmod(0o755)
 for x in ('compose.yaml','image-identities.json'):shutil.copyfile(a.pair/x,o/x)
 ids=json.loads((o/'image-identities.json').read_text());(o/'aux-image-id').write_text(ids['auxiliary']+'\n');(o/'coredns-image-id').write_text(ids['coredns']+'\n')
 shutil.copyfile(HERE/'runtime/pilot.sh',o/'pilot.sh');(o/'pilot.sh').chmod(0o755)
 # Native state uses a bind at BASE/state, exactly the path presented in Compose.
 # The bounded test operator prepares this mount before start and removes it after stop.
 instances={};env={'SSL_CERT_FILE':BASE+'/root/etc/ssl/certs/ca-certificates.crt','SSL_CERT_DIR':BASE+'/empty-certs','SKIP_SYSTEM_IPV6_CHECK':'1'}
 def instance(name,command):instances[name]={'command':command,'user':'nobody','group':'nogroup','env':env,'limits':{'nofile':'2048'},'term_timeout':10,'stdout':True,'stderr':True,'no_new_privs':True}
 instance('transport',[BASE+'/bin/mihomo','-d',BASE+'/state/mihomo','-f',BASE+'/config/mihomo.yaml'])
 for lane in ('g1','g2','g3','d1'):instance(lane,[BASE+'/root/lib/ld-musl-aarch64.so.1','--library-path',BASE+'/root/usr/lib:'+BASE+'/root/lib',BASE+'/root/usr/sbin/unbound','-d','-c',BASE+'/config/unbound-'+lane+'.conf'])
 instance('dispatcher',[BASE+'/bin/coredns','-conf',BASE+'/config/Corefile'])
 (o/'native-services.json').write_text(json.dumps({'name':'dns-evaluation','instances':instances},indent=2)+'\n')
 # Same bounded readiness workload, including both families and both transports.
 probes=[]
 for addr in ['127.0.0.1:6053','[::1]:6053']:
  for net in ['udp','tcp']:
   for name,kind,code,ad,answers in [('not-present.home.arpa',28,3,False,0),('cloudflare.com',1,0,True,1),('dnssec-failed.org',1,2,False,0),('www.baidu.com',1,0,False,1)]:probes.append({'address':addr,'network':net,'name':name,'type':kind,'rcode':code,'ad':ad,'min_answers':answers})
 (o/'readiness.json').write_text(json.dumps(probes,indent=2)+'\n')
 # Existing Compose refers to native-payload only for its CA bind; provide the same payload layout.
 (o/'native-payload/root/etc/ssl/certs').mkdir(parents=True)
 shutil.copyfile(o/'root/etc/ssl/certs/ca-certificates.crt',o/'native-payload/root/etc/ssl/certs/ca-certificates.crt')
 (o/'native-payload/empty-certs').mkdir()
 files=[x for x in o.rglob('*') if x.is_file() and not any(q.startswith('state-') for q in x.relative_to(o).parts)]
 (o/'pilot.SHA256SUMS').write_text(''.join(sha(f)+'  '+str(f.relative_to(o))+'\n' for f in sorted(files)))
 (o/'review.json').write_text(json.dumps({'status':'review-candidate','controller_sha256':sha(o/'bin/dnsctl'),'same_payload_policy_workload':True,'native_state_mount':BASE+'/state-native -> '+BASE+'/state','compose_state_mount':'per-lane independent binds','router_execution':False,'mutable_state_excluded_from_immutable_hashes':True,'readiness_is_not_acceptance':True},indent=2)+'\n')
 # Archive ownership is explicit; off-router files stay owned by the user.
 with tarfile.open(str(o)+'.tar.gz','w:gz') as tf:
  for f in sorted(o.rglob('*')):
   rel=str(f.relative_to(o));info=tf.gettarinfo(str(f),rel);info.uid=65534 if rel.startswith('state-') else 0;info.gid=65534;info.uname=info.gname='';info.mtime=0
   if f.is_dir():info.mode=0o750
   elif rel.startswith('bin/') or rel.startswith('root/') and f.stat().st_mode&0o111 or rel=='pilot.sh':info.mode=0o755
   else:info.mode=0o640
   if f.is_file():
    with f.open('rb') as data:tf.addfile(info,data)
   else:tf.addfile(info)
 print(json.dumps({'files':len(files),'controller_sha256':sha(o/'bin/dnsctl'),'router_execution':False}))
if __name__=='__main__':main()
