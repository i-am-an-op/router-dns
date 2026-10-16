#!/usr/bin/env python3
"""Workstation fixture adapter. No router paths, credentials or installation.
Run from RootlessKit's disposable user/mount/network namespace. Identical native
and Compose DNS payloads share fixture files; UID/GID are 65534 in both modes.
"""
import json,os,re,subprocess,sys
from pathlib import Path
mode=os.environ['DNS_PAIR_MODE'];component=Path(sys.argv[0]).name.split('-')[-1]
root=Path(os.environ['DNS_PAIR_ROOTFS']);args=sys.argv[1:]
# Every mutable pathname must remain inside a generated fixture root.
paths=[Path(x) for x in args if x.startswith('/tmp/')]
assert paths
fixture=next(p for p in [paths[0],*paths[0].parents] if p.parent==Path('/tmp'))
assert re.fullmatch(r'(dns-policy-lab|dns-lab|official-dns-regression|managed-api)-[A-Za-z0-9_-]+',fixture.name),fixture
for p in [fixture,*fixture.rglob('*')]:
 if p.is_dir():p.chmod(0o777)
 elif p.is_file():p.chmod(0o644)
# Mihomo creates its state directory and may need it before the executable runs.
if '-d' in args and component=='mihomo':
 d=Path(args[args.index('-d')+1]);d.mkdir(exist_ok=True,parents=True);d.chmod(0o777)
if component=='unbound':
 inside=['/usr/bin/qemu-aarch64','/arm/lib/ld-musl-aarch64.so.1','--library-path','/arm/usr/lib:/arm/lib','/arm/usr/sbin/unbound']
 native=['/usr/bin/qemu-aarch64',str(root/'arm/lib/ld-musl-aarch64.so.1'),'--library-path',str(root/'arm/usr/lib')+':'+str(root/'arm/lib'),str(root/'arm/usr/sbin/unbound')]
else:inside=['/bin/'+component];native=[str(root/'bin'/component)]
if mode=='native':os.execvp('setpriv',['setpriv','--reuid=65534','--regid=65534','--clear-groups',*native,*args])
assert mode=='compose'
service={'image':os.environ['DNS_PAIR_IMAGE'],'pull_policy':'never','network_mode':'host','userns_mode':'host','user':'65534:65534','read_only':True,'cap_drop':['ALL'],'security_opt':['no-new-privileges:true'],'entrypoint':inside,'command':args,'environment':{k:os.environ[k] for k in ['SKIP_SYSTEM_IPV6_CHECK','MIHOMO_MANAGED_DNS','SSL_CERT_FILE','SSL_CERT_DIR'] if k in os.environ},'volumes':[{'type':'bind','source':str(fixture),'target':str(fixture),'bind':{'create_host_path':False}}],'tmpfs':['/tmp-runtime:rw,nosuid,nodev,noexec,size=8m'],'restart':'no'}
# Give each process a unique Compose project to retain separate lifecycle logs.
project='dnsfixture'+str(os.getpid());cfg=fixture/(project+'.json');cfg.write_text(json.dumps({'name':project,'services':{'resolver':service}}));cfg.chmod(0o644)
os.execvp('docker',['docker','compose','--env-file','/dev/null','-f',str(cfg),'run','--rm','--no-deps','--quiet','resolver'])
