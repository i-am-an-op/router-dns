#!/usr/bin/env python3
"""Exact pinned-toolchain double build plus source/identity inventory; no publish."""
import hashlib,json,os,subprocess,tempfile
from pathlib import Path

def run(*a):return subprocess.check_output(a,text=True).strip()
pin=json.loads(Path('release.json').read_text());assert run('go','env','GOVERSION')=='go'+pin['go']
subprocess.run(['git','diff','--exit-code'],check=True)
commit=run('git','rev-parse','HEAD');arch=run('go','env','GOARCH');version=pin['version']+'+'+commit[:12]
flags=['-trimpath','-buildvcs=false','-ldflags','-buildid= -s -w -X main.version='+version]
env={**os.environ,'CGO_ENABLED':'0','GOTOOLCHAIN':'local','GOFLAGS':'','GOEXPERIMENT':''}
out=Path('dist');out.mkdir(exist_ok=True);binary=out/('dnsctl-linux-'+arch)
subprocess.run(['go','build',*flags,'-o',str(binary),'./cmd/dnsctl'],env=env,check=True)
with tempfile.TemporaryDirectory() as d:
 other=Path(d)/'dnsctl';subprocess.run(['go','build',*flags,'-o',str(other),'./cmd/dnsctl'],env=env,check=True);assert binary.read_bytes()==other.read_bytes()
subprocess.run(['git','archive','--format=tar.gz','-o',str(out/('source-'+arch+'.tar.gz')),'HEAD'],check=True)
(out/('build-'+arch+'.json')).write_text(json.dumps({'repository':pin['repository'],'source_commit':commit,'version':version,'go':run('go','version'),'arch':arch,'sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'go_sum_sha256':hashlib.sha256(Path('go.sum').read_bytes()).hexdigest(),'reproducible_on_same_runner':True,'independent_builder':False},indent=2)+'\n')
(out/('SHA256SUMS-'+arch)).write_text(''.join(hashlib.sha256(f.read_bytes()).hexdigest()+'  '+f.name+'\n' for f in sorted(out.iterdir()) if not f.name.startswith('SHA256SUMS')))
