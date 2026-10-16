#!/usr/bin/env python3
"""Verify the locally built auxiliary image archive against its reviewed context."""
import os
import hashlib
import io
import json
from pathlib import Path
import tarfile

ROOT=Path(__file__).resolve().parents[1]
pair=Path(os.environ.get('DNS_IMAGE_PAIR',str(ROOT/'.private/mt6000-deployment-pair-20261016-r2')))
output=Path(os.environ.get('DNS_IMAGE_OUTPUT',str(ROOT/'.work/paired-images')))
archive=output/'aux-offline.tar'
expected=json.loads((pair/'payload-sha256.json').read_text())
inspect=json.loads((output/'aux-inspect.json').read_text())[0]
files={};modes={}
with tarfile.open(archive) as outer:
    m=json.load(outer.extractfile('manifest.json'))[0]
    cfg=outer.extractfile(m['Config']).read();config=json.loads(cfg)
    image_id='sha256:'+hashlib.sha256(cfg).hexdigest()
    assert image_id==inspect['Id']
    for i,name in enumerate(m['Layers']):
        blob=outer.extractfile(name).read()
        assert 'sha256:'+hashlib.sha256(blob).hexdigest()==config['rootfs']['diff_ids'][i]
        with tarfile.open(fileobj=io.BytesIO(blob)) as layer:
            for f in layer:
                if f.isfile():
                    n=f.name.removeprefix('./').lstrip('/')
                    assert '.wh.' not in n
                    files[n]=hashlib.sha256(layer.extractfile(f).read()).hexdigest()
                    modes[n]=f.mode
    assert files==expected, 'Image must contain exactly the whitelisted runtime files'
    assert config['architecture']=='arm64' and config['os']=='linux'
    assert config['config']['User']=='65534:65534'
    assert config['config']['Entrypoint']==['/opt/dns-evaluation/20261016-rc1/bin/mihomo']
    for name in ['bin/mihomo','root/lib/ld-musl-aarch64.so.1','root/usr/sbin/unbound','root/usr/sbin/unbound-checkconf','root/usr/bin/drill']:
        assert modes['opt/dns-evaluation/20261016-rc1/'+name] & 0o111
record={'image_id':image_id,'architecture':config['architecture'],
 'archive_sha256':hashlib.sha256(archive.read_bytes()).hexdigest(),'archive_bytes':archive.stat().st_size,
 'exact_payload_files':len(files),'unexpected_files':0,'entrypoint_and_loader_modes_verified':True,
 'dockerfile_sha256':hashlib.sha256((pair/'image-context/Dockerfile').read_bytes()).hexdigest(),
 'builder':'Existing workstation Docker 29.9.0 integrated BuildKit; COPY-only scratch build, linux/arm64, offline isolated namespaces',
 'image_built':True,'payload_verified':True,'workload_executed':False,
 'provenance_limit':'Local build/manifest evidence, not a published or independently attested release. License inventory and image advisory triage remain release gates.',
 'initial_build_failure':'Deprecated legacy builder produced amd64 intermediate metadata during arm64 build; normal BuildKit path succeeded without source/binary changes'}
(output/'verification.json').write_text(json.dumps(record,indent=2)+'\n')
(pair/'image-identities.json').write_text(json.dumps({'auxiliary':image_id,'coredns':'sha256:5d3b3e589fcf57f626c7967bff5171924cf9c55068911247a1f7bd2458e726c3'},indent=2)+'\n')
manifest=json.loads((pair/'manifest.json').read_text());manifest['image_build_executed']=True;manifest['image_identities']=json.loads((pair/'image-identities.json').read_text());(pair/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
print(json.dumps(record,indent=2))
