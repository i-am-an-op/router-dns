#!/usr/bin/env python3
"""Prepare equivalent native/Compose review material; no router or Docker calls.

The source pilot is frozen. Private configs are rewritten only for installation
paths, separate writable anchor directories and identical stderr logging.
No credentials enter the scratch-image build context.
"""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import tarfile
import yaml

ROOT=Path(__file__).resolve().parents[1]
BASE='/opt/dns-evaluation/20261016-rc1'
OLD='/opt/dns-pilot/20261016-rc1'
LANES=('d1','g1','g2','g3')


def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--pilot',type=Path,required=True)
    ap.add_argument('--output',type=Path,required=True)
    ap.add_argument('--mihomo',type=Path)
    ap.add_argument('--receipt',type=Path)
    a=ap.parse_args(); src=a.pilot.resolve();out=a.output.resolve()
    if ROOT/'.private' not in out.parents: raise ValueError('Private output required')
    os.umask(0o077);out.mkdir(parents=True,mode=0o700,exist_ok=False)
    assert sha(src/'bin/coredns')=='e9a0052a67f70f59a88092ce466c1605308b41db2a5e4ddffd171fe670863401'
    core=a.mihomo or src/'bin/mihomo'
    revision='ab8edef315dc565e051a809e3d19b52cc2250d40'
    if a.mihomo:
        assert a.receipt
        receipt=json.loads(a.receipt.read_text());assert receipt['cryptographic_verification'] is True and receipt['repository_id']==1421581663 and receipt['architecture']=='arm64'
        assert sha(core)==receipt['artifact_sha256'];revision=receipt['source_commit']
    else:assert sha(core)=='f612ad8190b508eeb0e6be21604b5ad17a813597d24230e4cf9cd8e428d91469'
    config=out/'config';config.mkdir()
    for f in sorted((src/'config').iterdir()):
        text=f.read_text().replace(OLD,BASE).replace('use-syslog: yes','use-syslog: no')
        for lane in LANES:
            text=text.replace('/state/anchors/'+lane+'.key','/state/anchors/'+lane+'/root.key')
        (config/f.name).write_text(text)
    native=out/'native-payload';native.mkdir()
    for name in ('bin','root'): shutil.copytree(src/name,native/name)
    shutil.copyfile(core,native/'bin/mihomo')
    (native/'empty-certs').mkdir()
    executable_paths={'bin/coredns','bin/mihomo','root/lib/ld-musl-aarch64.so.1',
        'root/usr/sbin/unbound','root/usr/sbin/unbound-checkconf','root/usr/bin/drill'}
    # Source pilot files deliberately have private staging modes. Do not infer
    # runtime executable modes from them: QEMU parsing can hide missing +x.
    for f in native.rglob('*'):
        if f.is_dir(): f.chmod(0o755)
        elif f.is_file(): f.chmod(0o755 if str(f.relative_to(native)) in executable_paths else 0o644)
    context=out/'image-context';fs=context/'rootfs';fs.mkdir(parents=True)
    installed=fs/BASE.lstrip('/');installed.mkdir(parents=True)
    # CoreDNS has a verified upstream image with the SAME executable; use it.
    # The auxiliary image contains only Unbound/libraries and maintained Mihomo.
    (installed/'bin').mkdir();shutil.copyfile(core,installed/'bin/mihomo')
    (installed/'bin/mihomo').chmod(0o755)
    shutil.copytree(src/'root',installed/'root')
    # Image has empty config/state directories; secrets and anchors are mounts.
    for name in ('config','state','empty-certs'): (installed/name).mkdir()
    (fs/'etc').mkdir();(fs/'tmp').mkdir();(fs/'tmp').chmod(0o1777)
    (fs/'etc/passwd').write_text('nobody:x:65534:65534:DNS service:/:/nonexistent\n')
    (fs/'etc/group').write_text('nogroup:x:65534:\n')
    for f in fs.rglob('*'):
        if f.is_dir(): f.chmod(0o755)
        elif f.is_file():
            relative=str(f.relative_to(installed)) if installed in f.parents else ''
            f.chmod(0o755 if relative in executable_paths else 0o644)
    (fs/'tmp').chmod(0o1777)
    dockerfile='''FROM scratch
LABEL org.opencontainers.image.title="DNS evaluation: matched verified payloads" \
      org.opencontainers.image.description="Local engineering image, not an upstream-maintained distribution; no credentials" \
      org.opencontainers.image.version="20261016-rc1" \
      org.opencontainers.image.revision="mihomo:ab8edef315dc565e051a809e3d19b52cc2250d40;unbound:13b6717f1716810523ffb60f971a6c9c5e8ce127"
COPY rootfs/ /
USER 65534:65534
WORKDIR /opt/dns-evaluation/20261016-rc1/config
ENV SSL_CERT_FILE=/opt/dns-evaluation/20261016-rc1/root/etc/ssl/certs/ca-certificates.crt
ENV SSL_CERT_DIR=/opt/dns-evaluation/20261016-rc1/empty-certs
ENTRYPOINT ["/opt/dns-evaluation/20261016-rc1/bin/mihomo"]
'''
    dockerfile=dockerfile.replace('ab8edef315dc565e051a809e3d19b52cc2250d40',revision)
    (context/'Dockerfile').write_text(dockerfile)
    (context/'.dockerignore').write_text('*\n!Dockerfile\n!rootfs\n!rootfs/**\n')
    payload={str(f.relative_to(fs)):sha(f) for f in sorted(fs.rglob('*')) if f.is_file()}
    (out/'payload-sha256.json').write_text(json.dumps(payload,indent=2)+'\n')
    # Both state sets are initial seeds, never replacements for accepted state.
    for mode in ('state-native','state-compose'):
        for lane in LANES:
            d=out/mode/'anchors'/lane;d.mkdir(parents=True)
            shutil.copyfile(config/'root-seed.key',d/'root.key')
        (out/mode/'mihomo').mkdir()
    def mount(source,target,readonly):
        return {'type':'bind','source':'${DNS_EVAL_ROOT:?Set reviewed staging root}/'+source,
                'target':BASE+'/'+target,'read_only':readonly,'bind':{'create_host_path':False}}
    common={'image':'${DNS_AUX_IMAGE:?Set verified immutable auxiliary image ID or digest}',
        'pull_policy':'never','platform':'linux/arm64','network_mode':'host','userns_mode':'host',
        'user':'65534:65534','read_only':True,'cap_drop':['ALL'],
        'security_opt':['no-new-privileges:true'],'restart':'no','stop_grace_period':'10s',
        'working_dir':BASE+'/config',
        'environment':{'SSL_CERT_FILE':BASE+'/root/etc/ssl/certs/ca-certificates.crt',
                       'SSL_CERT_DIR':BASE+'/empty-certs','SKIP_SYSTEM_IPV6_CHECK':'1'},
        'tmpfs':['/tmp:rw,nosuid,nodev,noexec,size=8m,mode=1777'],
        'ulimits':{'nofile':{'soft':2048,'hard':2048}},
        'logging':{'driver':'local','options':{'max-size':'1m','max-file':'2'}}}
    services={}
    t=copy.deepcopy(common);t.update({'entrypoint':[BASE+'/bin/mihomo'],
        'command':['-d',BASE+'/state/mihomo','-f',BASE+'/config/mihomo.yaml'],
        'volumes':[mount('config/mihomo.yaml','config/mihomo.yaml',True),
                   mount('state-compose/mihomo','state/mihomo',False)]})
    services['transport']=t
    for lane in LANES:
        s=copy.deepcopy(common);s.update({
            'entrypoint':[BASE+'/root/lib/ld-musl-aarch64.so.1'],
            'command':['--library-path',BASE+'/root/usr/lib:'+BASE+'/root/lib',
                       BASE+'/root/usr/sbin/unbound','-d','-c',BASE+'/config/unbound-'+lane+'.conf'],
            'volumes':[mount('config/unbound-'+lane+'.conf','config/unbound-'+lane+'.conf',True),
                       mount('state-compose/anchors/'+lane,'state/anchors/'+lane,False)],
            'depends_on':{'dispatcher' if lane=='d1' else 'transport':{'condition':'service_started'}}})
        services[lane]=s
    d=copy.deepcopy(common);d.update({
        # Original upstream image config ID survives a verified offline load;
        # a saved repository digest is not assumed to survive that operation.
        'image':'sha256:5d3b3e589fcf57f626c7967bff5171924cf9c55068911247a1f7bd2458e726c3',
        'entrypoint':['/coredns'],'working_dir':'/',
        'command':['-conf',BASE+'/config/Corefile'],
        'volumes':[mount('config/Corefile','config/Corefile',True),
                   mount('native-payload/root/etc/ssl/certs/ca-certificates.crt','root/etc/ssl/certs/ca-certificates.crt',True),
                   mount('native-payload/empty-certs','empty-certs',True)],
        'depends_on':{lane:{'condition':'service_started'} for lane in ('g1','g2','g3')}})
    services['dispatcher']=d
    compose={'name':'dns-evaluation','services':services}
    rendered=yaml.safe_dump(compose,sort_keys=False)
    (out/'compose.yaml').write_text(rendered)
    (out/'compose.host.review.yaml').write_text('# REVIEW PROPOSAL. See research/DEPLOYMENT-COMPARISON.md and router test gates.\n'+rendered)
    (out/'Dockerfile.review').write_text(dockerfile)
    manifest={'base':BASE,'mihomo_sha256':sha(core),'mihomo_source':revision,'source_pilot_sha256':sha(src/'manifest.json'),
      'config_sha256':{f.name:sha(f) for f in sorted(config.iterdir())},
      'auxiliary_payload_file_count':len(payload),'auxiliary_payload_bytes':sum(f.stat().st_size for f in fs.rglob('*') if f.is_file()),
      'native_payload_bytes':sum(f.stat().st_size for f in native.rglob('*') if f.is_file()),
      'same_config_for_both':True,'state_roots_separate':True,'image_build_executed':False,
      'router_upload_or_execution':False,'native_state_target':BASE+'/state',
      'compose_state_source':BASE+'/state-compose',
      'differences_from_frozen_pilot':['new prefix','per-lane anchor directories','stderr rather than syslog for validators',
        'same explicit CA environment for Go processes','normal scheduling priority for both candidates'],
      'image_provenance':'Upstream CoreDNS image (verified identical executable); local auxiliary recipe around verified OpenWrt Unbound and maintained i-am-an-op Mihomo; auxiliary image is not upstream-maintained'}
    (out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print(json.dumps(manifest,indent=2))


if __name__=='__main__':main()
