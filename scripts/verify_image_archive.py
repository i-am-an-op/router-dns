#!/usr/bin/env python3
"""Validate a reviewed offline Docker/OCI archive before passing it to a daemon.

The expected digest must come from the independently reviewed inventory. This
is structural validation, not publisher authentication or arbitrary-image safety.
"""
import argparse, hashlib, json, re, tarfile
from pathlib import Path, PurePosixPath

def verify(path, expected):
    if not re.fullmatch(r'[a-f0-9]{64}', expected):
        raise ValueError('Expected SHA256 must be independently supplied')
    h=hashlib.sha256()
    with path.open('rb') as f:
        for b in iter(lambda:f.read(1024*1024), b''):h.update(b)
    if h.hexdigest()!=expected:raise ValueError('Archive digest mismatch')
    descriptors=[];json_count=0;docker_layers=0
    with tarfile.open(path) as archive:
        members={}
        for m in archive:
            name=m.name.removeprefix('./');p=PurePosixPath(name)
            if p.is_absolute() or '..' in p.parts or '\\' in name or name in members:
                raise ValueError('Unsafe or duplicate archive member')
            if not (m.isdir() or m.isfile()):raise ValueError('Outer archive links/devices refused')
            members[name]=m
        def member(name):
            if name not in members or not members[name].isfile():
                raise ValueError('Referenced metadata/layer missing')
            return members[name]
        def digest_of(name):
            h=hashlib.sha256()
            with archive.extractfile(member(name)) as f:
                for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
            return h.hexdigest()
        def walk(value):
            if isinstance(value,dict):
                if 'io.containerd.manifest.subject' in value.get('annotations',{}):
                    raise ValueError('Subject annotations are outside the reviewed image format')
                if 'digest' in value:
                    digest=value['digest']
                    if not isinstance(digest,str) or not re.fullmatch(r'sha256:[a-f0-9]{64}',digest):
                        raise ValueError('Malformed or unsupported descriptor digest')
                    size=value.get('size')
                    if type(size) is not int or size<0:raise ValueError('Invalid descriptor size')
                    descriptors.append((digest,size))
                for item in value.values():walk(item)
            elif isinstance(value,list):
                for item in value:walk(item)
        for name,m in members.items():
            if not m.isfile():continue
            if name.startswith('blobs/sha256/'):
                digest=name.removeprefix('blobs/sha256/')
                if not re.fullmatch('[a-f0-9]{64}',digest):raise ValueError('Invalid blob path')
                f=archive.extractfile(m);h=hashlib.sha256()
                for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
                if h.hexdigest()!=digest:raise ValueError('Blob content digest mismatch')
            with archive.extractfile(m) as f:
                prefix=f.read(512)
                is_json=name.endswith('.json') or prefix.lstrip().startswith((b'{',b'['))
                if is_json and m.size>8*1024*1024:
                    raise ValueError('Image metadata exceeds reviewed size limit')
                content=prefix+f.read() if is_json else b''
            if is_json:
                if content.lstrip().startswith((b'{',b'[')):
                    try:value=json.loads(content)
                    except (ValueError,UnicodeError):raise ValueError('Malformed image metadata')
                    walk(value);json_count+=1
                else:raise ValueError('Malformed JSON metadata')
        for digest,size in descriptors:
            name='blobs/sha256/'+digest.split(':',1)[1]
            if name not in members or not members[name].isfile() or members[name].size!=size:
                raise ValueError('Descriptor target missing or size mismatch')
        if not json_count:raise ValueError('No image metadata found')
        if 'manifest.json' in members:
            manifest=json.load(archive.extractfile(member('manifest.json')))
            if not isinstance(manifest,list) or not manifest:
                raise ValueError('Empty or malformed Docker manifest')
            for entry in manifest:
                config_name=entry['Config'];config_member=member(config_name)
                if config_member.size>8*1024*1024:raise ValueError('Oversized image configuration')
                config=json.load(archive.extractfile(config_member))
                expected_config=PurePosixPath(config_name).name.removesuffix('.json')
                if not re.fullmatch('[a-f0-9]{64}',expected_config) or digest_of(config_name)!=expected_config:
                    raise ValueError('Docker configuration digest mismatch')
                layers=entry['Layers'];diff_ids=config['rootfs']['diff_ids']
                if len(layers)!=len(diff_ids):raise ValueError('Layer count mismatch')
                for name,diff_id in zip(layers,diff_ids):
                    if not re.fullmatch(r'sha256:[a-f0-9]{64}',diff_id):
                        raise ValueError('Malformed layer diff ID')
                    # Reviewed Docker exports contain uncompressed layer tars.
                    # No decompression or filesystem extraction is performed here.
                    if 'sha256:'+digest_of(name)!=diff_id:
                        raise ValueError('Uncompressed layer digest mismatch')
                    docker_layers+=1
        elif 'index.json' not in members:
            raise ValueError('No supported image index/manifest')
    return {'archive_sha256':expected,'json_metadata_objects':json_count,
            'validated_descriptors':len(descriptors),'verified_docker_layer_diff_ids':docker_layers,
            'subject_annotations_allowed':False,
            'daemon_invoked':False,'publisher_authentication':False}

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--archive',type=Path,required=True);p.add_argument('--expected-sha256',required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    result=verify(a.archive,a.expected_sha256);a.output.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
