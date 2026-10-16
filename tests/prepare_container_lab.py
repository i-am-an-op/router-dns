#!/usr/bin/env python3
"""Assemble a credential-free LOCAL test image rootfs; no Docker installation.

Uses existing verified AMD64 CoreDNS/Mihomo and official ARM Unbound under the
same workstation QEMU in both candidates. Not a production router image.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tarfile

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--pilot',type=Path,required=True)
    parser.add_argument('--coredns',type=Path,required=True)
    parser.add_argument('--mihomo',type=Path,required=True)
    parser.add_argument('--qemu',type=Path,default=Path('/usr/bin/qemu-aarch64'))
    args=parser.parse_args();OUT=args.output;PILOT=args.pilot
    OUT.mkdir(exist_ok=False,mode=0o755)
    fs = OUT/'rootfs'; fs.mkdir()
    def copy(src, dest):
        target = fs / dest.lstrip('/'); target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, target); target.chmod(0o755 if Path(src).stat().st_mode & 0o111 else 0o644)
    copy(args.coredns, '/bin/coredns')
    copy(args.mihomo, '/bin/mihomo')
    copy(args.qemu, '/usr/bin/qemu-aarch64')
    # Copy the dynamic loader/library closure for the existing QEMU only.
    dynamic = subprocess.check_output(['ldd',str(args.qemu)], text=True)
    for line in dynamic.splitlines():
        m = re.search(r'(?:=>\s+)?(/\S+)', line)
        if m:
            copy(m.group(1), m.group(1))
            target=fs/m.group(1).lstrip('/')
            target.chmod(0o755 if target.name.startswith('ld-linux-') else 0o644)
    for src in (PILOT/'root').rglob('*'):
        if src.is_file(): copy(src, '/arm/'+str(src.relative_to(PILOT/'root')))
    # musl's libc is also its executable loader; both materialized paths retain
    # executable mode, matching the fixture that was actually exercised.
    (fs/'arm/lib/libc.so').chmod(0o755)
    for d in ['tmp','proc','dev','sys','etc','work']:
        (fs/d).mkdir(exist_ok=True)
    (fs/'tmp').chmod(0o1777)
    (fs/'etc/passwd').write_text('root:x:0:0:root:/:/nonexistent\nnobody:x:65534:65534:nobody:/:/nonexistent\n')
    (fs/'etc/group').write_text('root:x:0:\nnogroup:x:65534:\n')
    # The nobody identity must traverse the same payload in both runtime modes.
    # Callers still own/check access to ancestors of the selected output path.
    for directory in [OUT,fs,*fs.rglob('*')]:
        if directory.is_dir():directory.chmod(0o1777 if directory==fs/'tmp' else 0o755)
    manifest = {str(f.relative_to(fs)):hashlib.sha256(f.read_bytes()).hexdigest()
                for f in sorted(fs.rglob('*')) if f.is_file()}
    (OUT/'manifest.json').write_text(json.dumps(manifest, indent=2)+'\n')
    with tarfile.open(OUT/'rootfs.tar','w') as tf:
        for f in sorted(fs.rglob('*')):
            info=tf.gettarinfo(str(f),str(f.relative_to(fs)));info.uid=info.gid=0;info.uname=info.gname='';info.mtime=0
            if f.is_file():
                with f.open('rb') as inp: tf.addfile(info, inp)
            else: tf.addfile(info)
    print(json.dumps({'files':len(manifest),'tar_bytes':(OUT/'rootfs.tar').stat().st_size,
                      'secrets_included':False,'production_image':False}))


if __name__=='__main__': main()
