#!/usr/bin/env python3
"""Assemble a credential-free LOCAL test image rootfs; no Docker installation.

Uses existing verified AMD64 CoreDNS/Mihomo and official ARM Unbound under the
same workstation QEMU in both candidates. Not a production router image.
"""
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / '.work/container-lab-image'
PILOT = ROOT / '.private/mt6000-pilot-20261016-rc1'


def main():
    OUT.mkdir(exist_ok=False)
    fs = OUT/'rootfs'; fs.mkdir()
    def copy(src, dest):
        target = fs / dest.lstrip('/'); target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, target); target.chmod(0o755 if Path(src).stat().st_mode & 0o111 else 0o644)
    copy(ROOT/'.work/bin/coredns-official', '/bin/coredns')
    copy(ROOT/'.work/release-candidate/mihomo-linux-amd64', '/bin/mihomo')
    copy('/usr/bin/qemu-aarch64', '/usr/bin/qemu-aarch64')
    # Copy the dynamic loader/library closure for the existing QEMU only.
    dynamic = subprocess.check_output(['ldd','/usr/bin/qemu-aarch64'], text=True)
    for line in dynamic.splitlines():
        m = re.search(r'(?:=>\s+)?(/\S+)', line)
        if m: copy(m.group(1), m.group(1))
    for src in (PILOT/'root').rglob('*'):
        if src.is_file(): copy(src, '/arm/'+str(src.relative_to(PILOT/'root')))
    for d in ['tmp','proc','dev','sys','etc','work']:
        (fs/d).mkdir(exist_ok=True)
    (fs/'tmp').chmod(0o1777)
    (fs/'etc/passwd').write_text('root:x:0:0:root:/:/nonexistent\nnobody:x:65534:65534:nobody:/:/nonexistent\n')
    (fs/'etc/group').write_text('root:x:0:\nnogroup:x:65534:\n')
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
