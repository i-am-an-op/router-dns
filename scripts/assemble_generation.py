#!/usr/bin/env python3
"""Assemble an UNSIGNED private generation; no trust-key creation or router action.
Input plan contains all host pins, probes, mounts and exact reviewed file sources.
Artifact receipts must be produced separately by verify_artifact.py.
"""
import argparse,hashlib,json,os,shutil,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--plan',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--controller',type=Path,required=True);p.add_argument('--receipt',type=Path,required=True);p.add_argument('--bundle',type=Path,required=True);a=p.parse_args();os.umask(0o077)
plan=json.loads(a.plan.read_text());receipt=json.loads(a.receipt.read_text())
assert receipt['cryptographic_verification'] is True and receipt['repository_id']==1421581663
assert hashlib.sha256(a.bundle.read_bytes()).hexdigest()==receipt['bundle_sha256']
a.output.mkdir(parents=True,exist_ok=False,mode=0o700);files=[]
for entry in plan.pop('copy'):
 path=Path(entry['path']);assert not path.is_absolute() and '..' not in path.parts
 src=Path(entry['source']);dest=a.output/path;dest.parent.mkdir(parents=True,exist_ok=True);assert src.is_file() and not src.is_symlink();shutil.copyfile(src,dest);dest.chmod(entry['mode'])
 files.append({'path':str(path),'sha256':hashlib.sha256(dest.read_bytes()).hexdigest(),'mode':entry['mode']})
core=next(f for f in files if f['path']==plan['core']);assert core['sha256']==receipt['artifact_sha256'];assert plan['architecture']==receipt['architecture']
fingerprints=json.loads(subprocess.check_output([str(a.controller.resolve()),'profile-hash',str(a.output/plan['profile'])]))
plan.update(fingerprints);plan.update({'schema':1,'files':files,'provenance':{'core_bundle_sha256':receipt['bundle_sha256'],'verification_receipt_sha256':hashlib.sha256(a.receipt.read_bytes()).hexdigest()}})
(a.output/'manifest.json').write_text(json.dumps(plan,indent=2)+'\n')
print(json.dumps({'status':'unsigned-review-candidate','files':len(files),'manifest_sha256':hashlib.sha256((a.output/'manifest.json').read_bytes()).hexdigest(),'deployment_authorized':False}))
