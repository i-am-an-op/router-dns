#!/usr/bin/env python3
"""Recheck exact downloaded candidate provenance; never execute an artifact.
Inputs are retained offline policies/bundles/roots, not secrets. Requires gh.
"""
import argparse,copy,hashlib,importlib.util,json,tempfile
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--policy',type=Path,required=True);p.add_argument('--artifact',type=Path,required=True);p.add_argument('--bundle',type=Path,required=True);p.add_argument('--trusted-root',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
spec=importlib.util.spec_from_file_location('verifier',Path(__file__).resolve().parents[1]/'scripts/verify_artifact.py');v=importlib.util.module_from_spec(spec);spec.loader.exec_module(v)
policy=json.loads(a.policy.read_text());rows=[]
def check(name,pol,artifact,bundle,root,ok=False):
 try:v.verify(pol,artifact,bundle,root);accepted=True
 except (ValueError,KeyError):accepted=False
 rows.append({'case':name,'passed':accepted==ok,'accepted':accepted})
check('authentic exact-source candidate',policy,a.artifact,a.bundle,a.trusted_root,True)
with tempfile.TemporaryDirectory(prefix='dns-provenance-negative-') as d:
 temp=Path(d);data=bytearray(a.artifact.read_bytes());data[-1]^=1;bad=temp/'corrupt';bad.write_bytes(data)
 check('corrupted bytes unchanged policy',policy,bad,a.bundle,a.trusted_root)
 forged=copy.deepcopy(policy);forged['sha256']=hashlib.sha256(data).hexdigest();check('corrupted bytes with matching untrusted checksum',forged,bad,a.bundle,a.trusted_root)
 for label,key,value in [('wrong source revision','source_commit','0'*40),('wrong repository ID','repository_id',1),('wrong ELF architecture','architecture','amd64' if policy['architecture']=='arm64' else 'arm64')]:
  altered=copy.deepcopy(policy);altered[key]=value;check(label,altered,a.artifact,a.bundle,a.trusted_root)
 empty=temp/'empty-bundle.jsonl';empty.write_text('{}\n');check('invalid attestation bundle',policy,a.artifact,empty,a.trusted_root)
 r={'scope':'actual offline cryptographic verifier, real candidate and altered bytes/policies; no binary execution, router or service action','artifact_sha256':policy['sha256'],'source_commit':policy['source_commit'],'cases':rows,'passed':sum(x['passed'] for x in rows),'total':len(rows)}
 a.output.write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r,indent=2));assert all(x['passed'] for x in rows)
