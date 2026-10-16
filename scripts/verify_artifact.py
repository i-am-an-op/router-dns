#!/usr/bin/env python3
"""Verify a pinned raw Mihomo ELF and offline provenance. Never execute/install it.

The policy is independently reviewed input, not metadata trusted because it was
downloaded beside the binary. A successful receipt is not deployment approval.
"""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import re
import subprocess


def verify(policy, artifact, bundle, trusted_root):
    repositories={'i-am-an-op/mihomo':(1421581663,'downstream-release.yml','dns-maintained'),'i-am-an-op/router-dns':(1422214651,'draft.yml','main')}
    if policy['repository'] not in repositories:
        raise ValueError('unexpected repository')
    repo_id,workflow,branch=repositories[policy['repository']]
    if int(policy['repository_id']) != repo_id: raise ValueError('unexpected repository ID')
    if not re.fullmatch(r'[0-9a-f]{40}', policy['source_commit']):
        raise ValueError('invalid source commit')
    data=artifact.read_bytes()
    if hashlib.sha256(data).hexdigest() != policy['sha256']:
        raise ValueError('artifact digest mismatch')
    machines={'arm64':183,'amd64':62}
    if len(data)<64 or data[:6]!=b'\x7fELF\x02\x01' or int.from_bytes(data[18:20],'little')!=machines[policy['architecture']]:
        raise ValueError('ELF architecture mismatch')
    command=['gh','attestation','verify',str(artifact),'--repo',policy['repository'],
        '--bundle',str(bundle),'--custom-trusted-root',str(trusted_root),
        '--signer-workflow',policy['repository']+'/.github/workflows/'+workflow,
        '--signer-digest',policy['source_commit'],'--source-digest',policy['source_commit'],
        '--source-ref','refs/heads/'+branch,'--deny-self-hosted-runners',
        '--cert-oidc-issuer','https://token.actions.githubusercontent.com',
        '--predicate-type','https://slsa.dev/provenance/v1','--format','json']
    p=subprocess.run(command,capture_output=True,text=True,timeout=90)
    if p.returncode: raise ValueError('cryptographic provenance verification failed')
    results=json.loads(p.stdout)
    if not results: raise ValueError('no verified attestation')
    for result in results:
        certificate=result['verificationResult']['signature']['certificate']
        if str(certificate['sourceRepositoryIdentifier']) != str(policy['repository_id']):
            raise ValueError('repository identity mismatch')
    return {'verified_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'artifact_sha256':policy['sha256'],'architecture':policy['architecture'],
        'source_commit':policy['source_commit'],'repository_id':policy['repository_id'],
        'bundle_sha256':hashlib.sha256(bundle.read_bytes()).hexdigest(),
        'trusted_root_sha256':hashlib.sha256(trusted_root.read_bytes()).hexdigest(),
        'policy_sha256':hashlib.sha256(json.dumps(policy,sort_keys=True).encode()).hexdigest(),
        'verification_result_sha256':hashlib.sha256(p.stdout.encode()).hexdigest(),
        'cryptographic_verification':True,'binary_executed':False,
        'deployment_approved':False}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ['policy','artifact','bundle','trusted-root','output']:
        p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args()
    try: receipt=verify(json.loads(a.policy.read_text()),a.artifact,a.bundle,a.trusted_root)
    except (ValueError,KeyError,subprocess.TimeoutExpired) as e:
        raise SystemExit(str(e))
    a.output.write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps(receipt,indent=2))


if __name__=='__main__': main()
