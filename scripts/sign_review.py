#!/usr/bin/env python3
"""Sign an explicitly reviewed private manifest using an existing Ed25519 PEM key.
Never creates an operator/signing policy, downloads, uploads, or deploys anything.
Requires the pinned cryptography package from the research test environment.
"""
import argparse,base64,json,os
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--manifest',type=Path,required=True);p.add_argument('--key',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
if a.key.stat().st_mode&0o077:raise SystemExit('Private signing key permissions must be 0600')
key=serialization.load_pem_private_key(a.key.read_bytes(),password=None)
if not isinstance(key,Ed25519PrivateKey):raise SystemExit('Ed25519 key required')
b=a.manifest.read_bytes();json.loads(b)
os.umask(0o077)
with a.output.open('xb') as f:f.write(base64.b64encode(key.sign(b))+b'\n');f.flush();os.fsync(f.fileno())
print('Signed exact manifest bytes; deployment is not authorized by this command.')
