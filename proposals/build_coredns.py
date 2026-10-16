#!/usr/bin/env python3
"""CoreDNS 1.14.7 official-binary alternative. Generates files, never deploys."""
import argparse
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parent

def expression(path):
    """Translate the pinned mosdns domain-set grammar without changing scope."""
    domains, exact, patterns = [], [], []
    for line in Path(path).read_text().splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        kind, value = line.split(':', 1)
        if kind == 'domain':
            domains.append(value.lower())
        elif kind == 'full':
            exact.append(value.lower())
        elif kind == 'regexp':
            # Both engines use Go regexp against lowercase non-FQDN names.
            patterns.append('(?:' + value + ')')
        else:
            raise ValueError('Unsupported domain rule: ' + kind)
    # expr optimizes membership in a constant string array into a map lookup.
    # Enumerating the query's label suffixes avoids a giant alternation regex.
    terms=[]
    if domains:
        terms.append("any(0..(len(labels)-1), { join(labels[#:], '.') in " + json.dumps(domains) + " })")
    if exact:
        terms.append('q in '+json.dumps(exact))
    if patterns:
        terms.append('q matches '+json.dumps('|'.join(patterns)))
    return "let q = trimSuffix(lower(name()), '.'); let labels = split(q, '.'); " + ' || '.join('('+t+')' for t in terms)

def forward(addresses, timeout='500ms', attempts=None, tls_name=None, ca=None):
    lines = ['forward . ' + ' '.join(addresses) + ' {', '    force_tcp',
             '    policy sequential', '    max_fails 0', '    max_concurrent 128',
             '    failover SERVFAIL REFUSED FORMERR NOTIMP',
             '    read_timeout ' + timeout,
             '    max_connect_attempts ' + str(attempts or len(addresses))]
    if tls_name:
        lines += ['    tls' + (' ' + ca if ca else ''), '    tls_servername ' + tls_name]
    return '\n'.join(lines + ['}'])

def block(port, body, addresses=('127.0.0.1',), view=None):
    parts = ['bind ' + ' '.join(addresses), 'errors']
    if view:
        # Caddy's Corefile quoting escapes quotes, not JSON backslash pairs.
        # Double-JSON encoding would turn regexp \ . escapes into literal \.
        quoted = '"' + view[1].replace('"', '\\"') + '"'
        parts += ['view ' + view[0] + ' {\n    expr ' + quoted + '\n}']
    parts += [body]
    return '.:' + str(port) + ' {\n' + '\n'.join('    '+s for s in '\n'.join(parts).splitlines()) + '\n}\n'

def config(prefix=ROOT, port=6053, backend_base=6060,
           listen_addresses=('127.0.0.1', '192.168.2.2'),
           helper_port=6060, policy_port=6054,
           ali_addresses=('tls://223.5.5.5', 'tls://223.6.6.6'),
           ali_name='dns.alidns.com', ca='/etc/ssl/certs/ca-certificates.crt'):
    prefix = Path(prefix)
    global_lanes = [f'127.0.0.1:{backend_base+i}' for i in (3,4,5)]
    d1 = f'127.0.0.1:{backend_base+1}'
    # The outer server sees inner transport errors as actual SERVFAIL replies,
    # so they enter the same five-second failure cache as validator failures.
    outer = '''cache {
    success 4096 3600 0
    denial 4096 3600 0
    servfail 5s
}
''' + forward([f'127.0.0.1:{policy_port}'], '4400ms', 1)
    out = '# Official CoreDNS v1.14.7; no external plugins or source patch.\n'
    out += block(port, 'template ANY ANY {\n    rcode REFUSED\n}', listen_addresses,
                 ('class_guard', "class() != 'IN'"))
    out += block(port, outer, listen_addresses)
    out += block(policy_port, 'template IN ANY {\n    rcode NXDOMAIN\n}',
                 view=('local_guard', expression(prefix/'local.txt')))
    # Rewrite only exhausted error responses. NXDOMAIN and NODATA stay terminal.
    rewrite = '\n'.join('rewrite continue rcode regex .* '+rc+' SERVFAIL'
                        for rc in ('REFUSED','FORMERR','NOTIMP')) + '\n'
    out += block(policy_port, rewrite + forward(global_lanes),
                 view=('international', expression(prefix/'international.txt')))
    out += block(policy_port, rewrite + forward([d1]+global_lanes),
                 view=('domestic', expression(prefix/'domestic.txt')))
    out += block(policy_port, rewrite + forward(global_lanes))
    if helper_port is not None:
        out += block(helper_port, rewrite + forward(global_lanes),
                     view=('proof', "type() in ['DS','DNSKEY']"))
        out += block(helper_port, forward(list(ali_addresses), '1s', tls_name=ali_name, ca=ca))
    return out

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--out', type=Path, default=ROOT/'generated/Corefile')
    a = ap.parse_args()
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(config())
    print(a.out)

if __name__ == '__main__':
    main()
