#!/usr/bin/env python3
"""Generate review files only. Requires PyYAML. No router access or deployment."""
from pathlib import Path
import argparse
import yaml

ROOT = Path(__file__).resolve().parent

def mosdns_config(prefix='/etc/dns-policy', port=6053, backend_base=6060,
                  listen_addresses=('127.0.0.1', '192.168.2.2'),
                  domestic_helper_port=6060):
    plugins = []
    def add(tag, kind, args):
        plugins.append(dict(tag=tag, type=kind, args=args))
    def seq(tag, rules):
        add(tag, 'sequence', rules)
    def fallback(tag, primary, secondary, threshold):
        add(tag, 'fallback', dict(primary=primary, secondary=secondary,
                                 threshold=threshold, always_standby=False))
    add('domestic', 'domain_set', {'files': [prefix+'/domestic.txt']})
    add('international', 'domain_set', {'files': [prefix+'/international.txt']})
    add('local_names', 'domain_set', {'files': [prefix+'/local.txt']})
    # Deliberately no positive/NXDOMAIN/NODATA cache here.
    add('failure_cache', 'cache', {'size': 4096, 'lazy_cache_ttl': 0})
    seq('failure_lookup', [{'exec': '$failure_cache'}, {'exec': 'return'}])
    for i, tag in ((1, 'd1'), (3, 'g1'), (4, 'g2'), (5, 'g3')):
        add(tag+'_forward', 'forward', {'upstreams': [
            {'addr': f'tcp://127.0.0.1:{backend_base+i}', 'enable_pipeline': True}]})
        seq(tag, [{'exec': '$'+tag+'_forward'},
                  {'matches': ['rcode 0 3'], 'exec': 'accept'},
                  {'exec': 'drop_resp'}])
    fallback('global_tail', 'g2', 'g3', 600)
    fallback('global', 'g1', 'global_tail', 600)
    fallback('domestic_ladder', 'd1', 'global', 500)
    seq('use_global', [{'exec': '$global'}])
    seq('use_domestic', [{'exec': '$domestic_ladder'}])
    # Domestic recursive servers can omit signed delegation-denial material.
    # D1 still validates every CD=0 result itself. Obtain its DS/DNSKEY proof
    # queries from the global ladder; ordinary answers retain domestic CDN view.
    add('ali_wire', 'forward', {'concurrent': 2, 'upstreams': [
        {'addr': 'tls://dns.alidns.com', 'dial_addr': ip+':853',
         'enable_pipeline': True, 'insecure_skip_verify': False}
        for ip in ('223.5.5.5', '223.6.6.6')]})
    seq('domestic_wire', [
        {'matches': ['qtype 43 48'], 'exec': 'goto use_global'},
        {'exec': '$ali_wire'}])
    if domestic_helper_port is not None:
        add('domestic_helper', 'tcp_server', {
            'entry': 'domestic_wire', 'listen': f'127.0.0.1:{domestic_helper_port}'})
    seq('select_policy', [
        {'matches': ['qname $international'], 'exec': 'goto use_global'},
        {'matches': ['qname $domestic'], 'exec': 'goto use_domestic'},
        {'exec': 'goto use_global'}])
    seq('fail_closed', [{'exec': 'reject 2'}])
    fallback('bounded_policy', 'select_policy', 'fail_closed', 4500)
    # The failure_cache call at the end only sees SERVFAIL, including a cached hit.
    # On a lookup miss the sub-sequence ends without a response and stores nothing.
    seq('main', [
        {'matches': ['!qclass 1'], 'exec': 'reject 5'},
        {'matches': ['qname $local_names'], 'exec': 'reject 3'},
        {'exec': '$failure_lookup'},
        {'matches': ['has_resp'], 'exec': 'accept'},
        {'exec': '$bounded_policy'},
        {'matches': ['rcode 2'], 'exec': '$failure_cache'}])
    for i, addr in enumerate(listen_addresses):
        for transport in ('udp', 'tcp'):
            add(f'{transport}_{i}', transport+'_server',
                {'entry': 'main', 'listen': f'{addr}:{port}'})
    return {'log': {'level': 'warn'}, 'plugins': plugins}

BACKENDS = {
    'd1': (6061, ['127.0.0.1@6060']),
    'g1': (6063, ['127.0.0.1@6183#one.one.one.one']),
    'g2': (6064, ['127.0.0.1@6184#dns10.quad9.net']),
    'g3': (6065, ['127.0.0.1@6185#dns.google']),
}

def unbound_config(name, port, addresses, tls=True):
    return f'''# Unbound 1.26.1. procd owns the non-root UID/GID; see deployment.
server:
    interface: 127.0.0.1@{port}
    access-control: 127.0.0.0/8 allow
    access-control: 0.0.0.0/0 refuse
    access-control: ::0/0 refuse
    username: ""
    chroot: ""
    directory: "/etc/dns-policy"
    pidfile: ""
    do-daemonize: no
    use-syslog: yes
    verbosity: 1
    log-queries: no
    log-replies: no
    num-threads: 1
    msg-cache-size: 2m
    rrset-cache-size: 4m
    key-cache-size: 1m
    neg-cache-size: 1m
    msg-cache-slabs: 1
    rrset-cache-slabs: 1
    key-cache-slabs: 1
    infra-cache-slabs: 1
    outgoing-range: 128
    num-queries-per-thread: 128
    incoming-num-tcp: 32
    outgoing-num-tcp: 32
    outbound-msg-retry: 3
    edns-buffer-size: 1232
    max-udp-size: 1232
    do-udp: yes
    do-tcp: yes
    do-ip4: yes
    do-ip6: yes
    do-not-query-localhost: no
    module-config: "validator iterator"
    auto-trust-anchor-file: "/etc/dns-policy/anchors/{name}.key"
    tls-cert-bundle: "/etc/ssl/certs/ca-certificates.crt"
    tls-system-cert: no
    val-permissive-mode: no
    ignore-cd-flag: no
    val-bogus-ttl: 30
    val-max-restart: 1
    val-sig-skew-min: 0
    val-sig-skew-max: 0
    harden-dnssec-stripped: yes
    harden-glue: yes
    harden-below-nxdomain: yes
    qname-minimisation: yes
    cache-min-ttl: 0
    cache-min-negative-ttl: 0
    cache-max-negative-ttl: 3600
    serve-expired: no
    prefetch: no
    hide-identity: yes
    hide-version: yes
    minimal-responses: yes
    ede: yes
forward-zone:
    name: "."
    forward-first: no
    forward-tls-upstream: {'yes' if tls else 'no'}
    forward-tcp-upstream: yes
''' + ''.join(f'    forward-addr: "{addr}"\n' for addr in addresses)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--out', type=Path, default=ROOT/'generated')
    args = ap.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    from build_coredns import config
    (args.out/'Corefile').write_text(config())
    for name, (port, addrs) in BACKENDS.items():
        (args.out/f'unbound-{name}.conf').write_text(unbound_config(name, port, addrs, tls=name != 'd1'))
    print(f'Wrote five public configuration files to {args.out}')

if __name__ == '__main__':
    main()
