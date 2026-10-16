#!/usr/bin/env python3
"""Offline renderer. Never prints secrets. Inputs are protected local YAML exports.

Read the already-generated runtime (after the existing private routing module),
and the original subscription. Output is a new native OpenClash overwrite module.
There is no network, SSH, controller or deployment code in this program.
"""
import argparse
import copy
import ipaddress
import os
from pathlib import Path
import yaml

def render(runtime, subscription, ipv4_only=False):
    groups = {g['name'] for g in runtime.get('proxy-groups', [])}
    wanted = ['🇭🇰 Hong Kong / Auto', '🇸🇬 Singapore / Auto', '🇯🇵 Japan / Auto']
    if not set(wanted) <= groups:
        raise ValueError('Required existing regional groups missing; review subscription drift')
    urls = subscription['dns']['nameserver']
    if len(urls) != 3 or any(not u.startswith('https://') or '#' in u for u in urls):
        raise ValueError('Expected three unmodified HTTPS bootstrap endpoints')
    clones = []
    for p in runtime.get('proxies', []):
        if not p['name'].startswith('Private / Ingress /') or p.get('type') != 'ss':
            continue
        ip = ipaddress.ip_address(p['server'])
        node = copy.deepcopy(p)
        node['name'] = f'DNS / Private IPv{ip.version}'
        node['dialer-proxy'] = 'DIRECT'
        clones.append(node)
    if len(clones) != 2 or len({p['name'] for p in clones}) != 2:
        raise ValueError('Expected exactly two existing numeric private ingress endpoints')
    local_policy = {
        '+.lan': ['tcp://127.0.0.1:53#DIRECT'],
        '+.home.arpa': ['tcp://127.0.0.1:53#DIRECT'],
        '+.8.168.192.in-addr.arpa': ['tcp://127.0.0.1:53#DIRECT'],
        # A high-port tunnel ensures remote local DNS is not intercepted as Fake-IP.
        '+.2.168.192.in-addr.arpa': ['tcp://127.0.0.1:6186#DIRECT'],
    }
    dns = dict(enable=True, listen='0.0.0.0:7874', ipv6=not ipv4_only,
               **{'enhanced-mode': 'fake-ip', 'respect-rules': False,
                  'disable-cache': True,
                  'nameserver': ['tcp://127.0.0.1:6053'],
                  'fallback': [], 'direct-nameserver': [],
                  'default-nameserver': ['https://223.5.5.5/dns-query',
                                         'https://223.6.6.6/dns-query'],
                  'proxy-server-nameserver': [u+'#DIRECT' for u in urls],
                  'proxy-server-nameserver-policy': {},
                  'nameserver-policy': local_policy})
    listeners = []
    for name, port, target, proxy in [
        ('cloudflare', 6183, '1.1.1.1:853', 'DNS / Private'),
        ('quad9', 6184, '9.9.9.10:853', 'DNS / Provider'),
        ('google', 6185, '8.8.8.8:853', '🇯🇵 Japan / Auto'),
        ('mt5000-local', 6186, '192.168.2.1:53', 'DIRECT'),
    ]:
        listeners.append(dict(name='dns-'+name, type='tunnel', listen='127.0.0.1',
                              port=port, network=['tcp'], target=target, proxy=proxy))
    preserved_dns = copy.deepcopy(runtime['dns'])
    preserved_dns.update(dns)
    if ipv4_only:
        preserved_dns.pop('fake-ip-range6', None)
    else:
        preserved_dns['fake-ip-range6'] = 'fdfe:dcba:9876::1/64'
    if preserved_dns.get('fake-ip-filter-mode', 'blacklist') != 'blacklist':
        raise ValueError('Review required: unexpected Fake-IP filter mode')
    preserved_dns['fake-ip-filter'] = list(dict.fromkeys(
        preserved_dns.get('fake-ip-filter', []) + ['*.home.arpa', 'home.arpa']))
    return {'dns!': preserved_dns, 'proxies+': clones, 'listeners+': listeners,
            'proxy-groups+': [
                {'name': 'DNS / Provider', 'type': 'fallback', 'proxies': wanted,
                 'url': 'https://www.gstatic.com/generate_204', 'interval': 300, 'lazy': True},
                {'name': 'DNS / Private', 'type': 'fallback',
                 'proxies': ['DNS / Private IPv4', 'DNS / Private IPv6'],
                 'url': 'https://www.gstatic.com/generate_204', 'interval': 300, 'lazy': True}]}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--runtime', type=Path, required=True)
    ap.add_argument('--subscription', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--ipv4-only', action='store_true', help='Initial compatibility stage; final design is dual-stack')
    args = ap.parse_args()
    module = render(yaml.safe_load(args.runtime.read_text()), yaml.safe_load(args.subscription.read_text()), args.ipv4_only)
    args.output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as f:
        f.write('# REVIEW ONLY: bind after the existing routing module, to this subscription only.\n[YAML]\n')
        f.write(yaml.safe_dump(module, allow_unicode=True, sort_keys=False))
    print('Protected overwrite module written; credentials were not printed. No router changes.')

if __name__ == '__main__':
    main()
