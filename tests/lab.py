#!/usr/bin/env python3
"""Offline localhost tests. Requires dnspython, cryptography, PyYAML.

No SSH, public DNS, firewall changes, or live router control. Starts child
resolvers on high localhost ports and terminates only its own children.
"""
import argparse
from collections import Counter
import datetime
import importlib.util
import json
import os
from pathlib import Path
import socket
import socketserver
import ssl
import struct
import subprocess
import tempfile
import threading
import time
import dns.dnssec
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdatatype
import dns.rrset
import yaml
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('proposal', ROOT/'proposals/build_proposal.py')
proposal = importlib.util.module_from_spec(spec)
spec.loader.exec_module(proposal)
spec2 = importlib.util.spec_from_file_location('coredns_proposal', ROOT/'proposals/build_coredns.py')
coredns_proposal = importlib.util.module_from_spec(spec2)
spec2.loader.exec_module(coredns_proposal)

class ThreadTCP(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

class ThreadUDP(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True

def read_exact(sock, n):
    out = b''
    while len(out) < n:
        part = sock.recv(n-len(out))
        if not part:
            raise EOFError()
        out += part
    return out

class TCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        sock = self.request
        try:
            if self.server.tls:
                sock = self.server.tls.wrap_socket(sock, server_side=True)
            sock.settimeout(7)
            while True:
                n, = struct.unpack('!H', read_exact(sock, 2))
                q = dns.message.from_wire(read_exact(sock, n))
                r = self.server.reply(q)
                if r is not None:
                    data = r.to_wire(max_size=65535)
                    sock.sendall(struct.pack('!H', len(data))+data)
        except (EOFError, OSError, ssl.SSLError):
            pass
        finally:
            sock.close()

class UDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        q = dns.message.from_wire(data)
        r = self.server.reply(q)
        if r is not None:
            sock.sendto(r.to_wire(max_size=65535), self.client_address)

def serve(port, reply, tls=None):
    servers = [ThreadTCP(('127.0.0.1', port), TCPHandler)]
    if tls is None:
        servers.append(ThreadUDP(('127.0.0.1', port), UDPHandler))
    for server in servers:
        server.reply = reply
        server.tls = tls
        threading.Thread(target=server.serve_forever, daemon=True).start()
    return servers

def query(port, name, kind='A', tcp=False, cd=False, payload=1232):
    q = dns.message.make_query(name, kind, use_edns=0, want_dnssec=True, payload=payload)
    q.flags |= dns.flags.AD
    if cd:
        q.flags |= dns.flags.CD
    return (dns.query.tcp if tcp else dns.query.udp)(q, '127.0.0.1', port=port, timeout=7)

def start(cmd, directory, name, env=None):
    log = (directory/(name+'.log')).open('w')
    p = subprocess.Popen(cmd, stdout=log, stderr=log, env=env)
    time.sleep(float(os.environ.get("DNS_LAB_STARTUP_DELAY", ".3")))
    if p.poll() is not None:
        log.close()
        raise RuntimeError((directory/(name+'.log')).read_text()[-4000:])
    return p, log

def signed_fixture(directory):
    key = ec.generate_private_key(ec.SECP256R1())
    origin = dns.name.from_text('signed.example.')
    dnskey = dns.dnssec.make_dnskey(key.public_key(), 'ECDSAP256SHA256', flags=257)
    keys = dns.rrset.from_rdata(origin, 60, dnskey)
    (directory/'anchor.key').write_text(keys.to_text()+'\n')
    now = int(time.time())
    def sign(rr, expired=False, recent=False):
        sig = dns.dnssec.sign(rr, key, origin, dnskey,
            inception=now-7200 if expired or recent else now-60,
            expiration=now-30 if recent else (now-3600 if expired else now+3600))
        return dns.rrset.from_rdata(rr.name, rr.ttl, sig)
    counts = Counter()
    def reply(q):
        name = q.question[0].name.to_text()
        qt = q.question[0].rdtype
        counts[(name, qt)] += 1
        r = dns.message.make_response(q)
        r.flags |= dns.flags.AA | dns.flags.RA
        if name == 'signed.example.' and qt == dns.rdatatype.DNSKEY:
            r.answer = [keys, sign(keys)]
        elif name.endswith('.signed.example.') and qt == dns.rdatatype.DS:
            # Prove that this ordinary owner is not an unsigned delegation.
            # A validator needs this when an A reply deliberately lacks RRSIG.
            soa = dns.rrset.from_text('signed.example.', 30, 'IN', 'SOA',
                'ns.signed.example. hostmaster.signed.example. 1 60 60 60 2')
            following = {'bogus.signed.example.': 'expired.signed.example.',
                         'expired.signed.example.': 'good.signed.example.',
                         'good.signed.example.': 'recent.signed.example.',
                         'recent.signed.example.': 'signed.example.'}[name]
            denial = dns.rrset.from_text(name, 30, 'IN', 'NSEC',
                following+' A RRSIG NSEC')
            r.authority = [soa, sign(soa), denial, sign(denial)]
        elif name == 'nx.signed.example.' or (name == 'good.signed.example.' and qt == 28):
            soa = dns.rrset.from_text('signed.example.', 30, 'IN', 'SOA',
                'ns.signed.example. hostmaster.signed.example. 1 60 60 60 2')
            tail = dns.rrset.from_text('good.signed.example.', 30, 'IN', 'NSEC',
                'recent.signed.example. A RRSIG NSEC')
            r.authority = [soa, sign(soa), tail, sign(tail)]
            if name == 'nx.signed.example.':
                r.set_rcode(dns.rcode.NXDOMAIN)
                head = dns.rrset.from_text('signed.example.', 30, 'IN', 'NSEC',
                    'bogus.signed.example. NS SOA DNSKEY RRSIG NSEC')
                r.authority.extend([head, sign(head)])
        elif name.endswith('.signed.example.') and qt == dns.rdatatype.A:
            rr = dns.rrset.from_text(name, 60, 'IN', 'A', '192.0.2.1')
            sig = sign(rr, name.startswith('expired.'), name.startswith('recent.'))
            if name.startswith('bogus.'):
                rr = dns.rrset.from_text(name, 60, 'IN', 'A', '192.0.2.2')
            r.answer = [rr, sig]
        elif name.endswith('.unsigned.example.'):
            if name == 'nx.cache.unsigned.example.' and getattr(reply, 'negative_exists', False):
                r.answer = [dns.rrset.from_text(name, 60, 'IN', 'A', '192.0.2.9')]
                return r
            if name.startswith('nx.'):
                r.set_rcode(dns.rcode.NXDOMAIN)
            r.authority = [dns.rrset.from_text('unsigned.example.', 30, 'IN', 'SOA',
                'ns.unsigned.example. hostmaster.unsigned.example. 1 60 60 60 2')]
        else:
            r.set_rcode(dns.rcode.SERVFAIL)
        return r
    reply.sign = sign
    return reply, counts

def tls_context(directory):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'resolver.fixture')])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now-datetime.timedelta(days=1))
        .not_valid_after(now+datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName('resolver.fixture')]), critical=False)
        .sign(key, hashes.SHA256()))
    (directory/'ca.pem').write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (directory/'tls.key').write_bytes(key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(directory/'ca.pem', directory/'tls.key')
    return ctx

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--mosdns')
    ap.add_argument('--coredns')
    ap.add_argument('--disable-cache', action='store_true')
    ap.add_argument('--unbound', required=True)
    ap.add_argument('--mihomo', required=True)
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    checks, processes, servers = [], [], []
    def check(name, passed, detail=None):
        checks.append({'test': name, 'passed': bool(passed), 'detail': detail})
    with tempfile.TemporaryDirectory(prefix='dns-policy-lab-', delete=not bool(os.environ.get('DNS_LAB_RETAIN'))) as td:
        d = Path(td)
        try:
            counts = Counter()
            observed_do = {}
            def lane_reply(lane):
                def reply(q):
                    name, qt = q.question[0].name.to_text(), q.question[0].rdtype
                    counts[(lane, name, qt)] += 1
                    observed_do[(lane, name, qt)] = bool(q.ednsflags & dns.flags.DO)
                    r = dns.message.make_response(q)
                    r.flags |= dns.flags.RA
                    if name.startswith('timeout.'):
                        return None
                    if name.startswith('allfail.') or (name.startswith('collision.') and qt == 1):
                        r.set_rcode(dns.rcode.SERVFAIL)
                    elif name.startswith('recover.') and lane == 3:
                        r.set_rcode(dns.rcode.SERVFAIL)
                    elif name.startswith('third.') and lane in (3, 4):
                        r.set_rcode(dns.rcode.REFUSED)
                    elif name.startswith('domfail.') and lane == 1:
                        r.set_rcode(dns.rcode.SERVFAIL)
                    elif name.startswith('nx.'):
                        r.set_rcode(dns.rcode.NXDOMAIN)
                        r.authority = [dns.rrset.from_text('example.', 2, 'IN', 'SOA',
                            'ns.example. hostmaster.example. 1 60 60 60 2')]
                    elif name.startswith('nodata.'):
                        r.authority = [dns.rrset.from_text('example.', 2, 'IN', 'SOA',
                            'ns.example. hostmaster.example. 1 60 60 60 2')]
                    elif qt == 257:
                        r.answer = [dns.rrset.from_text(name, 60, 'IN', 'CAA', '0 issue "fixture.example"')]
                    elif qt == 16:
                        r.answer = [dns.rrset.from_text(name, 60, 'IN', 'TXT', *[
                            '"'+str(i)+('x'*240)+'"' for i in range(12)])]
                    else:
                        r.answer = [dns.rrset.from_text(name, 60, 'IN', 'A', f'192.0.2.{lane}')]
                    return r
                return reply
            for lane in (1, 3, 4, 5):
                servers.extend(serve(16660+lane, lane_reply(lane)))
            (d/'domestic.txt').write_text('domain:domestic.example\ndomain:domfail.example\n')
            (d/'international.txt').write_text('full:exception.domestic.example\n')
            (d/'local.txt').write_text('domain:lan\ndomain:home.arpa\n')
            config = proposal.mosdns_config(str(d), 16653, 16660, ('127.0.0.1',), None)
            (d/'mosdns.yaml').write_text(yaml.safe_dump(config, sort_keys=False))
            if args.coredns:
                cf = coredns_proposal.config(d, 16653, 16660, ('127.0.0.1',), None, 16656)
                (d/'Corefile').write_text(cf)
                processes.append(start([args.coredns, '-conf', str(d/'Corefile')], d, 'coredns'))
            else:
                processes.append(start([args.mosdns, 'start', '-c', str(d/'mosdns.yaml')], d, 'mosdns'))
            def addr(r):
                return r.answer[0][0].to_text() if r.answer else None
            check('domestic selection', addr(query(16653, 'a.domestic.example')) == '192.0.2.1')
            check('dispatcher preserves requested DO upstream',
                  observed_do[(1, 'a.domestic.example.', 1)])
            check('default international selection', addr(query(16653, 'unknown.example')) == '192.0.2.3')
            check('international exception wins', addr(query(16653, 'exception.domestic.example')) == '192.0.2.3')
            check('SERVFAIL advances to tier 2', addr(query(16653, 'recover.example')) == '192.0.2.4')
            check('REFUSED advances to tier 3', addr(query(16653, 'third.example')) == '192.0.2.5')
            check('domestic failures advance to global', addr(query(16653, 'domfail.example')) == '192.0.2.3')
            for n, code in [('nx.example', dns.rcode.NXDOMAIN), ('nodata.example', 0)]:
                r = query(16653, n)
                time.sleep(.05)
                check(n+' terminal negative', r.rcode() == code and not r.answer and
                      counts[(4, n+'.', 1)] == 0 and counts[(5, n+'.', 1)] == 0)
            query(16653, 'positive.example'); query(16653, 'positive.example')
            check('dispatcher positive cache policy', counts[(3, 'positive.example.', 1)] == (1 if args.coredns else 2))
            query(16653, 'nx.repeat.example'); query(16653, 'nx.repeat.example')
            check('dispatcher negative cache policy', counts[(3, 'nx.repeat.example.', 1)] == (1 if args.coredns else 2))
            r = query(16653, 'allfail.example')
            before = sum(counts.values())
            again = query(16653, 'allfail.example')
            check('final SERVFAIL cached', r.rcode() == again.rcode() == 2 and sum(counts.values()) == before)
            query(16653, 'collision.example', 'A')
            r = query(16653, 'collision.example', 'CAA')
            check('A/CAA failure-cache keys distinct', r.rcode() == 0 and bool(r.answer) and r.answer[0].rdtype == 257)
            check('local names never reach upstream', query(16653, 'printer.lan').rcode() == 3 and
                  not any(k[1] == 'printer.lan.' for k in counts))
            r = query(16653, 'large.example', 'TXT', payload=512)
            tcp = query(16653, 'large.example', 'TXT', tcp=True)
            check('UDP truncation and complete TCP response', bool(r.flags & dns.flags.TC) and len(tcp.answer[0]) == 12)
            started = time.monotonic()
            r = query(16653, 'timeout.example')
            elapsed = time.monotonic()-started
            check('total timeout bounded and fail-closed', r.rcode() == 2 and
                  (.5 if args.coredns else 4.3) <= elapsed <= 5.5, round(elapsed, 3))
            time.sleep(.6)  # Background branches have the inherited five-second deadline.
            before = sum(counts.values())
            query(16653, 'timeout.example')
            check('timeout failure cached', sum(counts.values()) == before)
            # Separate actual validator and certificate tests with a locally signed zone.
            reply, authcounts = signed_fixture(d)
            servers.extend(serve(16700, reply))
            def correct_reply(q):
                r = reply(q)
                if q.question[0].name.to_text() == 'bogus.signed.example.' and q.question[0].rdtype == 1:
                    rr = dns.rrset.from_text('bogus.signed.example.', 60, 'IN', 'A', '192.0.2.1')
                    r.answer = [rr, reply.sign(rr)]
                return r
            fixture_tls = tls_context(d)
            servers.extend(serve(16701, correct_reply, fixture_tls))
            for name, port, target, tls in [
                ('validator', 16711, '127.0.0.1@16700', False),
                ('tls_good', 16712, '127.0.0.1@16701#resolver.fixture', True),
                ('tls_bad', 16713, '127.0.0.1@16701#wrong.fixture', True)]:
                text = proposal.unbound_config(name, port, [target])
                text = text.replace('directory: "/etc/dns-policy"', f'directory: "{d}"')
                text = text.replace(f'auto-trust-anchor-file: "/etc/dns-policy/anchors/{name}.key"',
                                    f'trust-anchor-file: "{d}/anchor.key"')
                text = text.replace('tls-cert-bundle: "/etc/ssl/certs/ca-certificates.crt"',
                                    f'tls-cert-bundle: "{d}/ca.pem"')
                text = text.replace('forward-tls-upstream: yes', 'forward-tls-upstream: '+('yes' if tls else 'no'))
                text = text.replace('forward-zone:', '    domain-insecure: "unsigned.example."\nforward-zone:')
                text = text.replace('use-syslog: yes', 'use-syslog: no')
                path = d/(name+'.conf'); path.write_text(text)
                processes.append(start([args.unbound, '-d', '-c', str(path)], d, name))
            good = query(16711, 'good.signed.example')
            check('Unbound validates signed positive with AD', good.rcode() == 0 and bool(good.flags & dns.flags.AD))
            signed_nx = query(16711, 'nx.signed.example')
            check('Unbound authenticates signed NXDOMAIN', signed_nx.rcode() == 3 and bool(signed_nx.flags & dns.flags.AD))
            signed_nd = query(16711, 'good.signed.example', 'AAAA')
            check('Unbound authenticates signed NODATA', signed_nd.rcode() == 0 and not signed_nd.answer and bool(signed_nd.flags & dns.flags.AD))
            for name in ('bogus', 'expired', 'recent'):
                for cd in (False, True):
                    r = query(16711, name+'.signed.example', cd=cd)
                    if cd:
                        check(f'Unbound honors CD for {name}, clears AD', r.rcode() == 0 and bool(r.answer)
                              and not bool(r.flags & dns.flags.AD))
                    else:
                        check(f'Unbound rejects {name}; CD=0', r.rcode() == 2 and not r.answer)
            for name in ('nx', 'nodata'):
                fqdn = name+'.unsigned.example'
                r = query(16711, fqdn)
                n = authcounts[(fqdn+'.', 1)]
                query(16711, fqdn)
                check('Unbound '+name+' cache hit', authcounts[(fqdn+'.', 1)] == n)
                check('Unbound '+name+' SOA minimum bounds TTL', bool(r.authority) and r.authority[0].ttl <= 2)
                time.sleep(2.2)
                query(16711, fqdn)
                check('Unbound '+name+' cache expiry', authcounts[(fqdn+'.', 1)] > n)
            check('TLS authenticated endpoint accepted', query(16712, 'good.signed.example').rcode() == 0)
            domestic_wire_counts = Counter()
            def domestic_reply(q):
                domestic_wire_counts[(q.question[0].rdtype, bool(q.flags & dns.flags.CD))] += 1
                r = reply(q)
                r.flags &= ~dns.flags.AA
                # Reproduce the sampled domestic provider's CD=0 omission.
                if not q.flags & dns.flags.CD:
                    r.answer = [rr for rr in r.answer if rr.rdtype != dns.rdatatype.RRSIG]
                return r
            servers.extend(serve(16702, domestic_reply, fixture_tls))
            helper = proposal.mosdns_config(str(d), 16655, 16660, ('127.0.0.1',), 16716)
            for p in helper['plugins']:
                if p['tag'] in ('g1_forward', 'g2_forward', 'g3_forward'):
                    p['args']['upstreams'][0]['addr'] = 'tcp://127.0.0.1:16712'
                elif p['tag'] == 'ali_wire':
                    p['args']['upstreams'] = [{'addr': 'tls://resolver.fixture',
                        'dial_addr': '127.0.0.1:16702', 'enable_pipeline': True,
                        'insecure_skip_verify': False}]
            (d/'helper.yaml').write_text(yaml.safe_dump(helper, sort_keys=False))
            if args.coredns:
                cf = coredns_proposal.config(d, 16655, 16660, ('127.0.0.1',), 16716, 16657,
                     ('tls://127.0.0.1:16702',), 'resolver.fixture', str(d/'ca.pem'))
                for port in (16663,16664,16665): cf = cf.replace(':'+str(port), ':16712')
                (d/'helper.Corefile').write_text(cf)
                processes.append(start([args.coredns, '-conf', str(d/'helper.Corefile')], d, 'helper'))
            else:
                processes.append(start([args.mosdns, 'start', '-c', str(d/'helper.yaml')],
                    d, 'helper', env={**os.environ, 'SSL_CERT_FILE': str(d/'ca.pem')}))
            text = (d/'validator.conf').read_text().replace('127.0.0.1@16711', '127.0.0.1@16715')
            text = text.replace('127.0.0.1@16700', '127.0.0.1@16716')
            (d/'domestic_validator.conf').write_text(text)
            processes.append(start([args.unbound, '-d', '-c', str(d/'domestic_validator.conf')], d, 'domestic_validator'))
            domestic_good = query(16715, 'good.signed.example')
            check('domestic validator accepts authenticated signed answer after CD retry',
                  domestic_good.rcode() == 0 and bool(domestic_good.flags & dns.flags.AD)
                  and domestic_wire_counts[(dns.rdatatype.A, True)] > 0,
                  {'rcode': domestic_good.rcode(), 'ad': bool(domestic_good.flags & dns.flags.AD),
                   'wire_counts': {str(k): v for k, v in domestic_wire_counts.items()},
                   'validator_log': (d/'domestic_validator.log').read_text()[-1500:]})
            metadata = query(16716, 'signed.example', 'DNSKEY', tcp=True)
            check('domestic DNSKEY proof uses global path and preserves signatures',
                  metadata.rcode() == 0 and any(rr.rdtype == dns.rdatatype.RRSIG for rr in metadata.answer)
                  and not any(count for (qt, cd), count in domestic_wire_counts.items() if qt in (43, 48)))
            domestic_bogus = query(16715, 'bogus.signed.example')
            check('domestic proof separation never accepts bogus signed answer', domestic_bogus.rcode() == 2)
            composed = proposal.mosdns_config(str(d), 16654, 16660, ('127.0.0.1',), None)
            for p in composed['plugins']:
                if p['tag'] == 'g1_forward':
                    p['args']['upstreams'][0]['addr'] = 'tcp://127.0.0.1:16711'
                elif p['tag'] in ('g2_forward', 'g3_forward'):
                    p['args']['upstreams'][0]['addr'] = 'tcp://127.0.0.1:16712'
            (d/'composed.yaml').write_text(yaml.safe_dump(composed, sort_keys=False))
            if args.coredns:
                cf = coredns_proposal.config(d, 16654, 16660, ('127.0.0.1',), None, 16658)
                cf = cf.replace(':16663', ':16711').replace(':16664', ':16712').replace(':16665', ':16712')
                (d/'composed.Corefile').write_text(cf)
                processes.append(start([args.coredns, '-conf', str(d/'composed.Corefile')], d, 'composed'))
            else:
                processes.append(start([args.mosdns, 'start', '-c', str(d/'composed.yaml')], d, 'composed'))
            recovered = query(16654, 'bogus.signed.example')
            check('actual validation failure advances to independently valid TLS lane',
                  recovered.rcode() == 0 and bool(recovered.flags & dns.flags.AD) and addr(recovered) == '192.0.2.1')
            try:
                r = query(16713, 'good.signed.example')
                rejected = r.rcode() == 2 and not r.answer
            except dns.exception.Timeout:
                rejected = True
            log = (d/'tls_bad.log').read_text()
            check('TLS wrong certificate name fails closed', rejected and 'cert' in log.lower())
            before = sum(counts.values())
            query(16653, 'allfail.example')
            check('SERVFAIL cache expires and retries become possible', sum(counts.values()) > before)
            mc = {'ipv6': True, 'mode': 'rule', 'rules': ['MATCH,DIRECT'],
                  'listeners': [{'name': 'tls-fixture-tunnel', 'type': 'tunnel',
                      'listen': '127.0.0.1', 'port': 16882, 'network': ['tcp'],
                      'target': '127.0.0.1:16701', 'proxy': 'DIRECT'}],
                  'dns': {'enable': True, 'listen': '127.0.0.1:16853', 'ipv6': True,
                          'enhanced-mode': 'fake-ip', 'fake-ip-range': '198.18.0.1/15',
                          'fake-ip-range6': 'fdfe:dcba:9876::1/64',
                          'fake-ip-filter': ['bogus.signed.example', 'nx.cache.unsigned.example'],
                          'default-nameserver': ['udp://127.0.0.1:1'],
                          'nameserver': ['tcp://127.0.0.1:16654'],
                          'disable-cache': args.disable_cache}}
            (d/'mihomo.yaml').write_text(yaml.safe_dump(mc))
            # Lab host capability override only; no TUN/firewall is created.
            os.environ['SKIP_SYSTEM_IPV6_CHECK'] = 'true'
            processes.append(start([args.mihomo, '-d', str(d), '-f', str(d/'mihomo.yaml')], d, 'mihomo'))
            v4, v6 = query(16853, 'unknown.example'), query(16853, 'unknown.example', 'AAAA')
            check('deployed Mihomo revision synthesizes IPv4 Fake-IP', bool(v4.answer) and addr(v4).startswith('198.18.'))
            check('deployed Mihomo revision synthesizes IPv6 Fake-IP', bool(v6.answer) and addr(v6).startswith('fdfe:dcba:9876:'))
            synthetic_nx = query(16853, 'nx.signed.example')
            check('Fake-IP presentation synthesizes A even for a nonexistent name', synthetic_nx.rcode() == 0 and bool(synthetic_nx.answer))
            https = query(16853, 'unknown.example', 'HTTPS')
            check('Fake-IP presentation suppresses HTTPS records at this revision', https.rcode() == 0 and not https.answer)
            bad_cd = query(16853, 'bogus.signed.example', cd=True)
            good_cd0 = query(16853, 'bogus.signed.example')
            check('Mihomo separates CD=1 raw data from CD=0 validated answer',
                  addr(bad_cd) == '192.0.2.2' and addr(good_cd0) == '192.0.2.1')
            first_nx = query(16853, 'nx.cache.unsigned.example')
            reply.negative_exists = True
            time.sleep(2.3)
            after_expiry = query(16853, 'nx.cache.unsigned.example')
            check('Mihomo does not serve expired negative cache entry',
                  first_nx.rcode() == 3 and after_expiry.rcode() == 0 and addr(after_expiry) == '192.0.2.9')
            tunnel_config = (d/'tls_good.conf').read_text().replace('127.0.0.1@16712', '127.0.0.1@16714')
            tunnel_config = tunnel_config.replace('127.0.0.1@16701#', '127.0.0.1@16882#')
            (d/'tunnel.conf').write_text(tunnel_config)
            processes.append(start([args.unbound, '-d', '-c', str(d/'tunnel.conf')], d, 'tunnel'))
            tunneled = query(16714, 'good.signed.example')
            check('Mihomo fixed TCP listener carries end-to-end authenticated DoT',
                  tunneled.rcode() == 0 and bool(tunneled.flags & dns.flags.AD))
            if os.environ.get('DNS_PAIR_BENCH') == '1':
                import sys
                out=args.output.parent
                label=args.output.stem
                corpus=out/(label+'-benchmark-corpus.txt')
                corpus.write_text('good.signed.example A\ngood.signed.example AAAA\nnx.signed.example A\nbogus.signed.example A\n')
                sampler=Path(__file__).with_name('resource_sampler.py')
                benchmark=Path(__file__).with_name('runtime_benchmark.py')
                subprocess.run([sys.executable,str(sampler),'--seconds','5','--output',str(out/(label+'-idle-resources.json'))],check=True)
                sample=subprocess.Popen([sys.executable,str(sampler),'--seconds','120','--output',str(out/(label+'-load-resources.json'))])
                try:
                    for protocol in ['udp','tcp']:
                        command=[sys.executable,str(benchmark),'--address','127.0.0.1','--port','16654','--corpus',str(corpus),'--requests','2000','--concurrency','8','--output',str(out/(label+'-'+protocol+'-warm-benchmark.json'))]
                        if protocol=='tcp':command.append('--tcp')
                        subprocess.run(command,check=True,stdout=subprocess.DEVNULL)
                finally:
                    sample.terminate();sample.wait(timeout=3)
            rss = {}
            for p, _ in processes:
                try:
                    status = Path(f'/proc/{p.pid}/status').read_text()
                    rss[str(p.pid)] = next(l.strip() for l in status.splitlines() if l.startswith('VmRSS:'))
                except (FileNotFoundError, StopIteration):
                    pass
            result = {'scope': 'localhost synthetic fixtures, not router deployment or Internet benchmark',
                      'utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                      'checks': checks, 'process_rss': rss}
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(result, indent=2)+'\n')
            print(json.dumps({'passed': sum(c['passed'] for c in checks), 'total': len(checks),
                              'failures': [c for c in checks if not c['passed']]}))
            if not all(c['passed'] for c in checks):
                raise SystemExit(1)
        finally:
            if not args.output.exists():
                args.output.parent.mkdir(parents=True, exist_ok=True)
                args.output.write_text(json.dumps({'scope':'incomplete localhost fixture execution; not acceptance','checks':checks,'completed':False,'fixture':str(d),'logs':{p.name:p.read_text()[-2000:] for p in d.glob('*.log')}},indent=2)+'\n')
            for p, log in processes:
                p.terminate()
                try:
                    p.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    p.kill(); p.wait()
                log.close()
            for s in servers:
                s.shutdown(); s.server_close()

if __name__ == '__main__':
    main()
