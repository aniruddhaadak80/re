import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { analyzePcap, readPackets, parseClientHello, md5Hex } from '../src/index.js';

const S = join(dirname(fileURLToPath(import.meta.url)), '../../../samples/webrt');
const load = (f: string) => new Uint8Array(readFileSync(join(S, f)));

test('pcap: DNS query and answers match the tcpdump reference output', () => {
  const r = analyzePcap(load('dns_udp.pcap'));
  // tcpdump tests/dns_udp.out:
  //  1 ... IP 192.168.1.11.43966 > 209.87.249.18.53: 22836+ [1au] A? www.tcpdump.org. (56)
  //  2 ... IP 209.87.249.18.53 > 192.168.1.11.43966: 22836*- 2/2/5 A 192.139.46.66, A 198.199.88.104 (224)
  const ref = readFileSync(join(S, 'dns_udp.tcpdump.out'), 'utf8');
  assert.equal(r.format, 'pcap');
  assert.equal(r.packetCount, 2);
  const [q, a] = r.dns;
  assert.equal(q?.id, 22836); assert.ok(ref.includes(`${q?.id}+`));
  assert.equal(q?.response, false);
  assert.deepEqual(q?.questions, [{ name: 'www.tcpdump.org', type: 'A' }]);
  assert.equal(`${q?.src} > ${q?.dst}`, '192.168.1.11 > 209.87.249.18');
  const ips = a!.answers.filter((x) => x.type === 'A').map((x) => x.data);
  assert.deepEqual(ips, ['192.139.46.66', '198.199.88.104']);
  for (const ip of ips) assert.ok(ref.includes(`A ${ip}`));
  // timestamps: 2020-06-10 09:19:54.740079 UTC in the reference
  assert.equal(new Date(q!.ts * 1000).toISOString(), '2020-06-10T09:19:54.740Z');
  assert.equal(r.flows.length, 1);
  assert.equal(r.flows[0]?.service, 'dns');
  assert.equal(r.flows[0]?.client, '192.168.1.11');
  assert.equal(r.flows[0]?.serverPort, 53);
});

test('pcap: TLS ClientHello SNI and JA3 match pyja3 (Salesforce reference) and dpkt', () => {
  const r = analyzePcap(load('chrome-34-google.pcap'));
  const ref = JSON.parse(readFileSync(join(S, 'chrome-34-google.ja3.json'), 'utf8')) as { ja3: string; ja3_digest: string; source_ip: string; destination_ip: string; source_port: number }[];
  assert.equal(r.tls.length, 1);
  const h = r.tls[0]!;
  assert.equal(h.ja3, ref[0]!.ja3);
  assert.equal(h.ja3Hash, ref[0]!.ja3_digest);
  assert.equal(h.ja3Hash, 'a607f3a5c94c2ee592af1456f36c8367');
  assert.equal(h.src, ref[0]!.source_ip); assert.equal(h.dst, ref[0]!.destination_ip); assert.equal(h.sport, ref[0]!.source_port);
  assert.equal(h.sni, 'google.de'); // dpkt TLSHandshake server_name extension
  assert.deepEqual(h.alpn, ['spdy/3', 'spdy/3.1', 'http/1.1']);
  assert.equal(r.tlsServer[0]?.cipher, 0xc02f);
  assert.equal(r.packetCount, 42);
  assert.equal(r.flows.length, 1);
  assert.equal(r.flows[0]?.syn, true);
  assert.equal(r.flows[0]?.packetsToServer + r.flows[0]!.packetsToClient, 42);
});

test('pcap: HTTP/1.1 request and response from real captures', () => {
  const g = analyzePcap(load('get-gzip.pcap'));
  const req = g.http.find((x) => x.kind === 'request')!;
  assert.equal(req.method, 'GET'); assert.equal(req.target, '/gzip'); assert.equal(req.host, 'httpbin.org');
  assert.equal(req.headers['user-agent'], 'curl/7.29.0');
  assert.equal(g.http.find((x) => x.kind === 'response')?.status, 200);
  assert.equal(g.flows[0]?.fin, true);
  // tcpdump tests/ipv4_tcp_http_xml.out shows "HTTP/1.1 200 OK", Server: Microsoft-IIS/6.0, Content-Type: text/xml
  const x = analyzePcap(load('ipv4_tcp_http_xml.pcap'));
  const resp = x.http[0]!;
  assert.equal(resp.status, 200);
  assert.equal(resp.headers.server, 'Microsoft-IIS/6.0');
  assert.equal(resp.headers['content-type'], 'text/xml; charset=utf-8');
  assert.equal(resp.headers['content-length'], '351');
});

test('pcapng: multiple interfaces, packet count and DNS chain (dpkt reports 6 packets)', () => {
  const r = analyzePcap(load('pcapng-multi-interface.pcapng'));
  assert.equal(r.format, 'pcapng');
  assert.equal(r.packetCount, 6);
  assert.equal(r.flows.length, 3);
  const pk = [...readPackets(load('pcapng-multi-interface.pcapng'))];
  assert.equal(pk[0]?.ts, 1767663089.5003304);
  assert.deepEqual([...new Set(pk.map((p) => p.interfaceId))].sort(), [0, 1]);
  const names = r.dns.flatMap((d) => d.questions.map((q) => q.name));
  const nameSet = new Set(names);
  assert.ok(nameSet.has('www.apple.com') && nameSet.has('google.com'));
  const chain = r.dns.find((d) => d.response && d.questions[0]?.name === 'www.apple.com')!.answers.map((a) => `${a.type} ${a.data}`);
  assert.deepEqual(chain, ['CNAME www-apple-com.v.aaplimg.com', 'CNAME www.apple.com.edgekey.net', 'CNAME e6858.dsce9.akamaiedge.net', 'A 23.194.101.24']);
});

test('JA3 drops GREASE values and md5 matches known vectors', () => {
  assert.equal(md5Hex(''), 'd41d8cd98f00b204e9800998ecf8427e');
  assert.equal(md5Hex('The quick brown fox jumps over the lazy dog'), '9e107d9d372bb6826bd81d3542a419d6');
  // minimal ClientHello: version 0x0303, ciphers [GREASE 0x0a0a, 0x1301], ext GREASE 0x1a1a (empty), ext 10 groups [0x2a2a, 29], ext 11 [0]
  const body = [0x03, 0x03, ...new Array(32).fill(0), 0x00, 0x00, 0x04, 0x0a, 0x0a, 0x13, 0x01, 0x01, 0x00,
    0x00, 0x14, 0x1a, 0x1a, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x06, 0x00, 0x04, 0x2a, 0x2a, 0x00, 0x1d, 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00];
  const hs = [0x01, 0x00, 0x00, body.length, ...body];
  const rec = new Uint8Array([0x16, 0x03, 0x01, 0x00, hs.length, ...hs]);
  const h = parseClientHello(rec)!;
  assert.equal(h.ja3, '771,4865,10-11,29,0');
  assert.equal(h.ja3Hash, md5Hex('771,4865,10-11,29,0'));
});
