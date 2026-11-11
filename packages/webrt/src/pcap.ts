// PCAP and PCAPNG reader with Ethernet, Linux SLL, raw IP, IPv4, IPv6, TCP and UDP decoding,
// flow tracking, DNS, HTTP/1.x, and TLS ClientHello (SNI, ALPN, JA3) and ServerHello (JA3S).
import { Reader, InputError, decodeLatin1, md5Hex } from './util.js';

export interface PcapPacket {
  index: number;
  /** file offset of the captured bytes */
  offset: number;
  ts: number;
  capLen: number;
  origLen: number;
  linkType: number;
  interfaceId?: number;
}

export interface Decoded {
  l3?: 'ipv4' | 'ipv6' | 'arp' | 'other';
  src?: string;
  dst?: string;
  proto?: 'tcp' | 'udp' | 'icmp' | 'icmpv6' | 'other';
  sport?: number;
  dport?: number;
  tcpFlags?: number;
  seq?: number;
  payload?: Uint8Array;
  /** offset of the L4 payload inside the file */
  payloadOffset?: number;
}

export interface DnsRecord { name: string; type: string; ttl?: number; data?: string }
export interface DnsMessage { packet: number; ts: number; id: number; response: boolean; rcode: number; questions: { name: string; type: string }[]; answers: DnsRecord[]; src: string; dst: string; transport: 'udp' | 'tcp' }

export interface HttpMessage { packet: number; flow: number; kind: 'request' | 'response'; method?: string; target?: string; host?: string; status?: number; version: string; headers: Record<string, string> }

export interface TlsHello {
  packet: number;
  flow: number;
  src: string;
  dst: string;
  sport: number;
  dport: number;
  sni?: string;
  alpn?: string[];
  version: number;
  supportedVersions?: number[];
  ja3: string;
  ja3Hash: string;
  cipherCount: number;
}
export interface TlsServerHello { packet: number; flow: number; version: number; cipher: number; ja3s: string; ja3sHash: string }

export interface Flow {
  id: number;
  proto: 'tcp' | 'udp' | 'other';
  client: string;
  clientPort: number;
  server: string;
  serverPort: number;
  service?: string;
  firstPacket: number;
  first: number;
  last: number;
  packets: number;
  bytes: number;
  packetsToServer: number;
  packetsToClient: number;
  bytesToServer: number;
  bytesToClient: number;
  syn: boolean;
  fin: boolean;
  rst: boolean;
}

export interface PcapAnalysis {
  format: 'pcap' | 'pcapng';
  endian: 'le' | 'be';
  nanosecond: boolean;
  linkTypes: number[];
  packetCount: number;
  truncated: boolean;
  firstTs?: number;
  lastTs?: number;
  durationSeconds: number;
  totalBytes: number;
  protocols: Record<string, number>;
  topTalkers: { ip: string; packets: number; bytes: number }[];
  topPorts: { port: number; proto: string; packets: number }[];
  flows: Flow[];
  dns: DnsMessage[];
  http: HttpMessage[];
  tls: TlsHello[];
  tlsServer: TlsServerHello[];
  warnings: string[];
}

const LINKTYPE_NAMES: Record<number, string> = { 0: 'null', 1: 'ethernet', 101: 'raw', 12: 'raw', 14: 'raw', 113: 'linux-sll', 276: 'linux-sll2', 108: 'loop', 228: 'ipv4', 229: 'ipv6' };
export const linkTypeName = (n: number): string => LINKTYPE_NAMES[n] ?? `linktype-${n}`;

const MAX_PACKETS = 2_000_000;
const STREAM_CAP = 64 * 1024;

/** Iterate packets of a pcap or pcapng file. Yields views into the original bytes. */
export function* readPackets(bytes: Uint8Array, info: { format?: 'pcap' | 'pcapng'; endian?: 'le' | 'be'; nanosecond?: boolean; warnings?: string[] } = {}): Generator<PcapPacket & { data: Uint8Array }> {
  const r = new Reader(bytes);
  if (bytes.length < 4) throw new InputError('file too small for pcap');
  const m = r.u32(0, false);
  const warn = (s: string) => { if (info.warnings && info.warnings.length < 50) info.warnings.push(s); };
  if (m === 0xa1b2c3d4 || m === 0xd4c3b2a1 || m === 0xa1b23c4d || m === 0x4d3cb2a1) {
    const le = m === 0xd4c3b2a1 || m === 0x4d3cb2a1;
    const ns = m === 0xa1b23c4d || m === 0x4d3cb2a1;
    info.format = 'pcap'; info.endian = le ? 'le' : 'be'; info.nanosecond = ns;
    if (bytes.length < 24) throw new InputError('truncated pcap header');
    const linkType = r.u32(20, le) & 0x0fffffff;
    let off = 24, index = 0;
    while (off + 16 <= bytes.length && index < MAX_PACKETS) {
      const sec = r.u32(off, le), frac = r.u32(off + 4, le), incl = r.u32(off + 8, le), orig = r.u32(off + 12, le);
      if (incl > 0x4000000) { warn(`packet ${index + 1}: capture length ${incl} is not sane, stopping`); return; }
      if (off + 16 + incl > bytes.length) { warn(`packet ${index + 1}: truncated record`); return; }
      index++;
      yield { index, offset: off + 16, ts: sec + frac / (ns ? 1e9 : 1e6), capLen: incl, origLen: orig, linkType, data: bytes.subarray(off + 16, off + 16 + incl) };
      off += 16 + incl;
    }
    return;
  }
  if (m === 0x0a0d0d0a) {
    info.format = 'pcapng';
    let off = 0, index = 0;
    let le = true;
    let ifaces: { linkType: number; tsDiv: number; snap: number }[] = [];
    while (off + 12 <= bytes.length && index < MAX_PACKETS) {
      let type = r.u32(off, le);
      if (r.u32(off, false) === 0x0a0d0d0a) {
        type = 0x0a0d0d0a;
        const bom = r.u32(off + 8, true);
        if (bom === 0x1a2b3c4d) le = true; else if (bom === 0x4d3c2b1a) le = false; else { warn('bad pcapng byte order magic'); return; }
        info.endian = le ? 'le' : 'be';
        ifaces = [];
      }
      const len = r.u32(off + 4, le);
      if (len < 12 || len % 4 !== 0 || off + len > bytes.length) { warn(`pcapng block at ${off} has bad length ${len}`); return; }
      const body = off + 8, bodyEnd = off + len - 4;
      if (type === 1 && bodyEnd - body >= 8) {
        const linkType = r.u16(body, le), snap = r.u32(body + 4, le);
        let tsDiv = 1e6;
        // options
        let o = body + 8;
        while (o + 4 <= bodyEnd) {
          const code = r.u16(o, le), olen = r.u16(o + 2, le);
          if (code === 0) break;
          if (code === 9 && olen >= 1 && o + 5 <= bodyEnd) { const v = r.u8(o + 4); tsDiv = v & 0x80 ? 2 ** (v & 0x7f) : 10 ** (v & 0x7f); }
          o += 4 + olen + ((4 - (olen % 4)) % 4);
        }
        ifaces.push({ linkType, tsDiv, snap });
      } else if ((type === 6 || type === 2) && bodyEnd - body >= 20) {
        const ifId = type === 6 ? r.u32(body, le) : r.u16(body, le);
        const hi = r.u32(body + 4, le), lo = r.u32(body + 8, le);
        const cap = r.u32(body + 12, le), orig = r.u32(body + 16, le);
        const iface = ifaces[ifId];
        if (!iface) warn(`packet block references unknown interface ${ifId}`);
        if (body + 20 + cap > bodyEnd) { warn(`packet ${index + 1}: captured length past block end`); }
        else {
          index++;
          const div = iface?.tsDiv ?? 1e6;
          const ts = (hi * 4294967296 + lo) / div;
          yield { index, offset: body + 20, ts, capLen: cap, origLen: orig, linkType: iface?.linkType ?? 1, interfaceId: ifId, data: bytes.subarray(body + 20, body + 20 + cap) };
        }
      } else if (type === 3 && bodyEnd - body >= 4) {
        const orig = r.u32(body, le);
        const iface = ifaces[0];
        const cap = Math.min(orig, bodyEnd - body - 4, iface?.snap || Infinity);
        index++;
        yield { index, offset: body + 4, ts: 0, capLen: cap, origLen: orig, linkType: iface?.linkType ?? 1, interfaceId: 0, data: bytes.subarray(body + 4, body + 4 + cap) };
      }
      off += len;
    }
    return;
  }
  throw new InputError(`not a pcap or pcapng file (magic 0x${m.toString(16)})`);
}

function ip4(b: Uint8Array, o: number): string { return `${b[o]}.${b[o + 1]}.${b[o + 2]}.${b[o + 3]}`; }
function ip6(b: Uint8Array, o: number): string {
  const parts: string[] = [];
  for (let i = 0; i < 16; i += 2) parts.push((((b[o + i] as number) << 8) | (b[o + i + 1] as number)).toString(16));
  // compress the longest run of zeros
  let best = -1, bestLen = 0;
  for (let i = 0; i < 8;) {
    if (parts[i] !== '0') { i++; continue; }
    let j = i; while (j < 8 && parts[j] === '0') j++;
    if (j - i > bestLen && j - i > 1) { best = i; bestLen = j - i; }
    i = j;
  }
  if (best < 0) return parts.join(':');
  return `${parts.slice(0, best).join(':')}::${parts.slice(best + bestLen).join(':')}`;
}

/** Decode link, network and transport layers of one captured frame. Never throws on short data. */
export function decodeFrame(data: Uint8Array, linkType: number, fileOffset = 0): Decoded {
  const d: Decoded = {};
  const len = data.length;
  const u16 = (o: number) => (o + 2 <= len ? (((data[o] as number) << 8) | (data[o + 1] as number)) : -1);
  let off = 0;
  let etherType = -1;
  switch (linkType) {
    case 1: { // ethernet
      if (len < 14) return d;
      etherType = u16(12); off = 14;
      for (let k = 0; k < 4 && (etherType === 0x8100 || etherType === 0x88a8 || etherType === 0x9100); k++) { etherType = u16(off + 2); off += 4; }
      break;
    }
    case 113: if (len < 16) return d; etherType = u16(14); off = 16; break; // linux cooked
    case 276: if (len < 20) return d; etherType = u16(0); off = 20; break; // linux cooked v2
    case 0: case 108: { // null / loop: 4 byte family, host or network order
      if (len < 4) return d;
      const fam = linkType === 108 ? (((data[0] as number) << 24) | ((data[1] as number) << 16) | ((data[2] as number) << 8) | (data[3] as number)) >>> 0 : ((data[0] as number) | ((data[1] as number) << 8) | ((data[2] as number) << 16) | ((data[3] as number) << 24)) >>> 0;
      const famBE = (((data[0] as number) << 24) | ((data[1] as number) << 16) | ((data[2] as number) << 8) | (data[3] as number)) >>> 0;
      const f = fam === 2 || famBE === 2 ? 2 : fam;
      etherType = f === 2 ? 0x0800 : [24, 28, 30].includes(fam) || [24, 28, 30].includes(famBE) ? 0x86dd : -1; off = 4; break;
    }
    case 101: case 12: case 14: case 228: case 229: {
      const v = (data[0] ?? 0) >> 4; etherType = v === 4 ? 0x0800 : v === 6 ? 0x86dd : -1; off = 0; break;
    }
    default: return d;
  }
  let proto = -1, l4 = -1, l4end: number;
  if (etherType === 0x0800) {
    if (off + 20 > len) return d;
    const ihl = ((data[off] as number) & 0x0f) * 4;
    const total = u16(off + 2);
    if (ihl < 20) return d;
    d.l3 = 'ipv4'; d.src = ip4(data, off + 12); d.dst = ip4(data, off + 16);
    proto = data[off + 9] as number;
    const frag = u16(off + 6) & 0x1fff;
    l4end = Math.min(len, off + (total > 0 ? total : len - off));
    if (frag !== 0) { d.proto = 'other'; return d; }
    l4 = off + ihl;
  } else if (etherType === 0x86dd) {
    if (off + 40 > len) return d;
    d.l3 = 'ipv6'; d.src = ip6(data, off + 8); d.dst = ip6(data, off + 24);
    const plen = u16(off + 4);
    l4end = Math.min(len, off + 40 + plen);
    proto = data[off + 6] as number;
    l4 = off + 40;
    for (let k = 0; k < 8 && [0, 43, 60, 51, 135].includes(proto); k++) {
      if (l4 + 8 > len) return d;
      const next = data[l4] as number;
      const hlen = proto === 51 ? ((data[l4 + 1] as number) + 2) * 4 : ((data[l4 + 1] as number) + 1) * 8;
      proto = next; l4 += hlen;
    }
    if (proto === 44) { d.proto = 'other'; return d; } // fragment
  } else if (etherType === 0x0806) { d.l3 = 'arp'; return d; }
  else { d.l3 = 'other'; return d; }
  if (l4 > l4end) return d;
  if (proto === 6) {
    if (l4 + 20 > l4end) { d.proto = 'tcp'; return d; }
    d.proto = 'tcp'; d.sport = u16(l4); d.dport = u16(l4 + 2);
    d.seq = (((data[l4 + 4] as number) << 24) | ((data[l4 + 5] as number) << 16) | ((data[l4 + 6] as number) << 8) | (data[l4 + 7] as number)) >>> 0;
    const doff = ((data[l4 + 12] as number) >> 4) * 4;
    d.tcpFlags = data[l4 + 13] as number;
    const ps = l4 + Math.max(20, doff);
    if (ps <= l4end) { d.payload = data.subarray(ps, l4end); d.payloadOffset = fileOffset + ps; }
  } else if (proto === 17) {
    if (l4 + 8 > l4end) { d.proto = 'udp'; return d; }
    d.proto = 'udp'; d.sport = u16(l4); d.dport = u16(l4 + 2);
    const ulen = u16(l4 + 4);
    const end = ulen >= 8 ? Math.min(l4end, l4 + ulen) : l4end;
    d.payload = data.subarray(l4 + 8, end); d.payloadOffset = fileOffset + l4 + 8;
  } else if (proto === 1) d.proto = 'icmp';
  else if (proto === 58) d.proto = 'icmpv6';
  else d.proto = 'other';
  return d;
}

// ---------- DNS ----------
const DNS_TYPES: Record<number, string> = { 1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR', 15: 'MX', 16: 'TXT', 28: 'AAAA', 33: 'SRV', 41: 'OPT', 43: 'DS', 46: 'RRSIG', 47: 'NSEC', 48: 'DNSKEY', 64: 'SVCB', 65: 'HTTPS', 255: 'ANY', 256: 'URI', 257: 'CAA' };

function dnsName(b: Uint8Array, start: number): { name: string; next: number } | undefined {
  const labels: string[] = [];
  let off = start, next = -1, jumps = 0, total = 0;
  for (;;) {
    if (off >= b.length) return undefined;
    const l = b[off] as number;
    if (l === 0) { off++; break; }
    if ((l & 0xc0) === 0xc0) {
      if (off + 1 >= b.length || ++jumps > 32) return undefined;
      if (next < 0) next = off + 2;
      off = ((l & 0x3f) << 8) | (b[off + 1] as number);
      continue;
    }
    if ((l & 0xc0) !== 0) return undefined;
    if (off + 1 + l > b.length) return undefined;
    total += l + 1;
    if (total > 255 || labels.length > 127) return undefined;
    labels.push(decodeLatin1(b.subarray(off + 1, off + 1 + l)));
    off += 1 + l;
  }
  return { name: labels.join('.') || '.', next: next >= 0 ? next : off };
}

export function parseDns(b: Uint8Array): Omit<DnsMessage, 'packet' | 'ts' | 'src' | 'dst' | 'transport'> | undefined {
  if (b.length < 12) return undefined;
  const u16 = (o: number) => (((b[o] as number) << 8) | (b[o + 1] as number));
  const id = u16(0), flags = u16(2), qd = u16(4), an = u16(6), ns = u16(8), ar = u16(10);
  if (qd > 64 || an + ns + ar > 512 || ((flags >> 11) & 0xf) > 5) return undefined;
  const msg = { id, response: (flags & 0x8000) !== 0, rcode: flags & 0xf, questions: [] as { name: string; type: string }[], answers: [] as DnsRecord[] };
  let off = 12;
  for (let i = 0; i < qd; i++) {
    const n = dnsName(b, off);
    if (!n || n.next + 4 > b.length) return msg.questions.length ? msg : undefined;
    const ty = u16(n.next);
    msg.questions.push({ name: n.name, type: DNS_TYPES[ty] ?? `TYPE${ty}` });
    off = n.next + 4;
  }
  for (let i = 0; i < an; i++) {
    const n = dnsName(b, off);
    if (!n || n.next + 10 > b.length) break;
    const ty = u16(n.next), ttl = (((b[n.next + 4] as number) << 24) | ((b[n.next + 5] as number) << 16) | ((b[n.next + 6] as number) << 8) | (b[n.next + 7] as number)) >>> 0, rdlen = u16(n.next + 8);
    const rd = n.next + 10;
    if (rd + rdlen > b.length) break;
    let data: string | undefined;
    if (ty === 1 && rdlen === 4) data = ip4(b, rd);
    else if (ty === 28 && rdlen === 16) data = ip6(b, rd);
    else if (ty === 5 || ty === 2 || ty === 12) data = dnsName(b, rd)?.name;
    else if (ty === 15 && rdlen > 2) data = `${u16(rd)} ${dnsName(b, rd + 2)?.name ?? '?'}`;
    else if (ty === 16) { const parts: string[] = []; let o = rd; while (o < rd + rdlen) { const l = b[o] as number; parts.push(decodeLatin1(b.subarray(o + 1, Math.min(o + 1 + l, rd + rdlen)))); o += 1 + l; } data = parts.join(''); }
    msg.answers.push({ name: n.name, type: DNS_TYPES[ty] ?? `TYPE${ty}`, ttl, data });
    off = rd + rdlen;
  }
  return msg;
}

// ---------- TLS ----------
const isGrease = (v: number) => (v & 0x0f0f) === 0x0a0a && (v >> 8) === (v & 0xff);

/** Parse a TLS ClientHello from the start of a client byte stream. Computes JA3 (GREASE removed, as in the Salesforce reference). */
export function parseClientHello(b: Uint8Array): Omit<TlsHello, 'packet' | 'flow' | 'src' | 'dst' | 'sport' | 'dport'> | undefined {
  // reassemble handshake bytes across TLS records
  const hs: number[] = [];
  let o = 0;
  while (o + 5 <= b.length && hs.length < 65536) {
    if (b[o] !== 0x16 || b[o + 1] !== 3) break;
    const rl = ((b[o + 3] as number) << 8) | (b[o + 4] as number);
    const end = Math.min(b.length, o + 5 + rl);
    for (let i = o + 5; i < end; i++) hs.push(b[i] as number);
    o += 5 + rl;
    if (hs.length >= 4) { const need = (((hs[1] as number) << 16) | ((hs[2] as number) << 8) | (hs[3] as number)) + 4; if (hs.length >= need) break; }
  }
  if (hs.length < 4 || hs[0] !== 1) return undefined;
  const h = Uint8Array.from(hs);
  const u16 = (p: number) => (p + 2 <= h.length ? (((h[p] as number) << 8) | (h[p + 1] as number)) : -1);
  const bodyLen = ((h[1] as number) << 16) | ((h[2] as number) << 8) | (h[3] as number);
  const end = Math.min(h.length, 4 + bodyLen);
  let p = 4;
  const version = u16(p); p += 2 + 32;
  if (p >= end) return undefined;
  p += 1 + (h[p] as number); // session id
  const csLen = u16(p); p += 2;
  if (csLen < 0 || p + csLen > end) return undefined;
  const ciphers: number[] = [];
  for (let i = 0; i < csLen; i += 2) ciphers.push(u16(p + i));
  p += csLen;
  if (p >= end) return undefined;
  p += 1 + (h[p] as number); // compression
  const exts: number[] = [], curves: number[] = [], formats: number[] = [];
  let sni: string | undefined, alpn: string[] | undefined, supportedVersions: number[] | undefined;
  if (p + 2 <= end) {
    const extEnd = Math.min(end, p + 2 + u16(p)); p += 2;
    while (p + 4 <= extEnd) {
      const ty = u16(p), len = u16(p + 2), d = p + 4;
      if (d + len > extEnd) break;
      exts.push(ty);
      if (ty === 0 && len >= 5) {
        let q = d + 2;
        const listEnd = Math.min(d + len, d + 2 + u16(d));
        while (q + 3 <= listEnd) { const nt = h[q] as number, nl = u16(q + 1); if (nt === 0 && q + 3 + nl <= listEnd) { sni = decodeLatin1(h.subarray(q + 3, q + 3 + nl)); break; } q += 3 + nl; }
      } else if (ty === 10 && len >= 2) { const l = u16(d); for (let i = 0; i + 1 < l && d + 2 + i + 1 < d + len + 1; i += 2) curves.push(u16(d + 2 + i)); }
      else if (ty === 11 && len >= 1) { const l = h[d] as number; for (let i = 0; i < l && d + 1 + i < d + len; i++) formats.push(h[d + 1 + i] as number); }
      else if (ty === 16 && len >= 2) { alpn = []; let q = d + 2; while (q < d + len) { const l = h[q] as number; alpn.push(decodeLatin1(h.subarray(q + 1, Math.min(q + 1 + l, d + len)))); q += 1 + l; } }
      else if (ty === 43 && len >= 1) { supportedVersions = []; const l = h[d] as number; for (let i = 0; i + 1 < l; i += 2) supportedVersions.push(u16(d + 1 + i)); }
      p = d + len;
    }
  }
  const ja3 = [version, ciphers.filter((c) => !isGrease(c)).join('-'), exts.filter((e) => !isGrease(e)).join('-'), curves.filter((c) => !isGrease(c)).join('-'), formats.join('-')].join(',');
  return { version, sni, alpn, supportedVersions, ja3, ja3Hash: md5Hex(ja3), cipherCount: ciphers.length };
}

export function parseServerHello(b: Uint8Array): Omit<TlsServerHello, 'packet' | 'flow'> | undefined {
  if (b.length < 9 || b[0] !== 0x16 || b[1] !== 3 || b[5] !== 2) return undefined;
  const h = b.subarray(5);
  const u16 = (p: number) => (p + 2 <= h.length ? (((h[p] as number) << 8) | (h[p + 1] as number)) : -1);
  const end = Math.min(h.length, 4 + (((h[1] as number) << 16) | ((h[2] as number) << 8) | (h[3] as number)));
  let p = 4;
  const version = u16(p); p += 2 + 32;
  if (p >= end) return undefined;
  p += 1 + (h[p] as number);
  const cipher = u16(p); p += 2 + 1;
  const exts: number[] = [];
  if (p + 2 <= end) {
    const extEnd = Math.min(end, p + 2 + u16(p)); p += 2;
    while (p + 4 <= extEnd) { const ty = u16(p), len = u16(p + 2); exts.push(ty); p += 4 + len; }
  }
  if (cipher < 0) return undefined;
  const ja3s = `${version},${cipher},${exts.join('-')}`;
  return { version, cipher, ja3s, ja3sHash: md5Hex(ja3s) };
}

// ---------- HTTP ----------
const METHOD_RE = /^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE|PROPFIND|MKCOL|COPY|MOVE|LOCK|UNLOCK) (\S{1,4096}) (HTTP\/1\.[01])\r?\n/;
const STATUS_RE = /^(HTTP\/1\.[01]) (\d{3})(?: [^\r\n]{0,200})?\r?\n/;

function parseHttpStream(s: string, kind: 'request' | 'response', max = 100): Omit<HttpMessage, 'packet' | 'flow'>[] {
  const out: Omit<HttpMessage, 'packet' | 'flow'>[] = [];
  let pos = 0;
  while (pos < s.length && out.length < max) {
    const rest = s.slice(pos, pos + 65536);
    const m = kind === 'request' ? METHOD_RE.exec(rest) : STATUS_RE.exec(rest);
    if (!m) {
      const re = kind === 'request' ? /\r?\n(?=(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH) \S+ HTTP\/1\.[01]\r?\n)/g : /\r?\n(?=HTTP\/1\.[01] \d{3})/g;
      re.lastIndex = 0;
      const n = re.exec(rest);
      if (!n) break;
      pos += n.index + n[0].length;
      continue;
    }
    const headEnd = rest.indexOf('\r\n\r\n');
    const head = rest.slice(m[0].length, headEnd >= 0 ? headEnd : Math.min(rest.length, 16384));
    const headers: Record<string, string> = {};
    for (const line of head.split(/\r?\n/).slice(0, 100)) {
      const i = line.indexOf(':');
      if (i > 0) headers[line.slice(0, i).trim().toLowerCase()] = line.slice(i + 1).trim().slice(0, 1000);
    }
    if (kind === 'request') out.push({ kind, method: m[1], target: m[2], version: m[3] as string, host: headers.host, headers });
    else out.push({ kind, status: Number(m[2]), version: m[1] as string, headers });
    if (headEnd < 0) break;
    const cl = Number(headers['content-length']);
    pos += headEnd + 4 + (Number.isFinite(cl) && cl > 0 && cl < 1e9 ? cl : 0);
  }
  return out;
}

const SERVICES: Record<number, string> = { 53: 'dns', 80: 'http', 443: 'https', 8080: 'http-alt', 8443: 'https-alt', 22: 'ssh', 21: 'ftp', 25: 'smtp', 110: 'pop3', 143: 'imap', 993: 'imaps', 995: 'pop3s', 123: 'ntp', 67: 'dhcp', 68: 'dhcp', 5353: 'mdns', 1900: 'ssdp', 3306: 'mysql', 5432: 'postgres', 6379: 'redis', 27017: 'mongodb', 3389: 'rdp', 445: 'smb', 139: 'netbios', 137: 'netbios-ns', 161: 'snmp', 389: 'ldap', 636: 'ldaps', 88: 'kerberos', 1883: 'mqtt', 5060: 'sip', 853: 'dns-over-tls', 6667: 'irc' };

/** Full pass over a capture: stats, flows, DNS, HTTP, TLS. */
export function analyzePcap(bytes: Uint8Array, opts: { maxPackets?: number; maxRecords?: number } = {}): PcapAnalysis {
  const info: { format?: 'pcap' | 'pcapng'; endian?: 'le' | 'be'; nanosecond?: boolean; warnings: string[] } = { warnings: [] };
  const maxPackets = opts.maxPackets ?? MAX_PACKETS;
  const maxRecords = opts.maxRecords ?? 10_000;
  const res: PcapAnalysis = { format: 'pcap', endian: 'le', nanosecond: false, linkTypes: [], packetCount: 0, truncated: false, durationSeconds: 0, totalBytes: 0, protocols: {}, topTalkers: [], topPorts: [], flows: [], dns: [], http: [], tls: [], tlsServer: [], warnings: info.warnings };
  const links = new Set<number>();
  const talkers = new Map<string, { packets: number; bytes: number }>();
  const ports = new Map<string, number>();
  const flowMap = new Map<string, Flow & { streams: [{ base?: number; segs: Map<number, Uint8Array>; size: number }, { base?: number; segs: Map<number, Uint8Array>; size: number }] }>();
  const bump = (k: string) => { res.protocols[k] = (res.protocols[k] ?? 0) + 1; };
  for (const p of readPackets(bytes, info)) {
    if (res.packetCount >= maxPackets) { res.truncated = true; break; }
    res.packetCount++;
    res.totalBytes += p.origLen;
    links.add(p.linkType);
    if (p.ts) { if (res.firstTs === undefined || p.ts < res.firstTs) res.firstTs = p.ts; if (res.lastTs === undefined || p.ts > res.lastTs) res.lastTs = p.ts; }
    const d = decodeFrame(p.data, p.linkType, p.offset);
    bump(d.l3 ?? 'unknown-link');
    if (d.proto) bump(d.proto);
    if (!d.src || !d.dst) continue;
    for (const ip of [d.src, d.dst]) { const t = talkers.get(ip) ?? { packets: 0, bytes: 0 }; t.packets++; t.bytes += p.origLen; talkers.set(ip, t); }
    if ((d.proto === 'tcp' || d.proto === 'udp') && d.sport !== undefined && d.dport !== undefined) {
      const svcPort = Math.min(d.sport, d.dport);
      ports.set(`${d.proto}/${svcPort}`, (ports.get(`${d.proto}/${svcPort}`) ?? 0) + 1);
      const a = `${d.src}|${d.sport}`, b = `${d.dst}|${d.dport}`;
      const key = `${d.proto}|${a < b ? a : b}|${a < b ? b : a}`;
      let f = flowMap.get(key);
      if (!f) {
        // the side that sends the first SYN (or the first packet, or the higher port for UDP) is the client
        let clientIsSrc = true;
        if (d.proto === 'tcp' && d.tcpFlags !== undefined && (d.tcpFlags & 0x12) === 0x12) clientIsSrc = false;
        else if (d.proto === 'tcp' && d.tcpFlags !== undefined && (d.tcpFlags & 0x02) === 0) clientIsSrc = d.sport > d.dport;
        else if (d.proto === 'udp' && SERVICES[d.sport] && !SERVICES[d.dport]) clientIsSrc = false;
        f = { id: flowMap.size + 1, proto: d.proto, client: clientIsSrc ? d.src : d.dst, clientPort: clientIsSrc ? d.sport : d.dport, server: clientIsSrc ? d.dst : d.src, serverPort: clientIsSrc ? d.dport : d.sport, firstPacket: p.index, first: p.ts, last: p.ts, packets: 0, bytes: 0, packetsToServer: 0, packetsToClient: 0, bytesToServer: 0, bytesToClient: 0, syn: false, fin: false, rst: false, streams: [{ segs: new Map(), size: 0 }, { segs: new Map(), size: 0 }] };
        f.service = SERVICES[f.serverPort];
        flowMap.set(key, f);
      }
      const toServer = d.src === f.client && d.sport === f.clientPort;
      f.packets++; f.bytes += p.origLen; f.last = p.ts;
      if (toServer) { f.packetsToServer++; f.bytesToServer += p.origLen; } else { f.packetsToClient++; f.bytesToClient += p.origLen; }
      if (d.tcpFlags !== undefined) { if (d.tcpFlags & 0x02) f.syn = true; if (d.tcpFlags & 0x01) f.fin = true; if (d.tcpFlags & 0x04) f.rst = true; }
      const pl = d.payload;
      if (d.proto === 'udp' && pl && pl.length && (d.sport === 53 || d.dport === 53 || d.sport === 5353 || d.dport === 5353) && res.dns.length < maxRecords) {
        const m = parseDns(pl);
        if (m) res.dns.push({ ...m, packet: p.index, ts: p.ts, src: d.src, dst: d.dst, transport: 'udp' });
      }
      if (d.proto === 'tcp' && pl && pl.length && d.seq !== undefined) {
        const st = f.streams[toServer ? 0 : 1];
        if (st.base === undefined) st.base = d.seq;
        const rel = (d.seq - st.base + 4294967296) % 4294967296;
        if (rel < STREAM_CAP && !st.segs.has(rel) && st.size < STREAM_CAP) { st.segs.set(rel, pl.subarray(0, STREAM_CAP - rel)); st.size += pl.length; }
        if ((d.sport === 53 || d.dport === 53) && pl.length > 14 && res.dns.length < maxRecords) {
          const len = ((pl[0] as number) << 8) | (pl[1] as number);
          if (len + 2 <= pl.length) { const m = parseDns(pl.subarray(2, 2 + len)); if (m) res.dns.push({ ...m, packet: p.index, ts: p.ts, src: d.src, dst: d.dst, transport: 'tcp' }); }
        }
        // first packet index of data per direction for evidence
        (st as { firstPacket?: number }).firstPacket ??= p.index;
      }
    }
  }
  res.format = info.format ?? 'pcap'; res.endian = info.endian ?? 'le'; res.nanosecond = !!info.nanosecond;
  res.linkTypes = [...links];
  res.durationSeconds = res.firstTs !== undefined && res.lastTs !== undefined ? Math.round((res.lastTs - res.firstTs) * 1e6) / 1e6 : 0;
  for (const f of flowMap.values()) {
    const flat = (st: { segs: Map<number, Uint8Array> }) => {
      const keys = [...st.segs.keys()].sort((a, b) => a - b);
      const out = new Uint8Array(Math.min(STREAM_CAP, keys.length ? Math.max(...keys.map((k) => k + (st.segs.get(k) as Uint8Array).length)) : 0));
      for (const k of keys) { const s = st.segs.get(k) as Uint8Array; out.set(s.subarray(0, Math.max(0, out.length - k)), k); }
      // stop at the first gap: keep contiguous prefix only
      let contiguous = 0;
      for (const k of keys) { if (k > contiguous) break; contiguous = Math.max(contiguous, k + (st.segs.get(k) as Uint8Array).length); }
      return out.subarray(0, Math.min(contiguous, out.length));
    };
    if (f.proto !== 'tcp') continue;
    const c = flat(f.streams[0]), s = flat(f.streams[1]);
    const cp = (f.streams[0] as { firstPacket?: number }).firstPacket ?? f.firstPacket, sp = (f.streams[1] as { firstPacket?: number }).firstPacket ?? f.firstPacket;
    if (c.length && c[0] === 0x16 && res.tls.length < maxRecords) {
      const h = parseClientHello(c);
      if (h) { res.tls.push({ ...h, packet: cp, flow: f.id, src: f.client, dst: f.server, sport: f.clientPort, dport: f.serverPort }); f.service = h.alpn?.includes('h2') ? 'https/h2' : 'tls'; }
    }
    if (s.length && s[0] === 0x16 && res.tlsServer.length < maxRecords) {
      const h = parseServerHello(s);
      if (h) res.tlsServer.push({ ...h, packet: sp, flow: f.id });
    }
    if (c.length && res.http.length < maxRecords) for (const m of parseHttpStream(decodeLatin1(c), 'request')) { res.http.push({ ...m, packet: cp, flow: f.id }); f.service = 'http'; }
    if (s.length && res.http.length < maxRecords) for (const m of parseHttpStream(decodeLatin1(s), 'response')) { res.http.push({ ...m, packet: sp, flow: f.id }); f.service = 'http'; }
  }
  res.flows = [...flowMap.values()].map(({ streams: _s, ...f }) => f);
  res.topTalkers = [...talkers.entries()].map(([ip, v]) => ({ ip, ...v })).sort((a, b) => b.bytes - a.bytes).slice(0, 20);
  res.topPorts = [...ports.entries()].map(([k, n]) => { const [proto, port] = k.split('/'); return { proto: proto as string, port: Number(port), packets: n }; }).sort((a, b) => b.packets - a.packets).slice(0, 20);
  return res;
}

export function isPcap(bytes: Uint8Array): boolean {
  if (bytes.length < 4) return false;
  const m = ((bytes[0] as number) << 24 | (bytes[1] as number) << 16 | (bytes[2] as number) << 8 | (bytes[3] as number)) >>> 0;
  return [0xa1b2c3d4, 0xd4c3b2a1, 0xa1b23c4d, 0x4d3cb2a1, 0x0a0d0d0a].includes(m);
}
