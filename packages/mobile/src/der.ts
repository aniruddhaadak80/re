// Tiny ASN.1 DER reader and X.509 certificate summarizer. Enough for APK signatures and PKCS#7.

import { ParseError, digest, hex, utf8, utf16le } from './bytes.js';

export interface Tlv {
  tag: number;
  /** constructed bit set */
  cons: boolean;
  /** offset of the tag byte */
  start: number;
  /** offset of the content */
  vstart: number;
  /** offset after the content */
  end: number;
}

const MAX_DEPTH = 64;

export function readTlv(b: Uint8Array, off: number, limit = b.length): Tlv {
  if (off + 2 > limit) throw new ParseError(`DER truncated at ${off}`);
  const tag = b[off] as number;
  if ((tag & 0x1f) === 0x1f) throw new ParseError('DER high tag numbers are not supported');
  let len = b[off + 1] as number;
  let p = off + 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 4 || p + n > limit) throw new ParseError(`bad DER length at ${off}`);
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + (b[p + i] as number);
    p += n;
  }
  if (p + len > limit) throw new ParseError(`DER value at ${off} runs past its container`);
  return { tag, cons: (tag & 0x20) !== 0, start: off, vstart: p, end: p + len };
}

export function children(b: Uint8Array, t: Tlv, max = 10_000): Tlv[] {
  const out: Tlv[] = [];
  let p = t.vstart;
  while (p < t.end && out.length < max) {
    const c = readTlv(b, p, t.end);
    out.push(c);
    p = c.end;
  }
  return out;
}

export function oidToString(b: Uint8Array, t: Tlv): string {
  const parts: number[] = [];
  let v = 0;
  for (let i = t.vstart; i < t.end; i++) {
    const x = b[i] as number;
    v = v * 128 + (x & 0x7f);
    if (!(x & 0x80)) {
      if (parts.length === 0) { const a = v < 80 ? Math.floor(v / 40) : 2; parts.push(a, v - a * 40); }
      else parts.push(v);
      v = 0;
    }
  }
  return parts.join('.');
}

const NAME_OIDS: Record<string, string> = {
  '2.5.4.3': 'CN', '2.5.4.6': 'C', '2.5.4.7': 'L', '2.5.4.8': 'ST', '2.5.4.10': 'O', '2.5.4.11': 'OU',
  '2.5.4.5': 'SERIALNUMBER', '2.5.4.9': 'STREET', '2.5.4.12': 'T', '2.5.4.42': 'GN', '2.5.4.4': 'SN',
  '1.2.840.113549.1.9.1': 'EMAILADDRESS', '0.9.2342.19200300.100.1.25': 'DC', '0.9.2342.19200300.100.1.1': 'UID',
};

const SIG_OIDS: Record<string, string> = {
  '1.2.840.113549.1.1.5': 'sha1WithRSAEncryption', '1.2.840.113549.1.1.11': 'sha256WithRSAEncryption',
  '1.2.840.113549.1.1.12': 'sha384WithRSAEncryption', '1.2.840.113549.1.1.13': 'sha512WithRSAEncryption',
  '1.2.840.113549.1.1.4': 'md5WithRSAEncryption', '1.2.840.10045.4.3.2': 'ecdsa-with-SHA256',
  '1.2.840.10045.4.3.3': 'ecdsa-with-SHA384', '1.2.840.10045.4.3.4': 'ecdsa-with-SHA512',
  '1.2.840.10040.4.3': 'dsa-with-sha1', '2.16.840.1.101.3.4.3.2': 'dsa-with-sha256',
  '1.2.840.113549.1.1.1': 'rsaEncryption', '1.2.840.10045.2.1': 'ecPublicKey', '1.2.840.10040.4.1': 'dsa',
};

function strValue(b: Uint8Array, t: Tlv): string {
  const raw = b.subarray(t.vstart, t.end);
  if (t.tag === 0x1e) { // BMPString, big endian
    const sw = new Uint8Array(raw.length);
    for (let i = 0; i + 1 < raw.length; i += 2) { sw[i] = raw[i + 1] as number; sw[i + 1] = raw[i] as number; }
    return utf16le(sw);
  }
  return utf8(raw);
}

export function parseName(b: Uint8Array, t: Tlv): { attrs: { type: string; value: string }[]; text: string } {
  const attrs: { type: string; value: string }[] = [];
  for (const set of children(b, t, 64)) {
    for (const atv of children(b, set, 16)) {
      const [o, v] = children(b, atv, 2);
      if (!o || !v) continue;
      const oid = oidToString(b, o);
      attrs.push({ type: NAME_OIDS[oid] ?? oid, value: strValue(b, v) });
    }
  }
  // RFC 4514 and keytool print the most specific RDN first, which is the reverse of encoding order.
  return { attrs, text: [...attrs].reverse().map((a) => `${a.type}=${a.value}`).join(', ') };
}

function timeValue(b: Uint8Array, t: Tlv): string {
  const s = utf8(b.subarray(t.vstart, t.end));
  const m = t.tag === 0x17 ? /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?Z$/.exec(s) : /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?Z$/.exec(s);
  if (!m) return s;
  let y = Number(m[1]);
  if (t.tag === 0x17) y += y < 50 ? 2000 : 1900;
  return `${y}-${m[2]}-${m[3]}T${m[4]}:${m[5]}:${m[6] ?? '00'}Z`;
}

export interface CertInfo {
  subject: string;
  issuer: string;
  /** decimal serial, like keytool and androguard print it */
  serial: string;
  serialHex: string;
  notBefore: string;
  notAfter: string;
  signatureAlgorithm: string;
  publicKeyAlgorithm: string;
  publicKeyBits?: number;
  sha256: string;
  sha1: string;
  selfSigned: boolean;
  /** offset of the certificate inside the buffer it came from */
  offset: number;
  length: number;
}

function intToDecimal(b: Uint8Array, t: Tlv): string {
  let v = 0n;
  for (let i = t.vstart; i < t.end; i++) v = (v << 8n) | BigInt(b[i] as number);
  if (t.end > t.vstart && ((b[t.vstart] as number) & 0x80)) v -= 1n << BigInt((t.end - t.vstart) * 8);
  return v.toString();
}

/** Summarize a DER X.509 certificate that starts at `off`. */
export async function parseCertificate(b: Uint8Array, off = 0, depth = 0): Promise<CertInfo> {
  if (depth > MAX_DEPTH) throw new ParseError('certificate nesting too deep');
  const cert = readTlv(b, off);
  const [tbs, alg] = children(b, cert, 3);
  if (!tbs || !alg) throw new ParseError('bad certificate');
  const f = children(b, tbs, 16);
  let i = 0;
  if (f[0] && f[0].tag === 0xa0) i = 1;
  const serialT = f[i], issuerT = f[i + 2], validityT = f[i + 3], subjectT = f[i + 4], spkiT = f[i + 5];
  if (!serialT || !issuerT || !validityT || !subjectT || !spkiT) throw new ParseError('bad TBSCertificate');
  const [nb, na] = children(b, validityT, 2);
  const algOid = children(b, alg, 2)[0];
  const spki = children(b, spkiT, 2);
  const pkAlg = spki[0] ? children(b, spki[0], 2)[0] : undefined;
  const der = b.subarray(cert.start, cert.end);
  const subject = parseName(b, subjectT).text;
  const issuer = parseName(b, issuerT).text;
  const info: CertInfo = {
    subject, issuer,
    serial: intToDecimal(b, serialT),
    serialHex: hex(b.subarray(serialT.vstart, serialT.end)).replace(/^00(?=[89a-f])/, ''),
    notBefore: nb ? timeValue(b, nb) : '',
    notAfter: na ? timeValue(b, na) : '',
    signatureAlgorithm: algOid ? (SIG_OIDS[oidToString(b, algOid)] ?? oidToString(b, algOid)) : '',
    publicKeyAlgorithm: pkAlg ? (SIG_OIDS[oidToString(b, pkAlg)] ?? oidToString(b, pkAlg)) : '',
    sha256: await digest('SHA-256', der),
    sha1: await digest('SHA-1', der),
    selfSigned: subject === issuer,
    offset: cert.start,
    length: cert.end - cert.start,
  };
  // RSA modulus size
  try {
    if (info.publicKeyAlgorithm === 'rsaEncryption' && spki[1]) {
      const bits = spki[1];
      const inner = readTlv(b, bits.vstart + 1, bits.end);
      const mod = children(b, inner, 2)[0];
      if (mod) { let n = mod.end - mod.vstart; if (b[mod.vstart] === 0) n--; info.publicKeyBits = n * 8; }
    }
  } catch { /* optional */ }
  return info;
}

/** Find the certificates inside a PKCS#7 SignedData blob (META-INF/*.RSA, *.DSA, *.EC). */
export async function pkcs7Certificates(b: Uint8Array): Promise<CertInfo[]> {
  const ci = readTlv(b, 0);
  const [oid, content] = children(b, ci, 2);
  if (!oid || oidToString(b, oid) !== '1.2.840.113549.1.7.2' || !content) throw new ParseError('not PKCS#7 SignedData');
  const sd = children(b, content, 1)[0];
  if (!sd) throw new ParseError('empty SignedData');
  const out: CertInfo[] = [];
  for (const f of children(b, sd, 8)) {
    if (f.tag === 0xa0) {
      for (const c of children(b, f, 32)) out.push(await parseCertificate(b, c.start));
    }
  }
  return out;
}
