// Small, bounds checked DER reader with X.509 helpers, used by Authenticode, kernel module
// signatures and Mach-O CMS parsing. It never trusts lengths and caps child counts.

import { ParseError, toHex } from './util.js';
import { sha1, sha256 } from '@revlens/core';

export interface Der {
  tag: number;
  cls: number;
  constructed: boolean;
  /** offset of the tag byte */
  start: number;
  /** offset of the content */
  hdr: number;
  len: number;
  end: number;
  bytes: Uint8Array;
}

export function derAt(b: Uint8Array, off: number, limit = b.length): Der {
  if (off + 2 > limit) throw new ParseError('DER header out of range', off);
  const t = b[off] as number;
  let p = off + 1;
  let tag = t & 0x1f;
  if (tag === 0x1f) {
    tag = 0;
    for (let i = 0; i < 4; i++) { const c = b[p++]; if (c === undefined) throw new ParseError('DER tag out of range', off); tag = (tag << 7) | (c & 0x7f); if (!(c & 0x80)) break; }
  }
  const l0 = b[p++];
  if (l0 === undefined) throw new ParseError('DER length out of range', off);
  let len = 0;
  if (l0 < 0x80) len = l0;
  else {
    const n = l0 & 0x7f;
    if (n === 0 || n > 4) throw new ParseError('unsupported DER length', off);
    for (let i = 0; i < n; i++) { const c = b[p++]; if (c === undefined) throw new ParseError('DER length out of range', off); len = len * 256 + c; }
  }
  if (p + len > limit) throw new ParseError('DER content out of range', off);
  return { tag, cls: t >> 6, constructed: (t & 0x20) !== 0, start: off, hdr: p, len, end: p + len, bytes: b };
}

export function children(d: Der, max = 10000): Der[] {
  const out: Der[] = [];
  let p = d.hdr;
  while (p < d.end) {
    const c = derAt(d.bytes, p, d.end);
    out.push(c);
    p = c.end;
    if (out.length > max) throw new ParseError('too many DER children', p);
  }
  return out;
}
export function content(d: Der): Uint8Array { return d.bytes.subarray(d.hdr, d.end); }
export function raw(d: Der): Uint8Array { return d.bytes.subarray(d.start, d.end); }

export function oid(d: Der): string {
  const c = content(d);
  if (!c.length) return '';
  const parts: number[] = [Math.floor((c[0] as number) / 40), (c[0] as number) % 40];
  let v = 0;
  for (let i = 1; i < c.length; i++) {
    v = v * 128 + ((c[i] as number) & 0x7f);
    if (!((c[i] as number) & 0x80)) { parts.push(v); v = 0; }
  }
  return parts.join('.');
}
export function intHex(d: Der): string {
  let c = content(d);
  while (c.length > 1 && c[0] === 0) c = c.subarray(1);
  return toHex(c);
}
export function str(d: Der): string {
  const c = content(d);
  if (d.tag === 0x1e) { let s = ''; for (let i = 0; i + 1 < c.length; i += 2) s += String.fromCharCode(((c[i] as number) << 8) | (c[i + 1] as number)); return s; }
  return new TextDecoder().decode(c);
}
export function time(d: Der): string | null {
  const s = str(d);
  let m: RegExpExecArray | null;
  if (d.tag === 0x17 && (m = /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?Z$/.exec(s))) {
    const y = Number(m[1]);
    return `${y >= 50 ? 1900 + y : 2000 + y}-${m[2]}-${m[3]}T${m[4]}:${m[5]}:${m[6] ?? '00'}Z`;
  }
  if (d.tag === 0x18 && (m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.\d+)?Z$/.exec(s))) return `${m[1]}-${m[2]}-${m[3]}T${m[4]}:${m[5]}:${m[6]}Z`;
  return null;
}

const NAME_OIDS: Record<string, string> = {
  '2.5.4.3': 'CN', '2.5.4.6': 'C', '2.5.4.7': 'L', '2.5.4.8': 'ST', '2.5.4.10': 'O', '2.5.4.11': 'OU', '2.5.4.5': 'serialNumber',
  '1.2.840.113549.1.9.1': 'emailAddress', '2.5.4.9': 'street', '2.5.4.17': 'postalCode', '1.3.6.1.4.1.311.60.2.1.3': 'jurisdictionC',
  '2.5.4.15': 'businessCategory', '0.9.2342.19200300.100.1.25': 'DC',
};
export const ALG_OIDS: Record<string, string> = {
  '1.3.14.3.2.26': 'sha1', '2.16.840.1.101.3.4.2.1': 'sha256', '2.16.840.1.101.3.4.2.2': 'sha384', '2.16.840.1.101.3.4.2.3': 'sha512',
  '1.2.840.113549.2.5': 'md5', '1.2.840.113549.1.1.1': 'rsaEncryption', '1.2.840.113549.1.1.5': 'sha1WithRSAEncryption',
  '1.2.840.113549.1.1.11': 'sha256WithRSAEncryption', '1.2.840.113549.1.1.12': 'sha384WithRSAEncryption', '1.2.840.113549.1.1.13': 'sha512WithRSAEncryption',
  '1.2.840.10045.2.1': 'ecPublicKey', '1.2.840.10045.4.3.2': 'ecdsa-with-SHA256', '1.2.840.10045.4.3.3': 'ecdsa-with-SHA384',
  '1.2.840.113549.1.1.10': 'rsassa-pss',
};

export function x509Name(d: Der): { dn: string; fields: Record<string, string> } {
  const fields: Record<string, string> = {};
  const parts: string[] = [];
  for (const rdn of children(d)) {
    for (const atv of children(rdn)) {
      const [o, v] = children(atv);
      if (!o || !v) continue;
      const k = NAME_OIDS[oid(o)] ?? oid(o);
      const val = str(v);
      fields[k] = fields[k] ? fields[k] + ', ' + val : val;
      parts.push(`${k}=${val}`);
    }
  }
  return { dn: parts.reverse().join(', '), fields };
}

export interface Certificate {
  subject: string;
  issuer: string;
  subjectFields: Record<string, string>;
  serial: string;
  notBefore: string | null;
  notAfter: string | null;
  signatureAlgorithm: string;
  publicKeyAlgorithm: string;
  sha1: string;
  sha256: string;
  selfSigned: boolean;
  offset: number;
  /** DER of SubjectPublicKeyInfo, for verification */
  spki?: Uint8Array;
}

export function parseCertificate(d: Der): Certificate {
  const [tbs, sigAlg] = children(d);
  if (!tbs || !sigAlg) throw new ParseError('bad certificate', d.start);
  const t = children(tbs);
  let i = 0;
  if (t[0] && t[0].cls === 2 && t[0].tag === 0) i = 1;
  const serial = t[i]; const issuer = t[i + 2]; const validity = t[i + 3]; const subject = t[i + 4]; const spki = t[i + 5];
  if (!serial || !issuer || !validity || !subject || !spki) throw new ParseError('bad TBSCertificate', tbs.start);
  const [nb, na] = children(validity);
  const sub = x509Name(subject), iss = x509Name(issuer);
  const algo = children(spki)[0];
  const r = raw(d);
  const algOid = (x: Der | undefined): string => { const c = x ? children(x)[0] : undefined; return c ? oid(c) : ''; };
  return {
    subject: sub.dn, issuer: iss.dn, subjectFields: sub.fields, serial: intHex(serial),
    notBefore: nb ? time(nb) : null, notAfter: na ? time(na) : null,
    signatureAlgorithm: ALG_OIDS[algOid(sigAlg)] ?? algOid(sigAlg),
    publicKeyAlgorithm: ALG_OIDS[algOid(algo)] ?? (algOid(algo) || 'unknown'),
    sha1: sha1(r), sha256: sha256(r), selfSigned: sub.dn === iss.dn, offset: d.start, spki: raw(spki),
  };
}
