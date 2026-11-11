// APK signature inspection: v1 JAR signing (META-INF), and the APK Signing Block (v2, v3, v3.1, extras).
// This reports what is present and the signer certificates. It does not verify digests or signatures.

import { Buf, ParseError, digest, utf8 } from './bytes.js';
import { parseCertificate, pkcs7Certificates, type CertInfo } from './der.js';
import { openZip, readEntry, type ZipArchive } from './zip.js';

export const BLOCK_IDS: Record<number, string> = {
  0x7109871a: 'v2',
  0xf05368c0: 'v3',
  0x1b93ad61: 'v3.1',
  0x42726577: 'padding',
  0x6dff800d: 'source-stamp',
  0x2146444e: 'google-play-frosting',
  0x504b4453: 'dependency-info',
  0x71777777: 'meituan-channel',
};

export interface BlockSigner {
  certificates: CertInfo[];
  digestAlgorithms: string[];
  signatureAlgorithms: string[];
  minSdk?: number;
  maxSdk?: number;
  publicKeySha256?: string;
}

export interface SigningInfo {
  v1: { present: boolean; signatureFiles: string[]; certificates: (CertInfo & { file: string })[]; manifestEntries?: number; createdBy?: string };
  block?: { offset: number; size: number; ids: { id: string; name: string; size: number; offset: number }[] };
  v2: { present: boolean; signers: BlockSigner[] };
  v3: { present: boolean; signers: BlockSigner[] };
  v31: { present: boolean; signers: BlockSigner[] };
  sourceStamp: boolean;
  /** SHA-256 of every distinct signer certificate across schemes */
  certificateSha256: string[];
  warnings: string[];
}

const SIG_ALGS: Record<number, string> = {
  0x0101: 'RSASSA-PSS-SHA256', 0x0102: 'RSASSA-PSS-SHA512', 0x0103: 'RSASSA-PKCS1-v1_5-SHA256', 0x0104: 'RSASSA-PKCS1-v1_5-SHA512',
  0x0201: 'ECDSA-SHA256', 0x0202: 'ECDSA-SHA512', 0x0301: 'DSA-SHA256', 0x0421: 'RSASSA-PKCS1-v1_5-SHA256-verity',
  0x0423: 'ECDSA-SHA256-verity', 0x0425: 'DSA-SHA256-verity',
};

/** Read a u32 length-prefixed slice; returns [start, end) of the value. */
function lp(r: Buf, off: number, end: number): [number, number] {
  const n = r.u32(off);
  const s = off + 4;
  if (s + n > end) throw new ParseError(`length prefixed value at ${off} runs past ${end}`);
  return [s, s + n];
}

function* seq(r: Buf, start: number, end: number, max = 1024): Generator<[number, number]> {
  let p = start;
  let i = 0;
  while (p + 4 <= end && i++ < max) {
    const [s, e] = lp(r, p, end);
    yield [s, e];
    p = e;
  }
}

async function parseSigner(r: Buf, s: number, e: number, v3: boolean): Promise<BlockSigner> {
  const signer: BlockSigner = { certificates: [], digestAlgorithms: [], signatureAlgorithms: [] };
  const [sdS, sdE] = lp(r, s, e);
  // signed data: digests, certificates, (v3: minSdk, maxSdk), attributes
  const [dS, dE] = lp(r, sdS, sdE);
  for (const [a, b] of seq(r, dS, dE)) signer.digestAlgorithms.push(SIG_ALGS[r.u32(a)] ?? `0x${r.u32(a).toString(16)}`), void b;
  const [cS, cE] = lp(r, dE, sdE);
  for (const [a, b] of seq(r, cS, cE, 32)) signer.certificates.push(await parseCertificate(r.bytes.subarray(0, b), a));
  let p = cE;
  if (v3) { signer.minSdk = r.u32(p); signer.maxSdk = r.u32(p + 4); p += 8; }
  // after signed data
  let q = sdE;
  if (v3) { q += 8; }
  const [sgS, sgE] = lp(r, q, e);
  for (const [a] of seq(r, sgS, sgE)) {
    const id = r.u32(a + 0);
    signer.signatureAlgorithms.push(SIG_ALGS[id] ?? `0x${id.toString(16)}`);
  }
  if (sgE + 4 <= e) {
    const [pkS, pkE] = lp(r, sgE, e);
    signer.publicKeySha256 = await digest('SHA-256', r.bytes.subarray(pkS, pkE));
  }
  void p;
  return signer;
}

/** Locate and decode the APK Signing Block that sits right before the ZIP central directory. */
export async function parseSigningBlock(zip: ZipArchive, out: SigningInfo): Promise<void> {
  const r = new Buf(zip.bytes);
  const cd = zip.centralDirOffset;
  if (cd < 32 || !r.has(cd - 24, 24)) return;
  if (utf8(r.slice(cd - 16, 16)) !== 'APK Sig Block 42') return;
  const size = Number(r.u64(cd - 24));
  const start = cd - size - 8;
  if (size < 24 || start < 0 || Number(r.u64(start)) !== size) { out.warnings.push('APK signing block size fields disagree'); return; }
  const ids: NonNullable<SigningInfo['block']>['ids'] = [];
  let p = start + 8;
  const end = cd - 24;
  let n = 0;
  while (p + 12 <= end && n++ < 256) {
    const len = Number(r.u64(p));
    if (len < 4 || p + 8 + len > end) { out.warnings.push(`bad pair length at ${p}`); break; }
    const id = r.u32(p + 8);
    const vs = p + 12, ve = p + 8 + len;
    const name = BLOCK_IDS[id] ?? 'unknown';
    ids.push({ id: `0x${id.toString(16).padStart(8, '0')}`, name, size: len - 4, offset: vs });
    try {
      if (id === 0x7109871a || id === 0xf05368c0 || id === 0x1b93ad61) {
        const target = id === 0x7109871a ? out.v2 : id === 0xf05368c0 ? out.v3 : out.v31;
        target.present = true;
        const [ss, se] = lp(r, vs, ve);
        for (const [a, b] of seq(r, ss, se, 16)) target.signers.push(await parseSigner(r, a, b, id !== 0x7109871a));
      } else if (id === 0x6dff800d) out.sourceStamp = true;
    } catch (err) {
      out.warnings.push(`${name} block could not be decoded: ${(err as Error).message}`);
    }
    p += 8 + len;
  }
  out.block = { offset: start, size: size + 8, ids };
}

/** Inspect every signing scheme of an APK (or signed JAR). */
export async function apkSigning(input: Uint8Array | ZipArchive): Promise<SigningInfo> {
  const zip = input instanceof Uint8Array ? openZip(input) : input;
  const out: SigningInfo = {
    v1: { present: false, signatureFiles: [], certificates: [] },
    v2: { present: false, signers: [] }, v3: { present: false, signers: [] }, v31: { present: false, signers: [] },
    sourceStamp: false, certificateSha256: [], warnings: [],
  };
  const sigs = zip.entries.filter((e) => /^META-INF\/[^/]+\.(RSA|DSA|EC)$/i.test(e.name));
  const sfs = zip.entries.filter((e) => /^META-INF\/[^/]+\.SF$/i.test(e.name));
  out.v1.signatureFiles = sfs.map((e) => e.name);
  for (const e of sigs.slice(0, 16)) {
    try {
      const data = await readEntry(zip, e, 4 * 1024 * 1024);
      for (const c of await pkcs7Certificates(data)) out.v1.certificates.push({ ...c, file: e.name });
    } catch (err) { out.warnings.push(`${e.name}: ${(err as Error).message}`); }
  }
  out.v1.present = sfs.length > 0 && out.v1.certificates.length > 0;
  const mf = zip.byName.get('META-INF/MANIFEST.MF');
  if (mf) {
    try {
      const text = utf8(await readEntry(zip, mf, 16 * 1024 * 1024));
      out.v1.manifestEntries = (text.match(/^Name: /gm) ?? []).length;
      const cb = /^Created-By: (.*)$/m.exec(text);
      if (cb?.[1]) out.v1.createdBy = cb[1].trim();
    } catch { /* ignore */ }
  }
  await parseSigningBlock(zip, out);
  const all = new Set<string>();
  for (const c of out.v1.certificates) all.add(c.sha256);
  for (const s of [...out.v2.signers, ...out.v3.signers, ...out.v31.signers]) for (const c of s.certificates) all.add(c.sha256);
  out.certificateSha256 = [...all];
  return out;
}
