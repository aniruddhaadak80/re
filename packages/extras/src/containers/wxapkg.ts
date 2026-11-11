// WeChat mini program packages (.wxapkg): the plaintext 0xBE/0xED container and the
// PC client's V1MMWX encrypted form, which is decrypted when the AppID is known
// (PBKDF2-SHA1 key, AES-CBC over the first 1024 bytes, single byte XOR for the rest).

import { View, ParseError, utf8, latin1 } from '../util.js';

export interface WxapkgEntry { name: string; offset: number; size: number }
export interface Wxapkg {
  encrypted: boolean; decrypted?: boolean; info: number; indexLength: number; dataLength: number; fileCount: number; entries: WxapkgEntry[];
  kind: 'main' | 'subpackage' | 'plugin' | 'game' | 'unknown'; pages: string[]; appConfig?: Record<string, unknown>; warnings: string[];
}

/** True for a plaintext wxapkg header. */
export function isWxapkg(b: Uint8Array): boolean { return b.length >= 18 && b[0] === 0xbe && b[13] === 0xed; }
/** True for the PC client's encrypted wxapkg. */
export function isEncryptedWxapkg(b: Uint8Array): boolean { return b.length >= 1030 && latin1(b.subarray(0, 6)) === 'V1MMWX'; }

/** Decrypt a V1MMWX package with its AppID (WebCrypto, works in browsers and Node). */
export async function decryptWxapkg(b: Uint8Array, appId: string): Promise<Uint8Array> {
  if (!isEncryptedWxapkg(b)) throw new ParseError('not a V1MMWX encrypted wxapkg', 0);
  if (!appId) throw new ParseError('the AppID is needed to decrypt a PC wxapkg');
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) throw new ParseError('WebCrypto is not available in this runtime');
  const enc = new TextEncoder();
  const base = await subtle.importKey('raw', enc.encode(appId), 'PBKDF2', false, ['deriveKey']);
  const key = await subtle.deriveKey({ name: 'PBKDF2', salt: enc.encode('saltiest'), iterations: 1000, hash: 'SHA-1' }, base, { name: 'AES-CBC', length: 256 }, false, ['decrypt']);
  let head: Uint8Array;
  try { head = new Uint8Array(await subtle.decrypt({ name: 'AES-CBC', iv: enc.encode('the iv: 16 bytes') }, key, b.slice(6, 1030) as Uint8Array<ArrayBuffer>)); } catch { throw new ParseError('decryption failed: wrong AppID or corrupt package'); }
  const x = appId.length >= 2 ? appId.charCodeAt(appId.length - 2) & 0xff : 0x66;
  const out = new Uint8Array(head.length + b.length - 1030);
  out.set(head, 0);
  for (let i = 1030, j = head.length; i < b.length; i++, j++) out[j] = b[i]! ^ x;
  if (!isWxapkg(out)) throw new ParseError('decrypted bytes are not a wxapkg: wrong AppID');
  return out;
}

/** Parse a plaintext wxapkg; pass the AppID for encrypted PC packages. */
export async function parseWxapkgAny(b: Uint8Array, opts: { appId?: string; maxEntries?: number } = {}): Promise<Wxapkg & { bytes: Uint8Array }> {
  if (isEncryptedWxapkg(b)) {
    if (!opts.appId) return { encrypted: true, info: 0, indexLength: 0, dataLength: 0, fileCount: 0, entries: [], kind: 'unknown', pages: [], warnings: ['encrypted PC package: pass appId to decrypt'], bytes: b };
    const d = await decryptWxapkg(b, opts.appId);
    return { ...parseWxapkg(d, opts), encrypted: true, decrypted: true, bytes: d };
  }
  return { ...parseWxapkg(b, opts), bytes: b };
}

/** Parse a plaintext wxapkg member table and read app.json / app-config.json when present. */
export function parseWxapkg(b: Uint8Array, opts: { maxEntries?: number } = {}): Wxapkg {
  if (!isWxapkg(b)) throw new ParseError('not a wxapkg (0xBE ... 0xED header expected)', 0);
  const v = new View(b, false);
  const info = v.u32(1), indexLength = v.u32(5), dataLength = v.u32(9), count = v.u32(14);
  const warnings: string[] = [];
  if (18 + indexLength > b.length) throw new ParseError('wxapkg index runs past the end of the file', 5);
  if (count > Math.min(opts.maxEntries ?? 200000, indexLength / 12)) throw new ParseError('wxapkg member count does not fit its table', 14);
  const entries: WxapkgEntry[] = [];
  let p = 18;
  const end = 14 + indexLength;
  for (let i = 0; i < count; i++) {
    if (p + 4 > end + 4) throw new ParseError('truncated wxapkg member row', p);
    const n = v.u32(p);
    if (n > 65536 || !v.has(p + 4, n + 8)) throw new ParseError('bad wxapkg member name length', p);
    const name = utf8(v.sub(p + 4, n));
    const offset = v.u32(p + 4 + n), size = v.u32(p + 8 + n);
    if (offset + size > b.length) warnings.push(`${name} extends past the end of the file`);
    entries.push({ name, offset, size });
    p += 12 + n;
  }
  const read = (n: string): Record<string, unknown> | undefined => {
    const e = entries.find((x) => x.name === n);
    if (!e || e.offset + e.size > b.length || e.size > 16 << 20) return undefined;
    try { return JSON.parse(utf8(b.subarray(e.offset, e.offset + e.size))) as Record<string, unknown>; } catch { return undefined; }
  };
  const cfg = read('/app-config.json') ?? read('/app.json') ?? read('/game.json');
  const names = new Set(entries.map((e) => e.name));
  const kind: Wxapkg['kind'] = names.has('/game.js') || names.has('/game.json') ? 'game' : names.has('/plugin.json') ? 'plugin' : cfg ? 'main' : entries.length ? 'subpackage' : 'unknown';
  const pages = Array.isArray(cfg?.pages) ? (cfg!.pages as unknown[]).map(String) : [...names].filter((n) => /\.(wxml|html)$/.test(n)).map((n) => n.replace(/^\//, '').replace(/\.(wxml|html)$/, ''));
  return { encrypted: false, info, indexLength, dataLength, fileCount: count, entries, kind, pages, appConfig: cfg, warnings };
}

/** Bytes of one member. */
export function wxapkgMember(b: Uint8Array, e: WxapkgEntry): Uint8Array {
  if (e.offset + e.size > b.length) throw new ParseError(`member ${e.name} out of range`, e.offset);
  return b.subarray(e.offset, e.offset + e.size);
}
