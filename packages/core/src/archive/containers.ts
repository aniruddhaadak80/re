import { Reader, decodeUtf8 } from '../bytes.js';
import { decompress } from './inflate.js';

export interface Entry {
  name: string;
  size: number;
  compressedSize: number;
  offset: number;
  /** read the member bytes (decompressed) */
  read(): Promise<Uint8Array>;
}

/** List ZIP members from the central directory. Supports stored and deflate. */
export function listZip(bytes: Uint8Array, base = 0): Entry[] {
  const r = new Reader(bytes, true);
  // Find End Of Central Directory from the back.
  let eocd = -1;
  for (let i = bytes.length - 22; i >= Math.max(0, bytes.length - 65557); i--) {
    if (bytes[i] === 0x50 && bytes[i + 1] === 0x4b && bytes[i + 2] === 0x05 && bytes[i + 3] === 0x06) { eocd = i; break; }
  }
  if (eocd < 0) return [];
  const count = r.u16(eocd + 10);
  let cd = r.u32(eocd + 16) + base;
  const out: Entry[] = [];
  for (let i = 0; i < count && cd + 46 <= bytes.length; i++) {
    if (r.u32(cd) !== 0x02014b50) break;
    const method = r.u16(cd + 10);
    const csize = r.u32(cd + 20);
    const usize = r.u32(cd + 24);
    const nlen = r.u16(cd + 28), xlen = r.u16(cd + 30), clen = r.u16(cd + 32);
    const local = r.u32(cd + 42) + base;
    const name = decodeUtf8(bytes.subarray(cd + 46, cd + 46 + nlen));
    cd += 46 + nlen + xlen + clen;
    if (name.endsWith('/')) continue;
    out.push({
      name, size: usize, compressedSize: csize, offset: local,
      async read() {
        const lnlen = r.u16(local + 26), lxlen = r.u16(local + 28);
        const start = local + 30 + lnlen + lxlen;
        const raw = bytes.subarray(start, start + csize);
        if (method === 0) return raw;
        if (method === 8) return decompress(raw, 'deflate-raw');
        throw new Error(`zip method ${method} is not supported`);
      },
    });
  }
  return out;
}

/** List members of a POSIX ustar or GNU tar archive. */
export function listTar(bytes: Uint8Array): Entry[] {
  const out: Entry[] = [];
  let off = 0;
  let longName = '';
  while (off + 512 <= bytes.length) {
    const hdr = bytes.subarray(off, off + 512);
    if (hdr.every((b) => b === 0)) break;
    const str = (s: number, l: number) => { let v = ''; for (let i = s; i < s + l && hdr[i]; i++) v += String.fromCharCode(hdr[i] as number); return v; };
    let name = str(0, 100);
    const prefix = str(345, 155);
    if (prefix) name = `${prefix}/${name}`;
    const size = parseInt(str(124, 12).trim() || '0', 8) || 0;
    const type = String.fromCharCode(hdr[156] as number);
    const dataStart = off + 512;
    if (type === 'L') { longName = stripNul(decodeUtf8(bytes.subarray(dataStart, dataStart + size))); }
    else if (type === '0' || type === '\0' || type === '') {
      const nm = longName || name; longName = '';
      const s = dataStart;
      out.push({ name: nm, size, compressedSize: size, offset: s, read: async () => bytes.subarray(s, s + size) });
    } else if (type !== 'x' && type !== 'g') longName = '';
    off = dataStart + Math.ceil(size / 512) * 512;
  }
  return out;
}

/** Electron ASAR: 16 byte pickle header, JSON directory, then file data. */
export function listAsar(bytes: Uint8Array): Entry[] {
  const r = new Reader(bytes, true);
  const jsonLen = r.u32(12);
  const json = decodeUtf8(bytes.subarray(16, 16 + jsonLen));
  const headerSize = r.u32(4);
  const dataBase = 8 + headerSize;
  const out: Entry[] = [];
  type Node = { files?: Record<string, Node>; offset?: string; size?: number; unpacked?: boolean };
  let root: Node;
  try { root = JSON.parse(json) as Node; } catch { return out; }
  const walk = (n: Node, path: string) => {
    if (n.files) { for (const [k, v] of Object.entries(n.files)) walk(v, path ? `${path}/${k}` : k); return; }
    if (n.unpacked || n.offset === undefined) return;
    const s = dataBase + Number(n.offset); const size = n.size ?? 0;
    out.push({ name: path, size, compressedSize: size, offset: s, read: async () => bytes.subarray(s, s + size) });
  };
  walk(root, '');
  return out;
}

/** CRX v2 and v3: strip the header and return the embedded ZIP offset. */
export function crxZipOffset(bytes: Uint8Array): number {
  const r = new Reader(bytes, true);
  const version = r.u32(4);
  if (version === 3) return 12 + r.u32(8);
  if (version === 2) return 16 + r.u32(8) + r.u32(12);
  return -1;
}

/** Drop trailing NUL characters without a regex (linear on any input). */
function stripNul(s: string): string { let e = s.length; while (e > 0 && s.charCodeAt(e - 1) === 0) e--; return s.slice(0, e); }
