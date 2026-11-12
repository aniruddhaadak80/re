// cpio archives in the odc (070707), newc (070701) and crc (070702) forms, as found in pkg Scripts and
// Payload streams and in Linux initramfs images.

import { decodeUtf8 } from '../bytes.js';

export interface CpioEntry { name: string; mode: number; kind: 'file' | 'dir' | 'symlink' | 'other'; uid: number; gid: number; mtime: number; size: number; offset: number; link?: string }

function octal(b: Uint8Array, o: number, n: number): number { let v = 0; for (let i = 0; i < n; i++) { const c = (b[o + i] as number) - 0x30; if (c < 0 || c > 7) return NaN; v = v * 8 + c; } return v; }
function hexn(b: Uint8Array, o: number, n: number): number { let v = 0; for (let i = 0; i < n; i++) { const c = b[o + i] as number; const d = c >= 0x30 && c <= 0x39 ? c - 0x30 : c >= 0x61 && c <= 0x66 ? c - 87 : c >= 0x41 && c <= 0x46 ? c - 55 : -1; if (d < 0) return NaN; v = v * 16 + d; } return v; }
function kindOf(mode: number): CpioEntry['kind'] { const t = mode & 0o170000; return t === 0o100000 ? 'file' : t === 0o040000 ? 'dir' : t === 0o120000 ? 'symlink' : 'other'; }

export function isCpio(b: Uint8Array): boolean {
  return b.length >= 6 && b[0] === 0x30 && b[1] === 0x37 && b[2] === 0x30 && b[3] === 0x37 && b[4] === 0x30 && (b[5] === 0x37 || b[5] === 0x31 || b[5] === 0x32);
}

/** List entries up to the TRAILER!!! record. */
export function listCpio(b: Uint8Array, maxEntries = 100_000): { entries: CpioEntry[]; truncated: boolean; error?: string } {
  const out: CpioEntry[] = [];
  let o = 0;
  while (o + 6 <= b.length) {
    if (out.length >= maxEntries) return { entries: out, truncated: true };
    const magic = decodeUtf8(b.subarray(o, o + 6));
    let mode: number, uid: number, gid: number, mtime: number, nameSize: number, size: number, dataStart: number, name: string;
    if (magic === '070707') {
      if (o + 76 > b.length) return { entries: out, truncated: false, error: 'truncated odc header' };
      mode = octal(b, o + 18, 6); uid = octal(b, o + 24, 6); gid = octal(b, o + 30, 6);
      mtime = octal(b, o + 48, 11); nameSize = octal(b, o + 59, 6); size = octal(b, o + 65, 11);
      if (!Number.isFinite(nameSize + size + mode)) return { entries: out, truncated: false, error: `bad odc header at ${o}` };
      const ns = o + 76;
      name = decodeUtf8(b.subarray(ns, Math.min(b.length, ns + Math.max(0, nameSize - 1))));
      dataStart = ns + nameSize;
      if (name === 'TRAILER!!!') break;
      pushEntry(out, b, name, mode, uid, gid, mtime, size, dataStart);
      o = dataStart + size;
    } else if (magic === '070701' || magic === '070702') {
      if (o + 110 > b.length) return { entries: out, truncated: false, error: 'truncated newc header' };
      mode = hexn(b, o + 14, 8); uid = hexn(b, o + 22, 8); gid = hexn(b, o + 30, 8); mtime = hexn(b, o + 46, 8);
      size = hexn(b, o + 54, 8); nameSize = hexn(b, o + 94, 8);
      if (!Number.isFinite(nameSize + size + mode)) return { entries: out, truncated: false, error: `bad newc header at ${o}` };
      const ns = o + 110;
      name = decodeUtf8(b.subarray(ns, Math.min(b.length, ns + Math.max(0, nameSize - 1))));
      dataStart = (ns + nameSize + 3) & ~3;
      if (name === 'TRAILER!!!') break;
      pushEntry(out, b, name, mode, uid, gid, mtime, size, dataStart);
      o = (dataStart + size + 3) & ~3;
    } else return { entries: out, truncated: false, error: `unknown cpio header at ${o}` };
  }
  return { entries: out, truncated: false };
}

function pushEntry(out: CpioEntry[], b: Uint8Array, name: string, mode: number, uid: number, gid: number, mtime: number, size: number, dataStart: number): void {
  const e: CpioEntry = { name, mode, kind: kindOf(mode), uid, gid, mtime, size, offset: dataStart };
  if (e.kind === 'symlink' && dataStart + size <= b.length) e.link = decodeUtf8(b.subarray(dataStart, dataStart + Math.min(size, 4096)));
  out.push(e);
}
