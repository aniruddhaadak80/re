// Minimal PE reader: just enough to locate sections, data directories and the CLI header.
import { ByteReader, ParseError, latin1 } from '../util.js';

export interface PeSection { name: string; vaddr: number; vsize: number; rawOffset: number; rawSize: number; characteristics: number }
export interface PeDataDir { rva: number; size: number }
export interface PeImage {
  bytes: Uint8Array;
  machine: number;
  is64: boolean;
  characteristics: number;
  subsystem: number;
  imageBase: bigint;
  entryRva: number;
  sections: PeSection[];
  dirs: PeDataDir[];
  /** end of the last section's raw data; bytes after it are overlay */
  overlayOffset: number;
  timestamp: number;
}

export const MACHINES: Record<number, string> = {
  0x14c: 'i386', 0x8664: 'amd64', 0xaa64: 'arm64', 0x1c4: 'armnt', 0x200: 'ia64', 0: 'unknown',
  // ReadyToRun images xor the machine with an OS specific value.
  [0x14c ^ 0x7b79]: 'i386 (linux r2r)', [0x8664 ^ 0x7b79]: 'amd64 (linux r2r)', [0xaa64 ^ 0x7b79]: 'arm64 (linux r2r)',
  [0x14c ^ 0x4644]: 'i386 (macos r2r)', [0x8664 ^ 0x4644]: 'amd64 (macos r2r)', [0xaa64 ^ 0x4644]: 'arm64 (macos r2r)',
  [0x8664 ^ 0xadc4]: 'amd64 (freebsd r2r)', [0xaa64 ^ 0xadc4]: 'arm64 (freebsd r2r)',
  [0x8664 ^ 0x1993]: 'amd64 (netbsd r2r)',
};

export function isPe(bytes: Uint8Array): boolean {
  if (bytes.length < 0x40 || bytes[0] !== 0x4d || bytes[1] !== 0x5a) return false;
  const lfanew = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(0x3c, true);
  return lfanew + 24 <= bytes.length && bytes[lfanew] === 0x50 && bytes[lfanew + 1] === 0x45 && bytes[lfanew + 2] === 0 && bytes[lfanew + 3] === 0;
}

export function parsePe(bytes: Uint8Array): PeImage {
  if (!isPe(bytes)) throw new ParseError('not a PE file');
  const r = new ByteReader(bytes);
  const lfanew = r.seek(0x3c).u32();
  r.seek(lfanew + 4);
  const machine = r.u16();
  const nsec = r.u16();
  const timestamp = r.u32();
  r.skip(8);
  const optSize = r.u16();
  const characteristics = r.u16();
  const optStart = r.pos;
  const magic = r.u16();
  if (magic !== 0x10b && magic !== 0x20b) throw new ParseError('bad optional header magic', optStart);
  const is64 = magic === 0x20b;
  r.seek(optStart + 16);
  const entryRva = r.u32();
  let imageBase: bigint;
  if (is64) { r.seek(optStart + 24); imageBase = r.u64(); } else { r.seek(optStart + 28); imageBase = BigInt(r.u32()); }
  r.seek(optStart + 68);
  const subsystem = r.u16();
  r.seek(optStart + (is64 ? 108 : 92));
  const ndirs = Math.min(r.u32(), 16);
  const dirs: PeDataDir[] = [];
  for (let i = 0; i < ndirs; i++) dirs.push({ rva: r.u32(), size: r.u32() });
  r.seek(optStart + optSize);
  const sections: PeSection[] = [];
  let overlayOffset = 0;
  for (let i = 0; i < Math.min(nsec, 96); i++) {
    const name = latin1(r.take(8)).replace(/\0+$/, '');
    const vsize = r.u32(); const vaddr = r.u32(); const rawSize = r.u32(); const rawOffset = r.u32();
    r.skip(12);
    const ch = r.u32();
    sections.push({ name, vaddr, vsize, rawOffset, rawSize, characteristics: ch });
    if (rawSize > 0) overlayOffset = Math.max(overlayOffset, rawOffset + rawSize);
  }
  return { bytes, machine, is64, characteristics, subsystem, imageBase, entryRva, sections, dirs, overlayOffset: Math.min(overlayOffset, bytes.length), timestamp };
}

/** Map an RVA to a file offset, or -1 when it does not land in any section. */
export function rvaToOffset(pe: PeImage, rva: number): number {
  for (const s of pe.sections) {
    const span = Math.max(s.vsize, s.rawSize);
    if (rva >= s.vaddr && rva < s.vaddr + span) {
      const off = rva - s.vaddr;
      if (off >= s.rawSize) return -1;
      return s.rawOffset + off;
    }
  }
  // Headers are mapped at RVA 0.
  if (pe.sections.length && rva < (pe.sections[0]?.rawOffset ?? 0)) return rva;
  return -1;
}

export function sectionOf(pe: PeImage, rva: number): string | undefined {
  for (const s of pe.sections) if (rva >= s.vaddr && rva < s.vaddr + Math.max(s.vsize, s.rawSize)) return s.name;
  return undefined;
}
