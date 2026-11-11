// PE/COFF loader: sections, exports, imports (IAT slots), delay imports, .pdata function table, COFF symbols.
import { BR } from '../util.js';
import type { Arch, BinaryImage, FunctionHint, ImportRef, SectionInfo, Sym } from '../types.js';

const MAX_SECTIONS = 256;
const MAX_IMPORT_DLLS = 4096;
const MAX_THUNKS = 65536;

export function loadPe(bytes: Uint8Array): BinaryImage {
  const r = new BR(bytes, true);
  const warnings: string[] = [];
  const pe = r.u32(0x3c);
  const machine = r.u16(pe + 4);
  const arch: Arch = machine === 0x8664 ? 'x86_64' : machine === 0x14c ? 'x86' : machine === 0xaa64 ? 'arm64' : (machine === 0x1c0 || machine === 0x1c4 || machine === 0x1c2) ? 'arm' : 'unknown';
  const nsec = Math.min(r.u16(pe + 6), MAX_SECTIONS);
  const symPtr = r.u32(pe + 12);
  const nsyms = r.u32(pe + 16);
  const optSize = r.u16(pe + 20);
  const opt = pe + 24;
  const magic = r.u16(opt);
  const plus = magic === 0x20b;
  const bits: 32 | 64 = plus ? 64 : 32;
  const entryRva = r.u32(opt + 16);
  const imageBase = plus ? r.u64(opt + 24) : r.u32(opt + 28);
  const ndirs = Math.min(r.u32(opt + (plus ? 108 : 92)), 16);
  const dirBase = opt + (plus ? 112 : 96);
  const dir = (i: number): { rva: number; size: number } => i < ndirs ? { rva: r.u32(dirBase + i * 8), size: r.u32(dirBase + i * 8 + 4) } : { rva: 0, size: 0 };

  const secBase = opt + optSize;
  const raw: { name: string; va: number; vsize: number; ptr: number; rawSize: number; ch: number }[] = [];
  for (let i = 0; i < nsec; i++) {
    const o = secBase + i * 40;
    if (!r.ok(o, 40)) break;
    raw.push({ name: r.fixstr(o, 8), vsize: r.u32(o + 8), va: r.u32(o + 12), rawSize: r.u32(o + 16), ptr: r.u32(o + 20), ch: r.u32(o + 36) });
  }
  const sections: SectionInfo[] = raw.map((s) => {
    const size = Math.max(s.vsize || s.rawSize, 0);
    return {
      name: s.name, vaddr: imageBase + s.va, size, offset: s.ptr,
      fsize: Math.max(0, Math.min(s.rawSize, size, bytes.length - s.ptr)),
      exec: (s.ch & 0x20000000) !== 0 || (s.ch & 0x20) !== 0,
      write: (s.ch & 0x80000000) !== 0,
    };
  });
  // headers are mapped too
  const hdrSize = plus ? r.u32(opt + 60) : r.u32(opt + 60);
  const segments = [{ name: 'HEADERS', vaddr: imageBase, vsize: Math.min(hdrSize || 0x1000, 0x10000), offset: 0, fsize: Math.min(hdrSize || 0x1000, bytes.length), r: true, w: false, x: false }];

  const rvaToOff = (rva: number): number => {
    for (const s of raw) {
      const size = Math.max(s.vsize, s.rawSize);
      if (rva >= s.va && rva < s.va + size) {
        const d = rva - s.va;
        return d < s.rawSize ? s.ptr + d : -1;
      }
    }
    return rva < (hdrSize || 0x1000) ? rva : -1;
  };
  const strAt = (rva: number, max = 512): string => { const o = rvaToOff(rva); return o < 0 ? '' : r.cstr(o, max); };

  const symbols: Sym[] = [];
  // exports
  const ed = dir(0);
  if (ed.rva) {
    const o = rvaToOff(ed.rva);
    if (o >= 0) {
      const nfun = Math.min(r.u32(o + 20), 1_000_000);
      const nnames = Math.min(r.u32(o + 24), 1_000_000);
      const funcs = rvaToOff(r.u32(o + 28));
      const names = rvaToOff(r.u32(o + 32));
      const ords = rvaToOff(r.u32(o + 36));
      const named = new Set<number>();
      for (let i = 0; i < nnames && names >= 0 && ords >= 0 && funcs >= 0; i++) {
        const ord = r.u16(ords + i * 2);
        if (ord >= nfun) continue;
        const frva = r.u32(funcs + ord * 4);
        if (!frva || (frva >= ed.rva && frva < ed.rva + ed.size)) continue; // forwarder
        named.add(ord);
        const name = strAt(r.u32(names + i * 4));
        if (name) symbols.push({ addr: imageBase + frva, name, kind: 'func', source: 'export' });
      }
    }
  }

  // imports
  const imports: ImportRef[] = [];
  const readThunks = (dll: string, lookupRva: number, iatRva: number) => {
    const lo = rvaToOff(lookupRva || iatRva);
    if (lo < 0) return;
    const ps = bits / 8;
    for (let j = 0; j < MAX_THUNKS; j++) {
      const v = r.ptr(lo + j * ps, bits);
      if (!r.ok(lo + j * ps, ps) || v === 0) break;
      const ordinal = bits === 64 ? v >= 2 ** 63 : (v & 0x80000000) !== 0;
      const name = ordinal ? `${dll}#${v % 65536}` : strAt((v % 2 ** 31) + 2, 256);
      imports.push({ name: name || `${dll}#?`, library: dll, slot: imageBase + iatRva + j * ps });
    }
  };
  const id = dir(1);
  if (id.rva) {
    const o = rvaToOff(id.rva);
    for (let i = 0; o >= 0 && i < MAX_IMPORT_DLLS; i++) {
      const d = o + i * 20;
      if (!r.ok(d, 20)) break;
      const oft = r.u32(d), nameRva = r.u32(d + 12), ft = r.u32(d + 16);
      if (!oft && !nameRva && !ft) break;
      readThunks(strAt(nameRva, 256), oft, ft);
    }
  }
  const dd = dir(13);
  if (dd.rva) {
    const o = rvaToOff(dd.rva);
    for (let i = 0; o >= 0 && i < MAX_IMPORT_DLLS; i++) {
      const d = o + i * 32;
      if (!r.ok(d, 32)) break;
      const attrs = r.u32(d), nameRva = r.u32(d + 4), iat = r.u32(d + 12), int = r.u32(d + 16);
      if (!nameRva) break;
      const rel = (x: number) => (attrs & 1) ? x : x - imageBase;
      readThunks(strAt(rel(nameRva), 256), rel(int), rel(iat));
    }
  }

  // exception directory
  const hints: FunctionHint[] = [];
  const xd = dir(3);
  if (xd.rva && (arch === 'x86_64' || arch === 'arm64')) {
    const o = rvaToOff(xd.rva);
    const ent = arch === 'x86_64' ? 12 : 8;
    const n = Math.min(Math.floor(xd.size / ent), 1_000_000);
    for (let i = 0; o >= 0 && i < n; i++) {
      const e = o + i * ent;
      if (!r.ok(e, ent)) break;
      const begin = r.u32(e);
      if (!begin) continue;
      if (arch === 'x86_64') {
        const end = r.u32(e + 4);
        hints.push({ addr: imageBase + begin, size: end > begin ? end - begin : undefined, source: 'pdata' });
      } else {
        const data = r.u32(e + 4);
        const len = (data & 3) !== 0 ? ((data >>> 2) & 0x7ff) * 4 : undefined;
        hints.push({ addr: imageBase + begin, size: len, source: 'pdata' });
      }
    }
  }

  // COFF symbol table (MinGW and other GNU toolchains keep it)
  if (symPtr && nsyms && nsyms < 4_000_000 && r.ok(symPtr, nsyms * 18)) {
    const strTab = symPtr + nsyms * 18;
    for (let i = 0; i < nsyms; i++) {
      const o = symPtr + i * 18;
      const aux = r.u8(o + 17);
      const secNum = (r.u16(o + 12) << 16) >> 16;
      const type = r.u16(o + 14);
      const cls = r.u8(o + 16);
      const value = r.u32(o + 8);
      const name = r.u32(o) === 0 ? r.cstr(strTab + r.u32(o + 4), 512) : r.fixstr(o, 8);
      i += aux;
      if (secNum <= 0 || secNum > raw.length || (cls !== 2 && cls !== 3 && cls !== 6)) continue;
      if (!name || name.startsWith('.') || name.startsWith('$')) continue;
      const s = raw[secNum - 1]!;
      const isFunc = (type & 0x30) === 0x20 || sections[secNum - 1]!.exec;
      symbols.push({ addr: imageBase + s.va + value, name, kind: isFunc ? 'func' : 'object', source: 'coff' });
    }
  }
  if (machine === 0x1c0 || machine === 0x1c4) warnings.push('ARM PE: code is assumed to be Thumb-2');

  return {
    format: 'pe', arch, bits, endian: 'le',
    entry: entryRva ? imageBase + entryRva : undefined,
    entryThumb: arch === 'arm' ? true : undefined,
    imageBase, segments, sections, symbols, imports, hints,
    bytes, fileOffset: 0, warnings,
  };
}
