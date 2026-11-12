// Dart AOT snapshots (Flutter libapp.so, iOS App.framework/App, dart compile aot-snapshot output):
// snapshot headers (kind, version hash, feature flags), the string pool read from the read only
// object image, package and library URIs, and function names with addresses when the ELF still has
// its static symbol table (unstripped builds or Flutter --split-debug-info symbol files).
//
// Full object pool and class table recovery needs a cluster deserializer built for the exact
// Dart SDK version (the cluster layout changes between releases); that part is reported as partial.

import { ParseError } from '../util.js';

export interface DartSnapshotHeader {
  symbol?: string; offset: number; size?: number; magicOk: boolean; length: number; kind: number; kindName: string;
  hash: string | null; features: string[]; arch?: string; os?: string; compressedPointers?: boolean; nullSafety?: boolean | null; product?: boolean;
}
export interface DartString { offset: number; value: string; twoByte: boolean; blob: string }
export interface DartFunction { name: string; addr: number; size: number; kind: 'function' | 'stub' | 'other' }
export interface DartAotInfo {
  container: 'elf' | 'macho' | 'raw'; snapshots: DartSnapshotHeader[]; dartVersionHint?: string;
  strings: DartString[]; stringLayout?: { cid: number; dataOffset: number; lengthSize: number; alignment: number };
  libraries: string[]; packages: string[]; functions: DartFunction[]; functionSource: 'elf-symtab' | 'none';
  partial: string[]; notes: string[];
}

const KINDS = ['Full', 'FullCore', 'FullJIT', 'FullAOT', 'None', 'Invalid'];
const MAGIC = 0xdcdcf5f5;
const SYMS = ['_kDartVmSnapshotData', '_kDartVmSnapshotInstructions', '_kDartIsolateSnapshotData', '_kDartIsolateSnapshotInstructions'];

interface Region { name: string; offset: number; size: number }
interface ElfLite { regions: Region[]; symtab: { name: string; value: number; size: number; type: number }[]; vaToOff: (va: number) => number; is64: boolean }

function readElf(b: Uint8Array): ElfLite | undefined {
  if (b.length < 52 || b[0] !== 0x7f || b[1] !== 0x45 || b[2] !== 0x4c || b[3] !== 0x46) return undefined;
  const is64 = b[4] === 2, le = b[5] === 1;
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const need = (o: number, n: number) => { if (o < 0 || o + n > b.length) throw new ParseError('ELF read out of range', o); };
  const u16 = (o: number) => { need(o, 2); return dv.getUint16(o, le); };
  const u32 = (o: number) => { need(o, 4); return dv.getUint32(o, le); };
  const uw = (o: number) => { if (!is64) return u32(o); need(o, 8); const lo = dv.getUint32(o + (le ? 0 : 4), le), hi = dv.getUint32(o + (le ? 4 : 0), le); return hi * 0x100000000 + lo; };
  const shoff = uw(is64 ? 0x28 : 0x20), shentsize = u16(is64 ? 0x3a : 0x2e), shnum = Math.min(u16(is64 ? 0x3c : 0x30), 4096);
  const phoff = uw(is64 ? 0x20 : 0x1c), phentsize = u16(is64 ? 0x36 : 0x2a), phnum = Math.min(u16(is64 ? 0x38 : 0x2c), 1024);
  const loads: { va: number; off: number; filesz: number }[] = [];
  for (let i = 0; i < phnum; i++) {
    const p = phoff + i * phentsize;
    if (p + phentsize > b.length) break;
    if (u32(p) !== 1) continue;
    loads.push(is64 ? { off: uw(p + 8), va: uw(p + 16), filesz: uw(p + 32) } : { off: u32(p + 4), va: u32(p + 8), filesz: u32(p + 16) });
  }
  const vaToOff = (va: number) => { for (const l of loads) if (va >= l.va && va < l.va + l.filesz) return l.off + (va - l.va); return -1; };
  const sections: { type: number; offset: number; size: number; link: number; entsize: number }[] = [];
  for (let i = 0; i < shnum; i++) {
    const s = shoff + i * shentsize;
    if (s + shentsize > b.length) break;
    sections.push({ type: u32(s + 4), offset: uw(is64 ? s + 0x18 : s + 0x10), size: uw(is64 ? s + 0x20 : s + 0x14), link: u32(is64 ? s + 0x28 : s + 0x18), entsize: uw(is64 ? s + 0x38 : s + 0x24) });
  }
  const readSyms = (type: number) => {
    const out: { name: string; value: number; size: number; type: number }[] = [];
    for (const s of sections) {
      if (s.type !== type) continue;
      const str = sections[s.link];
      if (!str) continue;
      const ent = is64 ? 24 : 16;
      const n = Math.min(Math.floor(s.size / ent), 2_000_000);
      for (let i = 1; i < n; i++) {
        const e = s.offset + i * ent;
        if (e + ent > b.length) break;
        const nameOff = u32(e);
        const info = is64 ? b[e + 4]! : b[e + 12]!;
        const value = is64 ? uw(e + 8) : u32(e + 4), size = is64 ? uw(e + 16) : u32(e + 8);
        const so = str.offset + nameOff;
        if (nameOff >= str.size || so >= b.length) continue;
        let k = so; while (k < b.length && k < so + 4096 && b[k] !== 0) k++;
        out.push({ name: new TextDecoder().decode(b.subarray(so, k)), value, size, type: info & 0xf });
      }
    }
    return out;
  };
  const dyn = readSyms(11);
  const regions: Region[] = [];
  for (const s of [...dyn, ...readSyms(2)]) {
    if (!SYMS.includes(s.name) || regions.some((r) => r.name === s.name)) continue;
    const off = vaToOff(s.value);
    if (off >= 0) regions.push({ name: s.name, offset: off, size: Math.min(s.size || b.length - off, b.length - off) });
  }
  return { regions, symtab: readSyms(2), vaToOff, is64 };
}

function readHeader(b: Uint8Array, offset: number, symbol?: string, size?: number): DartSnapshotHeader {
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const h: DartSnapshotHeader = { symbol, offset, size, magicOk: false, length: 0, kind: -1, kindName: 'unknown', hash: null, features: [] };
  if (offset + 20 > b.length) return h;
  h.magicOk = dv.getUint32(offset, true) === MAGIC;
  if (!h.magicOk) return h;
  h.length = dv.getUint32(offset + 4, true) + dv.getUint32(offset + 8, true) * 0x100000000;
  h.kind = dv.getUint32(offset + 12, true);
  h.kindName = KINDS[h.kind] ?? `kind ${h.kind}`;
  if (offset + 52 <= b.length) {
    const hash = String.fromCharCode(...b.subarray(offset + 20, offset + 52));
    h.hash = /^[0-9a-f]{32}$/.test(hash) ? hash : null;
    let k = offset + 52; const end = Math.min(b.length, k + 1024);
    while (k < end && b[k] !== 0) k++;
    const feat = new TextDecoder().decode(b.subarray(offset + 52, k));
    h.features = feat.split(' ').filter(Boolean);
    for (const f of h.features) {
      if (['arm64', 'x64', 'arm', 'ia32', 'riscv64', 'riscv32'].includes(f)) h.arch = f;
      else if (['android', 'ios', 'linux', 'macos', 'windows', 'fuchsia'].includes(f)) h.os = f;
      else if (f === 'compressed-pointers') h.compressedPointers = true;
      else if (f === 'no-compressed-pointers') h.compressedPointers = false;
      else if (f === 'null-safety') h.nullSafety = true;
      else if (f === 'no-null-safety') h.nullSafety = false;
      else if (f === 'product') h.product = true;
      else if (f === 'no-product') h.product = false;
    }
    if (h.nullSafety === undefined && h.features.length) h.nullSafety = null; // Dart 3 is always sound and drops the flag
  }
  return h;
}

/** Find Dart string objects inside one data blob. Layout and class id are found from the data itself. */
export function scanDartStrings(b: Uint8Array, region: Region, opts: { word?: 4 | 8; compressed?: boolean; maxStrings?: number } = {}): { strings: DartString[]; layout?: DartAotInfo['stringLayout'] } {
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const end = Math.min(b.length, region.offset + region.size);
  const candidates = opts.word === 4 ? [{ dataOffset: 12, lengthOff: 4, lengthSize: 4, alignment: 8 }]
    : opts.compressed ? [{ dataOffset: 12, lengthOff: 8, lengthSize: 4, alignment: 16 }]
      : [{ dataOffset: 16, lengthOff: 8, lengthSize: 8, alignment: 16 }, { dataOffset: 12, lengthOff: 8, lengthSize: 4, alignment: 16 }, { dataOffset: 12, lengthOff: 4, lengthSize: 4, alignment: 8 }];
  const max = opts.maxStrings ?? 500000;
  let best: { layout: typeof candidates[number]; cid: number; hits: number } | undefined;
  // pass 1: vote for the (layout, class id) pair that explains the most well formed one byte strings
  for (const L of candidates) {
    const votes = new Map<number, number>();
    for (let o = region.offset + ((L.alignment - (region.offset % L.alignment)) % L.alignment); o + L.dataOffset < end; o += L.alignment) {
      const tags = dv.getUint32(o, true);
      const sizeTag = (tags >>> 8) & 0xf;
      const cid = tags >>> 12;
      if (cid < 20 || cid > 4000 || sizeTag === 0) continue;
      const lenRaw = L.lengthSize === 8 ? dv.getUint32(o + L.lengthOff, true) + (dv.getUint32(o + L.lengthOff + 4, true) ? 1e12 : 0) : dv.getUint32(o + L.lengthOff, true);
      if (lenRaw & 1) continue;
      const len = lenRaw / 2;
      if (len < 1 || o + L.dataOffset + len > end) continue;
      const need = Math.ceil((L.dataOffset + len) / L.alignment);
      if (need !== sizeTag) continue;
      let ok = true;
      for (let i = 0; i < len; i++) { const c = b[o + L.dataOffset + i]!; if (c < 0x09 || (c > 0x0d && c < 0x20) || c > 0x7e) { ok = false; break; } }
      if (ok) votes.set(cid, (votes.get(cid) ?? 0) + 1);
    }
    for (const [cid, hits] of votes) if (!best || hits > best.hits) best = { layout: L, cid, hits };
  }
  if (!best || best.hits < 3) return { strings: [] };
  const L = best.layout, oneCid = best.cid, twoCid = best.cid + 1;
  const out: DartString[] = [];
  for (let o = region.offset + ((L.alignment - (region.offset % L.alignment)) % L.alignment); o + L.dataOffset <= end && out.length < max; o += L.alignment) {
    const tags = dv.getUint32(o, true);
    const cid = tags >>> 12;
    if (cid !== oneCid && cid !== twoCid) continue;
    const lenRaw = L.lengthSize === 8 ? (dv.getUint32(o + L.lengthOff + 4, true) ? -1 : dv.getUint32(o + L.lengthOff, true)) : dv.getUint32(o + L.lengthOff, true);
    if (lenRaw < 0 || lenRaw & 1) continue;
    const len = lenRaw / 2;
    const two = cid === twoCid;
    const bytes = two ? len * 2 : len;
    if (o + L.dataOffset + bytes > end) continue;
    const sizeTag = (tags >>> 8) & 0xf;
    const need = Math.ceil((L.dataOffset + bytes) / L.alignment);
    if (sizeTag !== 0 ? need !== sizeTag : need < 16) continue;
    let value = '';
    if (two) for (let i = 0; i < len; i++) value += String.fromCharCode(dv.getUint16(o + L.dataOffset + i * 2, true));
    else for (let i = 0; i < len; i++) value += String.fromCharCode(b[o + L.dataOffset + i]!);
    if (sizeTag === 0 && !two && /[\x00-\x08\x0e-\x1f]/.test(value)) continue;
    out.push({ offset: o, value, twoByte: two, blob: region.name });
    o += (need - 1) * L.alignment;
  }
  // the empty string has no payload: count it once when the class id has a zero length object
  return { strings: out, layout: { cid: oneCid, dataOffset: L.dataOffset, lengthSize: L.lengthSize, alignment: L.alignment } };
}

/** Find the Dart version text in a companion binary (libflutter.so, Flutter.framework, the dart executable). */
export function dartVersionFrom(b: Uint8Array, hash?: string | null): string | undefined {
  const text = new TextDecoder('latin1').decode(b.length > 64 << 20 ? b.subarray(0, 64 << 20) : b);
  const m = /(\d+\.\d+\.\d+(?:-[0-9A-Za-z.]{1,40})?) \((stable|beta|dev|main|be)\) \([^)\n]{4,60}\)/.exec(text);
  if (m) return m[0];
  if (hash && text.includes(hash)) return `engine contains snapshot hash ${hash}`;
  return undefined;
}

/** Inspect a Dart AOT snapshot container. */
export function inspectDartAot(b: Uint8Array, opts: { companion?: Uint8Array; maxStrings?: number } = {}): DartAotInfo {
  const info: DartAotInfo = { container: 'raw', snapshots: [], strings: [], libraries: [], packages: [], functions: [], functionSource: 'none', partial: [], notes: [] };
  let regions: Region[] = [];
  const elf = readElf(b);
  if (elf) {
    info.container = 'elf';
    regions = elf.regions;
    const funcs = elf.symtab.filter((s) => s.type === 2 && s.size > 0);
    if (funcs.length) {
      info.functionSource = 'elf-symtab';
      info.functions = funcs.map((s) => ({ name: s.name, addr: s.value, size: s.size, kind: s.name.startsWith('stub ') ? 'stub' : 'function' }));
    }
  } else if (b.length > 4 && (new DataView(b.buffer, b.byteOffset).getUint32(0, false) === 0xcffaedfe || new DataView(b.buffer, b.byteOffset).getUint32(0, false) === 0xcafebabe)) {
    info.container = 'macho';
  }
  if (!regions.length) {
    // no symbols (Mach-O App binary or a raw blob): find snapshot magics directly
    const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
    const found: number[] = [];
    for (let o = 0; o + 52 <= b.length && found.length < 8; o += 4) if (dv.getUint32(o, true) === MAGIC && /^[0-9a-f]{32}$/.test(String.fromCharCode(...b.subarray(o + 20, o + 52)))) found.push(o);
    regions = found.map((o, i) => ({ name: i === 0 ? '_kDartVmSnapshotData' : i === 1 ? '_kDartIsolateSnapshotData' : `snapshot ${i}`, offset: o, size: (found[i + 1] ?? b.length) - o }));
    if (found.length) info.notes.push('snapshot blobs located by magic, not by symbol');
  }
  for (const r of regions) {
    if (r.name.endsWith('Instructions')) { info.snapshots.push({ symbol: r.name, offset: r.offset, size: r.size, magicOk: false, length: r.size, kind: -1, kindName: 'instructions', hash: null, features: [] }); continue; }
    info.snapshots.push(readHeader(b, r.offset, r.name, r.size));
  }
  const data = info.snapshots.find((s) => s.symbol === '_kDartIsolateSnapshotData' && s.magicOk) ?? info.snapshots.find((s) => s.magicOk);
  if (!data) { info.partial.push('no Dart snapshot header found'); return info; }
  const word: 4 | 8 = data.arch === 'arm' || data.arch === 'ia32' || data.arch === 'riscv32' ? 4 : 8;
  const seen = new Set<string>();
  for (const r of regions.filter((x) => x.name.endsWith('Data'))) {
    const s = scanDartStrings(b, r, { word, compressed: data.compressedPointers, maxStrings: opts.maxStrings });
    if (s.layout && !info.stringLayout) info.stringLayout = s.layout;
    for (const x of s.strings) {
      const key = x.value;
      info.strings.push(x);
      if (seen.has(key)) continue;
      seen.add(key);
      if (/^(package|dart|file):/.test(x.value) && x.value.length < 400) info.libraries.push(x.value);
    }
  }
  info.packages = [...new Set(info.libraries.filter((l) => l.startsWith('package:')).map((l) => l.slice(8).split('/')[0]!))].sort();
  info.libraries.sort();
  if (opts.companion) { const v = dartVersionFrom(opts.companion, data.hash); if (v) info.dartVersionHint = v; }
  if (info.functionSource === 'none') info.partial.push('function names with addresses need the ELF static symbols (unstripped build or the --split-debug-info symbol file); a stripped snapshot keeps them only inside version specific clusters');
  info.partial.push('object pool and class table are not deserialized: the cluster format is specific to each Dart SDK release');
  return info;
}
