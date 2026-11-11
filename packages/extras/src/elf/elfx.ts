// ELF extras: notes (build-id, ABI tag, GNU properties, Go build id, FDO package metadata,
// SystemTap probes), init/fini arrays with RELATIVE relocation resolution, Linux kernel
// modules (.modinfo, __versions, signature trailer) and embedded kernel config (IKCFG).

import { View, toHex, indexOfBytes, ascii, inflate, ParseError } from '../util.js';
import { parseElf, elfSymbols, vaToOffset, type BinImage } from '../bin/container.js';
import { derAt, children, x509Name, intHex, oid } from '../asn1.js';

export interface ElfNote { owner: string; type: number; typeName: string; offset: number; descSize: number; section?: string; decoded?: Record<string, unknown> }

const GNU_TYPES: Record<number, string> = { 1: 'NT_GNU_ABI_TAG', 2: 'NT_GNU_HWCAP', 3: 'NT_GNU_BUILD_ID', 4: 'NT_GNU_GOLD_VERSION', 5: 'NT_GNU_PROPERTY_TYPE_0' };
const ABI_OS: Record<number, string> = { 0: 'Linux', 1: 'Hurd', 2: 'Solaris', 3: 'FreeBSD', 4: 'NetBSD', 5: 'Syllable' };

function decodeNote(owner: string, type: number, desc: Uint8Array, le: boolean, bits: number): { typeName: string; decoded?: Record<string, unknown> } {
  const v = new View(desc, le);
  const td = new TextDecoder();
  if (owner === 'GNU') {
    const typeName = GNU_TYPES[type] ?? `GNU ${type}`;
    if (type === 3) return { typeName, decoded: { buildId: toHex(desc) } };
    if (type === 1 && desc.length >= 16) return { typeName, decoded: { os: ABI_OS[v.u32(0)] ?? v.u32(0), abi: `${v.u32(4)}.${v.u32(8)}.${v.u32(12)}` } };
    if (type === 4) return { typeName, decoded: { gold: td.decode(desc).replace(/\0+$/, '') } };
    if (type === 5) {
      const props: Record<string, unknown>[] = [];
      const align = bits === 64 ? 8 : 4;
      let p = 0;
      while (p + 8 <= desc.length && props.length < 64) {
        const t = v.u32(p), sz = v.u32(p + 4);
        if (p + 8 + sz > desc.length) break;
        const data = sz >= 4 ? v.u32(p + 8) : 0;
        const prop: Record<string, unknown> = { type: `0x${t.toString(16)}`, value: data };
        if (t === 0xc0000002) { prop.name = 'X86_FEATURE_1_AND'; prop.features = [data & 1 ? 'IBT' : '', data & 2 ? 'SHSTK' : ''].filter(Boolean); }
        else if (t === 0xc0000000) { prop.name = 'AARCH64_FEATURE_1_AND'; prop.features = [data & 1 ? 'BTI' : '', data & 2 ? 'PAC' : '', data & 4 ? 'GCS' : ''].filter(Boolean); }
        else if (t === 0xc0008002) prop.name = 'X86_ISA_1_NEEDED';
        else if (t === 0xc0008001) prop.name = 'X86_ISA_1_USED';
        props.push(prop);
        p += 8 + Math.ceil(sz / align) * align;
      }
      return { typeName, decoded: { properties: props } };
    }
    return { typeName };
  }
  if (owner === 'Go' && type === 4) return { typeName: 'GO_BUILDID', decoded: { goBuildId: td.decode(desc).replace(/\0+$/, '') } };
  if (owner === 'FDO' && type === 0xcafe1a7e) {
    const text = td.decode(desc).replace(/\0+$/, '');
    let json: unknown = null;
    try { json = JSON.parse(text); } catch { json = null; }
    return { typeName: 'FDO_PACKAGING_METADATA', decoded: { text, json } };
  }
  if (owner === 'FDO' && type === 0x407c0c0a) return { typeName: 'FDO_DLOPEN_METADATA', decoded: { text: td.decode(desc).replace(/\0+$/, '') } };
  if (owner === 'stapsdt' && type === 3) {
    const ps = bits === 64 ? 8 : 4;
    try {
      let p = 3 * ps;
      const prov = v.cstr(p, 256); p += prov.length + 1;
      const name = v.cstr(p, 256); p += name.length + 1;
      const args = v.cstr(p, 1024);
      return { typeName: 'NT_STAPSDT', decoded: { provider: prov, name, args, pc: v.uN(0, ps) } };
    } catch { return { typeName: 'NT_STAPSDT' }; }
  }
  if (owner === 'Android' && type === 1 && desc.length >= 4) return { typeName: 'ANDROID_IDENT', decoded: { apiLevel: v.u32(0) } };
  return { typeName: `${owner} ${type}` };
}

function parseNotes(v: View, off: number, size: number, le: boolean, bits: number, section?: string): ElfNote[] {
  const out: ElfNote[] = [];
  let p = off;
  const end = Math.min(off + size, v.length);
  const a = 4;
  while (p + 12 <= end && out.length < 1024) {
    const namesz = v.u32(p, le), descsz = v.u32(p + 4, le), type = v.u32(p + 8, le);
    const nameOff = p + 12;
    const descOff = nameOff + Math.ceil(namesz / a) * a;
    if (namesz > 4096 || descsz > (1 << 24) || descOff + descsz > end) break;
    const owner = namesz ? new TextDecoder().decode(v.sub(nameOff, namesz)).replace(/\0+$/, '') : '';
    const d = decodeNote(owner, type, v.sub(descOff, descsz), le, bits);
    out.push({ owner, type, typeName: d.typeName, offset: p, descSize: descsz, ...(section ? { section } : {}), ...(d.decoded ? { decoded: d.decoded } : {}) });
    p = descOff + Math.ceil(descsz / a) * a;
  }
  return out;
}

/** All notes from SHT_NOTE sections, or from PT_NOTE segments when there are no section headers. */
export function elfNotes(bytes: Uint8Array): ElfNote[] {
  const img = parseElf(bytes);
  const v = img.view;
  const out: ElfNote[] = [];
  const noteSecs = img.sections.filter((s) => s.type === 7 && s.size);
  if (noteSecs.length) {
    for (const s of noteSecs) out.push(...parseNotes(v, s.offset, s.size, img.le, img.bits, s.name));
    return out;
  }
  for (const sg of img.segments) if (sg.ptype === 4) out.push(...parseNotes(v, sg.offset, sg.size, img.le, img.bits));
  return out;
}

// ---------------- dynamic section and relocations ----------------
export interface DynamicInfo { needed: string[]; soname?: string; rpath?: string; runpath?: string; flags: number; flags1: number; bindNow: boolean; entries: { tag: number; value: number }[] }

export function elfDynamic(img: BinImage): DynamicInfo {
  const v = img.view;
  const dyn = img.sections.find((s) => s.type === 6) ?? img.segments.find((s) => s.ptype === 2);
  const info: DynamicInfo = { needed: [], flags: 0, flags1: 0, bindNow: false, entries: [] };
  if (!dyn) return info;
  const ps = img.bits === 64 ? 8 : 4;
  const strtabSec = img.sections.find((s) => s.name === '.dynstr');
  const raws: { tag: number; value: number }[] = [];
  for (let p = dyn.offset; p + 2 * ps <= dyn.offset + dyn.size && raws.length < 4096; p += 2 * ps) {
    const tag = v.uN(p, ps), value = v.uN(p + ps, ps);
    if (tag === 0) break;
    raws.push({ tag, value });
  }
  info.entries = raws;
  let strOff = strtabSec?.offset ?? -1;
  const strtab = raws.find((e) => e.tag === 5);
  if (strOff < 0 && strtab) strOff = vaToOffset(img, strtab.value);
  const s = (o: number): string => (strOff >= 0 && v.has(strOff + o, 1) ? v.cstr(strOff + o, 4096) : '');
  for (const e of raws) {
    if (e.tag === 1) info.needed.push(s(e.value));
    else if (e.tag === 14) info.soname = s(e.value);
    else if (e.tag === 15) info.rpath = s(e.value);
    else if (e.tag === 29) info.runpath = s(e.value);
    else if (e.tag === 30) info.flags = e.value;
    else if (e.tag === 0x6ffffffb) info.flags1 = e.value;
    else if (e.tag === 24) info.bindNow = true;
  }
  if (info.flags & 0x8 || info.flags1 & 0x1) info.bindNow = true;
  return info;
}

const RELATIVE_TYPES: Record<string, number> = { 'x86-64': 8, aarch64: 1027, x86: 8, arm: 23, riscv: 3, ppc64: 22, s390: 12, loongarch: 3 };

/** Map of virtual addresses patched by R_*_RELATIVE relocations to their addends. */
export function elfRelativeRelocs(img: BinImage, max = 2000000): Map<number, number> {
  const out = new Map<number, number>();
  const v = img.view;
  const want = RELATIVE_TYPES[img.machine];
  if (want === undefined) return out;
  const is64 = img.bits === 64;
  for (const s of img.sections) {
    if (s.type !== 4 && s.type !== 9) continue;
    const rela = s.type === 4;
    const ent = is64 ? (rela ? 24 : 16) : (rela ? 12 : 8);
    for (let p = s.offset; p + ent <= s.offset + s.size; p += ent) {
      const off = is64 ? v.u64n(p) : v.u32(p);
      const info = is64 ? Number(v.u64(p + 8) & 0xffffffffn) : v.u32(p + 4) & 0xff;
      if (info !== want) continue;
      let add: number;
      if (rela) add = is64 ? v.u64n(p + 16) : v.u32(p + 8);
      else { const fo = vaToOffset(img, off); add = fo >= 0 ? v.uN(fo, is64 ? 8 : 4) : 0; }
      out.set(off, add);
      if (out.size >= max) return out;
    }
  }
  return out;
}

export interface Initializer { array: string; index: number; slot: number; target: number; symbol?: string; viaRelocation: boolean }

/** Entries of .preinit_array, .init_array, .fini_array and the legacy DT_INIT/DT_FINI functions. */
export function elfInitializers(bytes: Uint8Array): Initializer[] {
  const img = parseElf(bytes);
  const v = img.view;
  const ps = img.bits === 64 ? 8 : 4;
  const rel = elfRelativeRelocs(img);
  const syms = new Map<number, string>();
  try { for (const s of [...elfSymbols(img, 'symtab'), ...elfSymbols(img, 'dynsym')]) if (s.type === 'func' && s.value && !syms.has(s.value)) syms.set(s.value, s.name); } catch { /* no symbols */ }
  const out: Initializer[] = [];
  for (const name of ['.preinit_array', '.init_array', '.fini_array']) {
    const s = img.sections.find((x) => x.name === name);
    if (!s || !s.size) continue;
    for (let i = 0; i * ps < s.size && i < 4096; i++) {
      const slot = s.vaddr + i * ps;
      let target = v.uN(s.offset + i * ps, ps);
      let via = false;
      if (rel.has(slot)) { target = rel.get(slot) as number; via = true; }
      const sym = syms.get(target);
      out.push({ array: name, index: i, slot, target, ...(sym ? { symbol: sym } : {}), viaRelocation: via });
    }
  }
  const dyn = elfDynamic(img);
  for (const [tag, name] of [[12, 'DT_INIT'], [13, 'DT_FINI']] as const) {
    const e = dyn.entries.find((x) => x.tag === tag);
    if (e) { const sym = syms.get(e.value); out.push({ array: name, index: 0, slot: 0, target: e.value, ...(sym ? { symbol: sym } : {}), viaRelocation: false }); }
  }
  return out;
}

// ---------------- kernel modules ----------------
export interface KernelModuleInfo {
  modinfo: { key: string; value: string }[];
  name?: string;
  vermagic?: string;
  license?: string;
  depends: string[];
  aliases: string[];
  versions: { name: string; crc: string }[];
  hasThisModule: boolean;
  signature: null | { offset: number; length: number; algorithm: number; hash: number; idType: number; signer?: string; serial?: string; digestOid?: string };
}

export function kernelModule(bytes: Uint8Array): KernelModuleInfo {
  const img = parseElf(bytes);
  const v = img.view;
  const info: KernelModuleInfo = { modinfo: [], depends: [], aliases: [], versions: [], hasThisModule: false, signature: null };
  const mi = img.sections.find((s) => s.name === '.modinfo');
  if (mi) {
    const text = new TextDecoder().decode(v.sub(mi.offset, mi.size));
    for (const part of text.split('\0')) {
      const eq = part.indexOf('=');
      if (eq <= 0) continue;
      const key = part.slice(0, eq), value = part.slice(eq + 1);
      info.modinfo.push({ key, value });
      if (key === 'name') info.name = value;
      if (key === 'vermagic') info.vermagic = value;
      if (key === 'license') info.license = value;
      if (key === 'depends') info.depends.push(...value.split(',').filter(Boolean));
      if (key === 'alias') info.aliases.push(value);
      if (info.modinfo.length > 4096) break;
    }
  }
  const ver = img.sections.find((s) => s.name === '__versions');
  if (ver) {
    const crcSize = img.bits === 64 ? 8 : 4;
    for (let p = ver.offset; p + 64 <= ver.offset + ver.size && info.versions.length < 100000; p += 64) {
      const crc = img.bits === 64 ? v.u64(p).toString(16) : v.u32(p).toString(16);
      info.versions.push({ name: v.cstr(p + crcSize, 64 - crcSize), crc: '0x' + crc.padStart(8, '0') });
    }
  }
  info.hasThisModule = img.sections.some((s) => s.name === '.gnu.linkonce.this_module');
  const marker = ascii('~Module signature appended~\n');
  const mpos = bytes.length - marker.length;
  if (mpos > 12 && indexOfBytes(bytes, marker, mpos) === mpos) {
    const sigHdr = mpos - 12;
    const bv = new View(bytes, false);
    const sigLen = bv.u32(sigHdr + 8);
    const start = sigHdr - sigLen;
    const sig: NonNullable<KernelModuleInfo['signature']> = { offset: start, length: sigLen, algorithm: bv.u8(sigHdr), hash: bv.u8(sigHdr + 1), idType: bv.u8(sigHdr + 2) };
    if (start >= 0 && sig.idType === 2) {
      try {
        const ci = derAt(bytes, start, sigHdr);
        const sd = children(children(ci)[1]!)[0]!;
        const parts = children(sd);
        const si = children(parts[parts.length - 1]!)[0]!;
        const sp = children(si);
        const [iss, ser] = children(sp[1]!);
        if (iss) sig.signer = x509Name(iss).dn;
        if (ser) sig.serial = intHex(ser);
        if (sp[2]) sig.digestOid = oid(children(sp[2])[0]!);
      } catch { /* keep the raw facts */ }
    }
    info.signature = sig;
  }
  return info;
}

// ---------------- kernel config ----------------
/** Find an IKCFG_ST..IKCFG_ED gzip blob (vmlinux, configs.ko) and return the config text. */
export async function kernelConfig(bytes: Uint8Array): Promise<{ offset: number; options: number; text: string; selected: Record<string, string> } | null> {
  const st = indexOfBytes(bytes, ascii('IKCFG_ST'));
  if (st < 0) return null;
  const gzStart = st + 8;
  if (bytes[gzStart] !== 0x1f || bytes[gzStart + 1] !== 0x8b) throw new ParseError('IKCFG_ST not followed by gzip', gzStart);
  const ed = indexOfBytes(bytes, ascii('IKCFG_ED'), gzStart);
  const text = new TextDecoder().decode(await inflate(bytes.subarray(gzStart, ed > 0 ? ed : bytes.length), 'gzip', 32 << 20));
  const selected: Record<string, string> = {};
  let options = 0;
  for (const line of text.split('\n')) {
    const m = /^(CONFIG_[A-Z0-9_]+)=(.*)$/.exec(line);
    if (!m) continue;
    options++;
    if (/^CONFIG_(SECURITY|STACKPROTECTOR|STRICT_|RANDOMIZE|HARDENED|FORTIFY|MODULE_SIG|KASAN|DEBUG_INFO|SLAB_FREELIST|INIT_ON|LOCALVERSION|BPF|SECCOMP|SELINUX|APPARMOR|IKCONFIG)/.test(m[1] as string)) selected[m[1] as string] = m[2] as string;
  }
  return { offset: st, options, text: text.slice(0, 200000), selected };
}
