// GPU code objects: CUDA fatbin containers and their entries, CUDA cubin ELF, PTX text,
// AMD HSA code objects (amdgcn ELF) and SPIR-V modules. Reading only.

import { View, ParseError, hexs, utf8, indexOfBytes, ascii } from '../util.js';
import { parseElf, elfSymbols } from '../bin/container.js';

export const FATBIN_MAGIC = 0xba55ed50;
export const FATBIN_WRAPPER_MAGIC = 0x466243b1;

export interface FatbinEntry {
  offset: number;
  kind: 'ptx' | 'cubin' | `kind-${number}`;
  headerSize: number;
  payloadOffset: number;
  payloadSize: number;
  arch: string;
  version: string;
  compressed: boolean;
  uncompressedSize?: number;
  flags: string;
  /** set when the payload is plain PTX text */
  ptx?: PtxInfo;
  /** set when the payload is an uncompressed cubin */
  cubin?: CubinInfo;
}
export interface Fatbin { offset: number; version: number; headerSize: number; size: number; entries: FatbinEntry[] }

/** Parse a fatbin data block (magic 0xBA55ED50) at `off`. */
export function parseFatbin(b: Uint8Array, off = 0, maxEntries = 4096): Fatbin {
  const v = new View(b, true);
  if (v.u32(off) !== FATBIN_MAGIC) throw new ParseError('fatbin magic not found', off);
  const version = v.u16(off + 4);
  const headerSize = v.u16(off + 6);
  const size = v.u64n(off + 8);
  const end = Math.min(b.length, off + headerSize + size);
  const entries: FatbinEntry[] = [];
  let p = off + headerSize;
  while (p + 64 <= end && entries.length < maxEntries) {
    const kindId = v.u16(p);
    const eh = v.u32(p + 4);
    const psize = v.u64n(p + 8);
    if (eh < 64 || eh > 4096 || psize > b.length) break;
    const minor = v.u16(p + 20), major = v.u16(p + 22);
    const arch = v.u32(p + 24);
    const flags = v.u64(p + 40);
    const compressed = (flags & 0x2000n) !== 0n;
    const uncompressed = v.u64n(p + 56);
    const kind: FatbinEntry['kind'] = kindId === 1 ? 'ptx' : kindId === 2 ? 'cubin' : `kind-${kindId}`;
    const e: FatbinEntry = {
      offset: p, kind, headerSize: eh, payloadOffset: p + eh, payloadSize: psize, arch: `sm_${arch}`, version: `${major}.${minor}`,
      compressed, flags: hexs(flags), ...(compressed ? { uncompressedSize: uncompressed } : {}),
    };
    const payload = b.subarray(p + eh, Math.min(b.length, p + eh + psize));
    if (!compressed && kind === 'ptx') { try { e.ptx = parsePtx(stripNul(utf8(payload))); } catch { /* not text */ } }
    if (!compressed && kind === 'cubin') { try { e.cubin = parseCubin(payload); } catch { /* not ELF */ } }
    entries.push(e);
    p += eh + psize;
  }
  return { offset: off, version, headerSize, size, entries };
}

/** Find every fatbin block in a host binary or a standalone .fatbin file. */
export function findFatbins(b: Uint8Array, max = 64): Fatbin[] {
  const out: Fatbin[] = [];
  const sig = new Uint8Array([0x50, 0xed, 0x55, 0xba]);
  let i = 0;
  while (out.length < max) {
    i = indexOfBytes(b, sig, i);
    if (i < 0) break;
    try { const f = parseFatbin(b, i); out.push(f); i += Math.max(16, f.headerSize + f.size); } catch { i += 4; }
  }
  return out;
}

export interface PtxInfo {
  version?: string;
  target?: string;
  addressSize?: number;
  entries: { name: string; line: number; params: number }[];
  functions: { name: string; line: number }[];
  globals: number;
}

/** Read the module directives and kernel names from PTX assembly text. */
export function parsePtx(text: string, maxLines = 2_000_000): PtxInfo {
  if (!/\.version\s+\d/.test(text.slice(0, 1 << 16)) && !/\.target\s+\w/.test(text.slice(0, 1 << 16))) throw new ParseError('not PTX text');
  const out: PtxInfo = { entries: [], functions: [], globals: 0 };
  const lines = text.split('\n', maxLines);
  let pending: { name: string; line: number; params: number } | null = null;
  for (let i = 0; i < lines.length; i++) {
    const l = (lines[i] as string).trim();
    if (!l || l.startsWith('//')) continue;
    let m: RegExpMatchArray | null;
    if ((m = l.match(/^\.version\s+([\d.]+)/))) out.version = m[1];
    else if ((m = l.match(/^\.target\s+([\w, ]+)/))) out.target = (m[1] as string).trim();
    else if ((m = l.match(/^\.address_size\s+(\d+)/))) out.addressSize = Number(m[1]);
    else if ((m = l.match(/^(?:\.visible\s+|\.weak\s+|\.extern\s+)*\.entry\s+([\w$.]+)/))) { pending = { name: m[1] as string, line: i + 1, params: 0 }; out.entries.push(pending); }
    else if ((m = l.match(/^(?:\.visible\s+|\.weak\s+|\.extern\s+)*\.func\s+(?:\([^)]{0,512}\)\s*)?([\w$.]+)/))) { out.functions.push({ name: m[1] as string, line: i + 1 }); pending = null; }
    else if (/^(?:\.visible\s+|\.extern\s+)*\.global\s/.test(l)) out.globals++;
    if (pending && /\.param\s/.test(l)) pending.params++;
    if (pending && l.startsWith('{')) pending = null;
  }
  return out;
}

export interface CubinInfo { arch: string; abiVersion: number; flags: string; kernels: string[]; functions: string[]; sections: number }

/** CUDA cubin (ELF machine 190): SM target from e_flags and kernel names from .text.<name> and .nv.info.<name>. */
export function parseCubin(b: Uint8Array): CubinInfo {
  const img = parseElf(b);
  const v = img.view;
  if (v.u16(18) !== 190) throw new ParseError('not a CUDA cubin (ELF machine 190)');
  const flags = v.u32(img.bits === 64 ? 48 : 36);
  const abi = v.u8(8);
  const sm = (flags & 0xff) || ((flags >>> 8) & 0xff);
  const kernels = new Set<string>();
  for (const s of img.sections) {
    if (s.name.startsWith('.nv.info.')) kernels.add(s.name.slice(9));
  }
  const functions: string[] = [];
  for (const s of img.sections) if (s.name.startsWith('.text.')) functions.push(s.name.slice(6));
  if (!kernels.size) for (const f of functions) kernels.add(f);
  return { arch: `sm_${sm}`, abiVersion: abi, flags: hexs(flags, 8), kernels: [...kernels], functions, sections: img.sections.length };
}

const AMDGPU_MACH: Record<number, string> = {
  0x20: 'gfx600', 0x21: 'gfx601', 0x22: 'gfx700', 0x23: 'gfx701', 0x24: 'gfx702', 0x25: 'gfx703', 0x26: 'gfx704', 0x28: 'gfx801', 0x29: 'gfx802',
  0x2a: 'gfx803', 0x2b: 'gfx810', 0x2c: 'gfx900', 0x2d: 'gfx902', 0x2e: 'gfx904', 0x2f: 'gfx906', 0x30: 'gfx908', 0x31: 'gfx909', 0x32: 'gfx90c',
  0x33: 'gfx1010', 0x34: 'gfx1011', 0x35: 'gfx1012', 0x36: 'gfx1030', 0x37: 'gfx1031', 0x38: 'gfx1032', 0x39: 'gfx1033', 0x3a: 'gfx602', 0x3b: 'gfx705',
  0x3c: 'gfx805', 0x3d: 'gfx1035', 0x3e: 'gfx1034', 0x3f: 'gfx90a', 0x40: 'gfx940', 0x41: 'gfx1100', 0x42: 'gfx1013', 0x43: 'gfx1150', 0x44: 'gfx1103',
  0x45: 'gfx1036', 0x46: 'gfx1101', 0x47: 'gfx1102', 0x48: 'gfx1200', 0x4a: 'gfx1151', 0x4b: 'gfx941', 0x4c: 'gfx942', 0x4e: 'gfx1201', 0x4f: 'gfx950',
};

export interface AmdgpuInfo { target: string; mach: number; codeObjectVersion: number | null; xnack: string; sramecc: string; kernels: string[]; hasMetadataNote: boolean }

/** AMD HSA code object (ELF machine 224): gfx target, code object version and kernel descriptors (*.kd symbols). */
export function parseAmdgpu(b: Uint8Array): AmdgpuInfo {
  const img = parseElf(b);
  const v = img.view;
  if (v.u16(18) !== 224) throw new ParseError('not an AMDGPU code object (ELF machine 224)');
  const flags = v.u32(48);
  const osabi = v.u8(7), abiv = v.u8(8);
  const mach = flags & 0xff;
  // EI_ABIVERSION for ELFOSABI_AMDGPU_HSA (64): 2 means v4, 3 means v5, 4 means v6
  const cov = osabi === 64 ? (abiv + 2) : null;
  const feat = (mask: number, any: number, name: string): string => {
    if (cov === null || cov < 4) return 'unknown';
    const x = flags & mask;
    return x === 0 ? 'unsupported' : x === any ? 'any' : x === any * 2 ? `${name}-` : `${name}+`;
  };
  const kernels = elfSymbols(img).filter((s) => s.name.endsWith('.kd')).map((s) => s.name.slice(0, -3));
  const hasMetadataNote = img.sections.some((s) => s.name === '.note');
  return { target: AMDGPU_MACH[mach] ?? `mach-${hexs(mach)}`, mach, codeObjectVersion: cov, xnack: feat(0x300, 0x100, 'xnack'), sramecc: feat(0xc00, 0x400, 'sramecc'), kernels, hasMetadataNote };
}

const SPIRV_EXEC: Record<number, string> = { 0: 'Vertex', 1: 'TessellationControl', 2: 'TessellationEvaluation', 3: 'Geometry', 4: 'Fragment', 5: 'GLCompute', 6: 'Kernel', 5267: 'TaskNV', 5268: 'MeshNV', 5313: 'RayGenerationKHR', 5314: 'IntersectionKHR', 5315: 'AnyHitKHR', 5316: 'ClosestHitKHR', 5317: 'MissKHR', 5318: 'CallableKHR', 5364: 'TaskEXT', 5365: 'MeshEXT' };
const SPIRV_CAP: Record<number, string> = { 0: 'Matrix', 1: 'Shader', 2: 'Geometry', 3: 'Tessellation', 4: 'Addresses', 5: 'Linkage', 6: 'Kernel', 9: 'Float16', 10: 'Float64', 11: 'Int64', 22: 'Int16', 39: 'Int8', 50: 'ImageQuery', 56: 'StorageImageExtendedFormats', 61: 'VariablePointersStorageBuffer', 4427: 'ShaderDrawParameters', 5345: 'VulkanMemoryModel', 4423: 'SubgroupBallotKHR', 5301: 'RuntimeDescriptorArray', 4479: 'RayQueryKHR', 4478: 'RayTracingKHR' };
const SPIRV_SOURCE: Record<number, string> = { 0: 'Unknown', 1: 'ESSL', 2: 'GLSL', 3: 'OpenCL_C', 4: 'OpenCL_CPP', 5: 'HLSL', 6: 'CPP_for_OpenCL', 7: 'SYCL', 8: 'HERO_C', 9: 'NZSL', 10: 'WGSL', 11: 'Slang', 12: 'Zig' };
const SPIRV_ADDR: Record<number, string> = { 0: 'Logical', 1: 'Physical32', 2: 'Physical64', 5348: 'PhysicalStorageBuffer64' };
const SPIRV_MEM: Record<number, string> = { 0: 'Simple', 1: 'GLSL450', 2: 'OpenCL', 3: 'Vulkan' };

export interface SpirvInfo {
  endian: 'le' | 'be';
  version: string;
  generator: { id: number; version: number; hex: string };
  bound: number;
  capabilities: string[];
  extensions: string[];
  extInstImports: string[];
  addressing?: string;
  memoryModel?: string;
  source?: { language: string; version: number };
  entryPoints: { executionModel: string; id: number; name: string; offset: number; interface: number[] }[];
  executionModes: { id: number; mode: number; operands: number[] }[];
  names: number;
  instructions: number;
  complete: boolean;
}

function spirvString(v: View, wordOff: number, words: number): { s: string; used: number } {
  const bytes: number[] = [];
  for (let i = 0; i < words; i++) {
    for (let k = 0; k < 4; k++) {
      const c = v.u8(wordOff + i * 4 + (v.le ? k : 3 - k));
      if (c === 0) return { s: utf8(new Uint8Array(bytes)), used: i + 1 };
      bytes.push(c);
    }
  }
  return { s: utf8(new Uint8Array(bytes)), used: words };
}

/** Read a SPIR-V module header and its leading declarations (capabilities, entry points, modes). */
export function parseSpirv(b: Uint8Array, maxInstructions = 2_000_000): SpirvInfo {
  if (b.length < 20 || b.length % 4) throw new ParseError('SPIR-V module length must be a multiple of 4 and at least 20');
  const le = b[0] === 0x03 && b[1] === 0x02 && b[2] === 0x23 && b[3] === 0x07;
  const be = b[0] === 0x07 && b[1] === 0x23 && b[2] === 0x02 && b[3] === 0x03;
  if (!le && !be) throw new ParseError('SPIR-V magic 0x07230203 not found', 0);
  const v = new View(b, le);
  const ver = v.u32(4);
  const gen = v.u32(8);
  const out: SpirvInfo = {
    endian: le ? 'le' : 'be', version: `${(ver >>> 16) & 0xff}.${(ver >>> 8) & 0xff}`, generator: { id: gen >>> 16, version: gen & 0xffff, hex: hexs(gen, 8) },
    bound: v.u32(12), capabilities: [], extensions: [], extInstImports: [], entryPoints: [], executionModes: [], names: 0, instructions: 0, complete: true,
  };
  let p = 20;
  while (p + 4 <= b.length) {
    const w = v.u32(p);
    const wc = w >>> 16, op = w & 0xffff;
    if (wc === 0 || p + wc * 4 > b.length) { out.complete = false; break; }
    out.instructions++;
    if (out.instructions > maxInstructions) { out.complete = false; break; }
    if (op === 17) { const c = v.u32(p + 4); out.capabilities.push(SPIRV_CAP[c] ?? `Capability${c}`); }
    else if (op === 10) out.extensions.push(spirvString(v, p + 4, wc - 1).s);
    else if (op === 11) out.extInstImports.push(spirvString(v, p + 8, wc - 2).s);
    else if (op === 14) { out.addressing = SPIRV_ADDR[v.u32(p + 4)] ?? String(v.u32(p + 4)); out.memoryModel = SPIRV_MEM[v.u32(p + 8)] ?? String(v.u32(p + 8)); }
    else if (op === 15) {
      const em = v.u32(p + 4), id = v.u32(p + 8);
      const { s, used } = spirvString(v, p + 12, wc - 3);
      const iface: number[] = [];
      for (let k = 3 + used; k < wc && iface.length < 256; k++) iface.push(v.u32(p + k * 4));
      out.entryPoints.push({ executionModel: SPIRV_EXEC[em] ?? `ExecutionModel${em}`, id, name: s, offset: p, interface: iface });
    } else if (op === 16) {
      const ops: number[] = [];
      for (let k = 3; k < wc && ops.length < 8; k++) ops.push(v.u32(p + k * 4));
      out.executionModes.push({ id: v.u32(p + 4), mode: v.u32(p + 8), operands: ops });
    } else if (op === 3) out.source = { language: SPIRV_SOURCE[v.u32(p + 4)] ?? String(v.u32(p + 4)), version: v.u32(p + 8) };
    else if (op === 5) out.names++;
    else if (op === 54) break; // OpFunction: declarations are done
    p += wc * 4;
  }
  return out;
}

export type GpuObject =
  | { kind: 'fatbin'; fatbins: Fatbin[] }
  | { kind: 'cubin'; cubin: CubinInfo }
  | { kind: 'amdgpu'; amdgpu: AmdgpuInfo }
  | { kind: 'ptx'; ptx: PtxInfo }
  | { kind: 'spirv'; spirv: SpirvInfo }
  | { kind: 'host-binary'; fatbins: Fatbin[]; offloadBundles: { offset: number; targets: string[] }[] };

/** Clang offload bundles (__CLANG_OFFLOAD_BUNDLE__) embedded in HIP or OpenMP host binaries. */
export function findOffloadBundles(b: Uint8Array, max = 64): { offset: number; targets: string[] }[] {
  const sig = ascii('__CLANG_OFFLOAD_BUNDLE__');
  const out: { offset: number; targets: string[] }[] = [];
  const v = new View(b, true);
  let i = 0;
  while (out.length < max) {
    i = indexOfBytes(b, sig, i);
    if (i < 0) break;
    const targets: string[] = [];
    try {
      const n = v.u64n(i + 24);
      let p = i + 32;
      for (let k = 0; k < Math.min(n, 256); k++) {
        const len = v.u64n(p + 16);
        if (len > 4096) break;
        targets.push(utf8(v.sub(p + 24, len)));
        p += 24 + len;
      }
    } catch { /* truncated bundle header */ }
    out.push({ offset: i, targets });
    i += sig.length;
  }
  return out;
}

/** Detect and read any supported GPU code object. */
export function inspectGpu(b: Uint8Array): GpuObject | null {
  if (b.length >= 4) {
    const v = new View(b, true);
    const m = v.u32(0);
    if (m === FATBIN_MAGIC) return { kind: 'fatbin', fatbins: [parseFatbin(b)] };
    if (m === FATBIN_WRAPPER_MAGIC || m === 0x07230203 || m === 0x03022307) { if (m !== FATBIN_WRAPPER_MAGIC) return { kind: 'spirv', spirv: parseSpirv(b) }; }
    if (b[0] === 0x7f && b[1] === 0x45 && b[2] === 0x4c && b[3] === 0x46 && b.length >= 20) {
      const mach = new View(b, b[5] !== 2).u16(18);
      if (mach === 190) return { kind: 'cubin', cubin: parseCubin(b) };
      if (mach === 224) return { kind: 'amdgpu', amdgpu: parseAmdgpu(b) };
    }
  }
  const head = utf8(b.subarray(0, Math.min(b.length, 1 << 16)));
  if (ptxStartsWithVersion(head) || /\n\s*\.target\s+sm_\d/.test(head)) return { kind: 'ptx', ptx: parsePtx(utf8(b)) };
  const fatbins = findFatbins(b);
  const offloadBundles = findOffloadBundles(b);
  if (fatbins.length || offloadBundles.length) return { kind: 'host-binary', fatbins, offloadBundles };
  return null;
}

/** Drop trailing NUL characters without a regex (linear on any input). */
function stripNul(s: string): string { let e = s.length; while (e > 0 && s.charCodeAt(e - 1) === 0) e--; return s.slice(0, e); }

/** True when the text, after blank lines and // comment lines, starts with `.version <digit>`. Linear, no regex backtracking. */
function ptxStartsWithVersion(head: string): boolean {
  let i = 0;
  for (;;) {
    while (i < head.length && /\s/.test(head[i]!)) i++;
    if (head.startsWith('//', i)) { const nl = head.indexOf('\n', i); if (nl < 0) return false; i = nl + 1; continue; }
    break;
  }
  if (!head.startsWith('.version', i)) return false;
  let j = i + 8, ws = 0;
  while (j < head.length && /\s/.test(head[j]!)) { j++; ws++; }
  return ws > 0 && j < head.length && head[j]! >= '0' && head[j]! <= '9';
}
