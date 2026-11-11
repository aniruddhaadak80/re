// JavaScript runtimes packed into one executable: Node.js single executable applications
// (SEA fuse plus NODE_SEA_BLOB), Bun --compile (StandaloneModuleGraph with the
// "---- Bun! ----" trailer) and Deno compile (d3n0l4nd payload with metadata JSON).

import { View, ParseError, utf8, latin1, ascii, indexOfBytes } from '../util.js';

const SEA_FUSE = ascii('NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2');
const SEA_MAGIC = new Uint8Array([0x20, 0xda, 0x43, 0x01]);
const BUN_TRAILER = ascii('\n---- Bun! ----\n');
const DENO_MAGIC = ascii('d3n0l4nd');

export interface SeaBlob {
  offset: number; size: number; flags: string[]; flagBits: number; execArgvExtension?: number;
  codePath: string; mainCodeSize: number; mainCodePreview: string; mainCodeOffset: number; usesSnapshot: boolean;
  codeCacheSize?: number; assets: { name: string; size: number; offset: number }[]; execArgv: string[];
}
export interface StandaloneJs {
  runtime: 'node-sea' | 'bun' | 'deno' | null; evidence: { what: string; offset: number }[]; runtimeVersion?: string;
  nodeSea?: { fuse: 'present-unused' | 'injected' | 'absent'; fuseOffset?: number; blob?: SeaBlob };
  bun?: { trailerOffset: number; byteCount: number; graphOffset: number; entryPoint: number; modules: { name: string; size: number; offset: number; sourceMapSize: number; bytecodeSize: number; preview: string }[]; execArgv?: string };
  deno?: { payloadOffset: number; metadata?: Record<string, unknown>; entrypoint?: string; sections: { offset: number; size: number }[]; files: { path: string; offset: number; size: number; preview: string }[]; specifiers: string[] };
}

const SEA_FLAGS: [number, string][] = [[1, 'disableExperimentalSEAWarning'], [2, 'useSnapshot'], [4, 'useCodeCache'], [8, 'includeAssets'], [16, 'includeExecArgv']];

/** Decode a NODE_SEA_BLOB at `off` (layout of src/node_sea.cc, Node 20 to 24, 64 bit). */
export function parseSeaBlob(b: Uint8Array, off: number, limit = b.length): SeaBlob {
  const v = new View(b, true);
  if (v.u32(off) !== 0x0143da20) throw new ParseError('SEA blob magic 0x143da20 expected', off);
  const flagBits = v.u32(off + 4);
  if (flagBits > 0xff) throw new ParseError('implausible SEA flags', off + 4);
  const tryLayout = (withExt: boolean): SeaBlob => {
    let p = off + 8;
    let ext: number | undefined;
    if (withExt) { ext = v.u8(p); p += 1; if (ext > 2) throw new ParseError('bad exec argv extension'); }
    const str = (max: number): { s: Uint8Array; at: number } => {
      const n = v.u64n(p);
      if (n > max || p + 8 + n > limit) throw new ParseError('SEA string out of range', p);
      const at = p + 8;
      p = at + n;
      return { s: v.sub(at, n), at };
    };
    const cp = str(4096);
    const codePath = utf8(cp.s);
    if (!codePath || /[\x00-\x1f]/.test(codePath)) throw new ParseError('bad SEA code path');
    const main = str(1 << 30);
    const usesSnapshot = (flagBits & 2) !== 0;
    let codeCacheSize: number | undefined;
    if ((flagBits & 4) && !usesSnapshot) codeCacheSize = str(1 << 30).s.length;
    const assets: SeaBlob['assets'] = [];
    if (flagBits & 8) {
      const n = v.u64n(p); p += 8;
      if (n > 100000) throw new ParseError('too many SEA assets');
      for (let i = 0; i < n; i++) { const k = str(4096); const c = str(1 << 30); assets.push({ name: utf8(k.s), size: c.s.length, offset: c.at }); }
    }
    const execArgv: string[] = [];
    if (flagBits & 16) { const n = v.u64n(p); p += 8; if (n > 1000) throw new ParseError('too many exec argv'); for (let i = 0; i < n; i++) execArgv.push(utf8(str(65536).s)); }
    return {
      offset: off, size: p - off, flags: SEA_FLAGS.filter(([bit]) => flagBits & bit).map(([, n]) => n), flagBits, execArgvExtension: ext,
      codePath, mainCodeSize: main.s.length, mainCodeOffset: main.at, mainCodePreview: usesSnapshot ? '' : utf8(main.s.subarray(0, 400)), usesSnapshot, codeCacheSize, assets, execArgv,
    };
  };
  // Node 22.20+ writes one exec argv extension byte after the flags; older versions do not
  try { return tryLayout(true); } catch { return tryLayout(false); }
}

function findVersion(b: Uint8Array, prefix: string, from = 0): { version: string; offset: number } | undefined {
  // the most frequent x.y.z after the prefix wins (binaries also embed versions of their dependencies)
  const pat = ascii(prefix);
  const seen = new Map<string, { n: number; offset: number }>();
  let i = indexOfBytes(b, pat, from);
  for (let n = 0; i >= 0 && n < 200; n++) {
    let s = '';
    for (let k = i + pat.length; k < Math.min(b.length, i + pat.length + 16); k++) { const c = b[k]!; if ((c >= 0x30 && c <= 0x39) || c === 0x2e) s += String.fromCharCode(c); else break; }
    if (/^\d+\.\d+\.\d+$/.test(s)) { const e = seen.get(s); if (e) e.n++; else seen.set(s, { n: 1, offset: i }); }
    i = indexOfBytes(b, pat, i + 1);
  }
  let best: { version: string; offset: number; n: number } | undefined;
  for (const [version, e] of seen) if (!best || e.n > best.n) best = { version, ...e };
  return best && { version: best.version, offset: best.offset };
}

/** Detect and decode a Node SEA, Bun or Deno single-file executable (ELF, PE or Mach-O). */
export function inspectStandaloneJs(b: Uint8Array, opts: { maxModules?: number } = {}): StandaloneJs {
  const out: StandaloneJs = { runtime: null, evidence: [] };
  // Node SEA: fuse string ends ":0" before injection and ":1" after
  const fuse = indexOfBytes(b, SEA_FUSE);
  if (fuse >= 0) {
    const state = b[fuse + SEA_FUSE.length + 1];
    out.nodeSea = { fuse: state === 0x31 ? 'injected' : 'present-unused', fuseOffset: fuse };
    out.evidence.push({ what: `NODE_SEA_FUSE ...:${state === 0x31 ? 1 : 0}`, offset: fuse });
    const nv = findVersion(b, 'node/v') ?? findVersion(b, 'https://nodejs.org/download/release/v');
    if (nv) out.runtimeVersion = nv.version;
    if (state === 0x31) {
      out.runtime = 'node-sea';
      let i = indexOfBytes(b, SEA_MAGIC);
      while (i >= 0) {
        try { out.nodeSea.blob = parseSeaBlob(b, i); out.evidence.push({ what: 'NODE_SEA_BLOB', offset: i }); break; } catch { /* not the blob */ }
        i = indexOfBytes(b, SEA_MAGIC, i + 1);
      }
    }
  }
  // Bun: trailer at the end of the module graph (appended, or inside a .bun section)
  let t = -1;
  for (let i = indexOfBytes(b, BUN_TRAILER, Math.max(0, b.length - (256 << 20))); i >= 0; i = indexOfBytes(b, BUN_TRAILER, i + 1)) t = i;
  if (t >= 32) {
    const v = new View(b, true);
    const bcBig = v.u64(t - 32);
    const byteCount = bcBig > BigInt(t) ? -1 : Number(bcBig);
    const modOff = v.u32(t - 24), modLen = v.u32(t - 20), entry = v.u32(t - 16), argvOff = v.u32(t - 12), argvLen = v.u32(t - 8);
    const g = t - 32 - byteCount;
    if (byteCount >= 0 && g >= 0 && modOff + modLen <= byteCount) {
      const sp = (o: number): { off: number; len: number } => ({ off: v.u32(o), len: v.u32(o + 4) });
      const okName = (o: number): boolean => { const p = sp(o); return p.len > 0 && p.len < 4096 && p.off + p.len <= byteCount && /^(\/\$bunfs\/|B:\/~BUN\/|[A-Za-z]:\\~BUN\\)/.test(latin1(b.subarray(g + p.off, g + p.off + Math.min(p.len, 12)))); };
      let size = 0;
      for (const s of [52, 48, 56, 44, 40, 60, 64, 36, 32, 68, 72]) {
        if (modLen % s) continue;
        const n = modLen / s;
        let ok = n > 0;
        for (let i = 0; ok && i < Math.min(n, 64); i++) ok = okName(g + modOff + i * s);
        if (ok) { size = s; break; }
      }
      if (size) {
        out.runtime ??= 'bun';
        const modules: NonNullable<StandaloneJs['bun']>['modules'] = [];
        for (let i = 0; i < Math.min(modLen / size, opts.maxModules ?? 10000); i++) {
          const e = g + modOff + i * size;
          const name = sp(e), contents = sp(e + 8), map = sp(e + 16), bc = sp(e + 24);
          const inGraph = (p: { off: number; len: number }): boolean => p.off + p.len <= byteCount;
          modules.push({ name: utf8(b.subarray(g + name.off, g + name.off + name.len)), size: contents.len, offset: g + contents.off, sourceMapSize: inGraph(map) ? map.len : 0, bytecodeSize: inGraph(bc) ? bc.len : 0, preview: inGraph(contents) ? utf8(b.subarray(g + contents.off, g + contents.off + Math.min(contents.len, 400))) : '' });
        }
        out.bun = { trailerOffset: t, byteCount, graphOffset: g, entryPoint: entry, modules, execArgv: argvLen && argvOff + argvLen <= byteCount ? utf8(b.subarray(g + argvOff, g + argvOff + argvLen)) : undefined };
        out.evidence.push({ what: '---- Bun! ---- trailer', offset: t });
        const bv = findVersion(b, 'Bun v');
        if (bv && out.runtime === 'bun') out.runtimeVersion = bv.version;
      }
    }
  }
  // Deno: "d3n0l4nd" then u64 length-prefixed sections, the first being metadata JSON
  for (let i = indexOfBytes(b, DENO_MAGIC); i >= 0 && !out.deno; i = indexOfBytes(b, DENO_MAGIC, i + 1)) {
    const v = new View(b, true);
    let p = i + 8;
    if (indexOfBytes(b.subarray(p, p + 8), DENO_MAGIC) === 0) p += 8;
    if (!v.has(p, 9)) continue;
    const big = v.u64(p);
    if (big > 64n << 20n) continue;
    const n = Number(big);
    if (n < 2 || n > 64 << 20 || !v.has(p + 8, n) || b[p + 8] !== 0x7b) continue;
    let metadata: Record<string, unknown> | undefined;
    try { metadata = JSON.parse(utf8(v.sub(p + 8, n))) as Record<string, unknown>; } catch { continue; }
    const sections: { offset: number; size: number }[] = [{ offset: p + 8, size: n }];
    // after the metadata come length-prefixed sections; the virtual file system is a JSON
    // list ([{"File":...},{"Dir":...}]) followed by one blob holding every file's bytes
    const files: NonNullable<StandaloneJs['deno']>['files'] = [];
    let q = p + 8 + n;
    const scanEnd = Math.min(b.length - 9, q + 4096);
    for (; q < scanEnd; q++) {
      const lb = v.u64(q);
      if (lb < 2n || lb > BigInt(b.length - q - 8)) continue;
      const c = b[q + 8];
      if (c !== 0x5b && c !== 0x7b) continue;
      const len = Number(lb);
      let vfs: unknown;
      try { vfs = JSON.parse(utf8(v.sub(q + 8, len))); } catch { continue; }
      sections.push({ offset: q + 8, size: len });
      const dataLenAt = q + 8 + len;
      const dataLen = v.has(dataLenAt, 8) ? Number(v.u64(dataLenAt) > BigInt(b.length) ? 0n : v.u64(dataLenAt)) : 0;
      const data = dataLenAt + 8;
      if (dataLen && v.has(data, dataLen)) sections.push({ offset: data, size: dataLen });
      const walk = (node: unknown, prefix: string, depth: number): void => {
        if (depth > 64 || files.length > (opts.maxModules ?? 10000)) return;
        if (Array.isArray(node)) { for (const x of node) walk(x, prefix, depth + 1); return; }
        if (!node || typeof node !== 'object') return;
        const o = node as Record<string, any>;
        if (o.File) { const f = o.File; const [fo, fl] = Array.isArray(f.o) ? f.o : [0, 0]; const path = prefix + String(f.n); files.push({ path, offset: data + fo, size: fl, preview: fo + fl <= dataLen ? utf8(b.subarray(data + fo, data + fo + Math.min(fl, 400))) : '' }); }
        else if (o.Dir) walk(o.Dir.entries ?? [], prefix + String(o.Dir.n ?? '') + '/', depth + 1);
        else for (const val of Object.values(o)) walk(val, prefix, depth + 1);
      };
      walk(vfs, '', 0);
      break;
    }
    const specifiers = new Set<string>();
    for (const s of sections.slice(1)) {
      const txt = latin1(b.subarray(s.offset, s.offset + Math.min(s.size, 4 << 20)));
      for (const m of txt.matchAll(/(?:file|https?|npm|jsr|node):\/{0,3}[A-Za-z0-9@._~:/%+-]{1,300}\.(?:[cm]?[jt]sx?|json|wasm)/g)) { specifiers.add(m[0]); if (specifiers.size > 2000) break; }
    }
    out.deno = { payloadOffset: i, metadata, entrypoint: typeof metadata?.entrypoint_key === 'string' ? metadata.entrypoint_key : undefined, sections, files, specifiers: [...specifiers] };
    out.runtime ??= 'deno';
    out.evidence.push({ what: 'd3n0l4nd payload', offset: i });
    const dv = findVersion(b, 'Deno/');
    if (dv && out.runtime === 'deno') out.runtimeVersion = dv.version;
  }
  return out;
}

/** Bytes of a Bun module or Node SEA asset, by name. */
export function standaloneFile(b: Uint8Array, s: StandaloneJs, name: string): Uint8Array | undefined {
  const m = s.bun?.modules.find((x) => x.name === name);
  if (m) return b.subarray(m.offset, m.offset + m.size);
  const a = s.nodeSea?.blob?.assets.find((x) => x.name === name);
  if (a) return b.subarray(a.offset, a.offset + a.size);
  if (s.nodeSea?.blob && (name === s.nodeSea.blob.codePath || name === 'main')) return b.subarray(s.nodeSea.blob.mainCodeOffset, s.nodeSea.blob.mainCodeOffset + s.nodeSea.blob.mainCodeSize);
  return undefined;
}
