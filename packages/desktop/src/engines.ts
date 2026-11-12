// Game engine and .NET detection for an application folder: Unity (Mono and IL2CPP), Unreal,
// Godot (standalone and embedded packs), GameMaker, Ren'Py, RPG Maker (MV, MZ, XP, VX, VX Ace)
// and .NET (framework-dependent, self-contained and single-file bundles). It reads the folder's
// file list plus small header and trailer ranges through a caller-supplied reader, so it works on
// a real folder (node.ts) and in a browser on dropped files. No Node imports. Every finding lists
// its evidence (path, kind, offset) so it can be checked; a marker is evidence of an engine's
// files, not proof that the program runs on it.
import { InputError } from './proc.js';

export type EngineId = 'unity' | 'unreal' | 'godot' | 'gamemaker' | 'renpy' | 'rpgmaker' | 'dotnet';
export interface EngineEvidence { path: string; kind: string; offset?: number; detail?: Record<string, unknown> }
export interface EngineFinding { engine: EngineId; confidence: 'high' | 'medium' | 'low'; version?: string; variant?: string; evidence: EngineEvidence[] }
export interface EngineFileInfo { path: string; size: number }
/** Read length bytes at offset of a listed file (shorter at the end of the file). */
export type RangeReader = (path: string, offset: number, length: number) => Promise<Uint8Array>;

const te = new TextDecoder('utf-8', { fatal: false });
const ascii = (b: Uint8Array, s: number, n: number) => { let o = ''; for (let i = s; i < s + n && i < b.length; i++) o += String.fromCharCode(b[i]!); return o; };
const cstr = (b: Uint8Array, s: number, max = 64) => { let o = ''; for (let i = s; i < b.length && i < s + max && b[i] !== 0; i++) o += String.fromCharCode(b[i]!); return o; };
const dvOf = (b: Uint8Array) => new DataView(b.buffer, b.byteOffset, b.byteLength);
const base = (p: string) => p.slice(p.lastIndexOf('/') + 1);
const lower = (p: string) => p.toLowerCase();

// ---------------- header probes (pure, on byte ranges) ----------------

/** UnityFS asset bundle header: signature, format version, player and engine versions. */
export function parseUnityFsHeader(b: Uint8Array): { format: number; player: string; engine: string } | undefined {
  if (ascii(b, 0, 8) !== 'UnityFS\0' || b.length < 14) return undefined;
  const format = dvOf(b).getUint32(8, false);
  const player = cstr(b, 12, 32);
  const engine = cstr(b, 12 + player.length + 1, 64);
  if (!/^[\w.]+$/.test(engine)) return undefined;
  return { format, player, engine };
}

/** Unity serialized file header (globalgamemanagers, level0, *.assets): format version and Unity version string. */
export function parseUnitySerializedHeader(b: Uint8Array, fileSize: number): { format: number; unityVersion: string; bigEndian: boolean } | undefined {
  if (b.length < 20) return undefined;
  const dv = dvOf(b);
  const format = dv.getUint32(8, false);
  if (format < 9 || format > 64) return undefined;
  // header fields are big-endian; format 22 and later moved the sizes into 64-bit fields
  const bigEndian = b[16] !== 0;
  let p = 20, declared = dv.getUint32(4, false);
  if (format >= 22) {
    if (b.length < 48) return undefined;
    declared = Number(dv.getBigUint64(24, false));
    p = 48;
  }
  if (declared !== fileSize) return undefined;
  const unityVersion = cstr(b, p, 32);
  if (!/^\d{1,4}\.\d+\.\d+[a-z]\d+/.test(unityVersion) && !/^\d+\.\d+\.\d+$/.test(unityVersion)) return undefined;
  return { format, unityVersion, bigEndian };
}

/** IL2CPP global-metadata.dat: magic 0xFAB11BAF and the metadata version. */
export function parseIl2cppMetadata(b: Uint8Array): { version: number } | undefined {
  if (b.length < 8 || dvOf(b).getUint32(0, true) !== 0xfab11baf) return undefined;
  return { version: dvOf(b).getInt32(4, true) };
}

/** Godot PCK header at the start of a range: pack format and engine version. */
export function parseGodotPck(b: Uint8Array): { packFormat: number; engine: string; flags?: number } | undefined {
  if (ascii(b, 0, 4) !== 'GDPC' || b.length < 20) return undefined;
  const dv = dvOf(b);
  const packFormat = dv.getUint32(4, true);
  if (packFormat > 16) return undefined;
  return { packFormat, engine: `${dv.getUint32(8, true)}.${dv.getUint32(12, true)}.${dv.getUint32(16, true)}`, flags: packFormat >= 2 && b.length >= 24 ? dv.getUint32(20, true) : undefined };
}

/** Godot embedded pack trailer (last 12 bytes: pack size u64, "GDPC"): where the pack starts. */
export function godotEmbeddedStart(tail: Uint8Array, fileSize: number): number | undefined {
  if (tail.length < 12 || ascii(tail, tail.length - 4, 4) !== 'GDPC') return undefined;
  const size = Number(dvOf(tail).getBigUint64(tail.length - 12, true));
  const start = fileSize - 12 - size;
  return size > 0 && start >= 0 ? start : undefined;
}

/** GameMaker data file (data.win, game.unx, game.ios, game.droid): FORM container with GEN8 first. */
export function parseGameMakerHeader(b: Uint8Array, fileSize: number): { formSize: number; bytecodeVersion?: number; nameOffset?: number; ideVersion?: string } | undefined {
  if (ascii(b, 0, 4) !== 'FORM' || ascii(b, 8, 4) !== 'GEN8' || b.length < 16) return undefined;
  const dv = dvOf(b);
  const formSize = dv.getUint32(4, true);
  if (formSize + 8 > fileSize || formSize < 8) return undefined;
  const out: { formSize: number; bytecodeVersion?: number; nameOffset?: number; ideVersion?: string } = { formSize };
  if (b.length >= 18) out.bytecodeVersion = b[17];
  // GEN8 body: debug(1) bytecode(1) pad(2) filename(4) config(4) lastObj(4) lastTile(4) gameId(4) guid(16) name(4) major minor release build (4 each)
  if (b.length >= 16 + 56) { out.nameOffset = dv.getUint32(16 + 40, true); out.ideVersion = [44, 48, 52, 56].map((o) => dv.getUint32(16 + o, true)).join('.'); }
  return out;
}

/** Unreal .pak footer: magic 0x5A6F12E1 followed by the pak version, searched in the last bytes. */
export function parseUnrealPakFooter(tail: Uint8Array, fileSize: number): { version: number; footerOffset: number } | undefined {
  const dv = dvOf(tail);
  // newest footers are longest (encryption key guid, compression names); scan back from the end
  for (let i = tail.length - 8; i >= 0; i--) {
    if (dv.getUint32(i, true) === 0x5a6f12e1) {
      const version = dv.getUint32(i + 4, true);
      if (version >= 1 && version <= 32) return { version, footerOffset: fileSize - tail.length + i };
    }
  }
  return undefined;
}

/** Unreal IoStore .utoc: magic "-==--==--==--==-" and the TOC version byte. */
export function parseUnrealUtoc(b: Uint8Array): { tocVersion: number } | undefined {
  if (ascii(b, 0, 16) !== '-==--==--==--==-' || b.length < 17) return undefined;
  return { tocVersion: b[16]! };
}

/** Ren'Py archive header line ("RPA-3.0 <index offset> <key>") and compiled script header. */
export function parseRenpyHeader(b: Uint8Array): { kind: 'rpa' | 'rpyc'; version: string; indexOffset?: number } | undefined {
  const head = ascii(b, 0, 64);
  const m = /^RPA-(\d\.\d) ([0-9a-fA-F]{1,16})(?: [0-9a-fA-F]{1,16})?\n/.exec(head);
  if (m) return { kind: 'rpa', version: m[1]!, indexOffset: parseInt(m[2]!, 16) };
  if (head.startsWith('RENPY RPC2')) return { kind: 'rpyc', version: '2' };
  return undefined;
}

/** RPG Maker MV/MZ encrypted asset header ("RPGMV" + 0 0 0, then version bytes) and RGSS archives. */
export function parseRpgMakerHeader(b: Uint8Array): { kind: 'mv-encrypted' | 'rgssad'; version?: number } | undefined {
  if (b.length >= 16 && ascii(b, 0, 8) === 'RPGMV\0\0\0') return { kind: 'mv-encrypted', version: b[8] };
  if (b.length >= 8 && ascii(b, 0, 7) === 'RGSSAD\0') return { kind: 'rgssad', version: b[7] };
  return undefined;
}

export interface PeInfo { machine: number; managed: boolean; cliRva?: number; cliSize?: number; runtimeVersion?: string }

/** PE header facts from the first bytes: machine and, when present, the CLI (.NET) data directory. */
export function parsePeHeader(b: Uint8Array): PeInfo | undefined {
  if (b.length < 64 || b[0] !== 0x4d || b[1] !== 0x5a) return undefined;
  const dv = dvOf(b);
  const pe = dv.getUint32(0x3c, true);
  if (pe + 24 > b.length || ascii(b, pe, 4) !== 'PE\0\0') return undefined;
  const machine = dv.getUint16(pe + 4, true);
  const optSize = dv.getUint16(pe + 20, true);
  const opt = pe + 24;
  if (opt + 2 > b.length) return { machine, managed: false };
  const magic = dv.getUint16(opt, true);
  const ddBase = magic === 0x20b ? opt + 112 : opt + 96;
  const nDirs = ddBase - 4 + 4 <= b.length ? dv.getUint32(ddBase - 4, true) : 0;
  if (nDirs < 15 || ddBase + 15 * 8 > b.length || ddBase + 15 * 8 > opt + optSize) return { machine, managed: false };
  const cliRva = dv.getUint32(ddBase + 14 * 8, true), cliSize = dv.getUint32(ddBase + 14 * 8 + 4, true);
  return { machine, managed: cliRva !== 0 && cliSize !== 0, cliRva: cliRva || undefined, cliSize: cliSize || undefined };
}

/** Map an RVA to a file offset through the PE section table. */
export function peRvaToOffset(b: Uint8Array, rva: number): number | undefined {
  const dv = dvOf(b);
  const pe = dv.getUint32(0x3c, true);
  const n = dv.getUint16(pe + 6, true), optSize = dv.getUint16(pe + 20, true);
  const sec = pe + 24 + optSize;
  for (let i = 0; i < n && sec + i * 40 + 40 <= b.length; i++) {
    const o = sec + i * 40;
    const vsize = dv.getUint32(o + 8, true), va = dv.getUint32(o + 12, true), rawSize = dv.getUint32(o + 16, true), raw = dv.getUint32(o + 20, true);
    if (rva >= va && rva < va + Math.max(vsize, rawSize)) return raw + (rva - va);
  }
  return undefined;
}

/** The .NET single-file bundle signature (SHA-256 of ".net core bundle"), stored after the header offset. */
export const DOTNET_BUNDLE_SIGNATURE = new Uint8Array([0x8b, 0x12, 0x02, 0xb9, 0x6a, 0x61, 0x20, 0x38, 0x72, 0x7b, 0x93, 0x02, 0x14, 0xd7, 0xa0, 0x32, 0x13, 0xf5, 0xb9, 0xe6, 0xef, 0xae, 0x33, 0x18, 0xee, 0x3b, 0x2d, 0xce, 0x24, 0xb3, 0x6a, 0xae]);

export interface DotnetBundle { headerOffset: number; major: number; minor: number; fileCount: number; bundleId: string; files: { path: string; offset: number; size: number; compressedSize?: number; type: number }[]; truncated: boolean }

/** Parse a .NET single-file bundle header and manifest at headerOffset (format versions 1 to 6+). */
export function parseDotnetBundle(b: Uint8Array, headerOffset: number, maxFiles = 10_000): DotnetBundle {
  const dv = dvOf(b);
  let p = headerOffset;
  const need = (n: number) => { if (p + n > b.length) throw new InputError('bundle manifest runs past the file'); };
  const u32 = () => { need(4); const v = dv.getUint32(p, true); p += 4; return v; };
  const i64 = () => { need(8); const v = Number(dv.getBigInt64(p, true)); p += 8; return v; };
  const str = () => { let len = 0, shift = 0; for (let k = 0; k < 5; k++) { need(1); const c = b[p++]!; len |= (c & 0x7f) << shift; if (!(c & 0x80)) break; shift += 7; } if (len > 4096) throw new InputError('bundle string too long'); need(len); const s = te.decode(b.subarray(p, p + len)); p += len; return s; };
  const major = u32(), minor = u32();
  if (major < 1 || major > 20) throw new InputError(`unexpected bundle version ${major}`);
  const fileCount = u32();
  const bundleId = str();
  if (major >= 2) { i64(); i64(); i64(); i64(); i64(); } // deps.json and runtimeconfig.json locations, flags
  const files: DotnetBundle['files'] = [];
  for (let k = 0; k < fileCount && k < maxFiles; k++) {
    const offset = i64(), size = i64();
    const compressedSize = major >= 6 ? i64() : undefined;
    need(1); const type = b[p++]!;
    files.push({ path: str(), offset, size, compressedSize, type });
  }
  return { headerOffset, major, minor, fileCount, bundleId, files, truncated: fileCount > files.length };
}

// ---------------- folder detection ----------------

const UNITY_DATA_FILES = new Set(['globalgamemanagers', 'maindata', 'data.unity3d', 'level0', 'resources.assets', 'sharedassets0.assets', 'unity default resources']);

/**
 * Detect engines and .NET in an application folder from its file list (paths relative to the
 * folder, '/' separated) and small reads. Header reads are 64 bytes; trailers 512 bytes; .NET
 * bundle marker search reads native executables up to maxScanBytes each.
 */
export async function detectEngines(files: EngineFileInfo[], read: RangeReader, opts: { maxScanBytes?: number; maxProbes?: number } = {}): Promise<{ engines: EngineFinding[]; probed: number; warnings: string[] }> {
  const maxScan = Math.max(0, Math.min(opts.maxScanBytes ?? 256 * 1024 * 1024, 2 * 1024 * 1024 * 1024));
  const maxProbes = Math.max(1, Math.min(opts.maxProbes ?? 2000, 100_000));
  const warnings: string[] = [];
  const found = new Map<EngineId, EngineFinding>();
  const add = (engine: EngineId, ev: EngineEvidence, extra: Partial<EngineFinding> = {}) => {
    const f = found.get(engine) ?? { engine, confidence: 'low', evidence: [] };
    if (f.evidence.length < 50 && !f.evidence.some((e) => e.path === ev.path && e.kind === ev.kind)) f.evidence.push(ev);
    if (extra.version && !f.version) f.version = extra.version;
    if (extra.variant && !f.variant) f.variant = extra.variant;
    found.set(engine, f);
  };
  const list = files.slice(0, 200_000).map((f) => ({ ...f, l: lower(f.path), b: lower(base(f.path)) }));
  const has = (re: RegExp) => list.filter((f) => re.test(f.l));
  let probed = 0;
  const head = async (f: { path: string; size: number }, n = 64) => { if (probed >= maxProbes) return new Uint8Array(0); probed++; try { return await read(f.path, 0, Math.min(n, f.size)); } catch (e) { warnings.push(`${f.path}: ${(e as Error).message}`); return new Uint8Array(0); } };
  const tail = async (f: { path: string; size: number }, n = 512) => { if (probed >= maxProbes) return new Uint8Array(0); probed++; const len = Math.min(n, f.size); try { return await read(f.path, f.size - len, len); } catch (e) { warnings.push(`${f.path}: ${(e as Error).message}`); return new Uint8Array(0); } };

  // ----- Unity -----
  for (const f of list) {
    if (/(^|\/)unityplayer\.(dll|so|dylib)$/.test(f.l)) add('unity', { path: f.path, kind: 'unity-player-library' });
    else if (/(^|\/)gameassembly\.(dll|so|dylib)$|(^|\/)libil2cpp\.so$/.test(f.l)) add('unity', { path: f.path, kind: 'il2cpp-game-assembly' }, { variant: 'il2cpp' });
    else if (/_data\/managed\/unityengine(\.coremodule)?\.dll$/.test(f.l)) add('unity', { path: f.path, kind: 'unity-managed-assembly' });
    else if (/_data\/managed\/assembly-csharp\.dll$/.test(f.l)) add('unity', { path: f.path, kind: 'unity-game-scripts' }, { variant: 'mono' });
    else if (/(^|\/)monobleedingedge\//.test(f.l) && /(mono-2\.0-bdwgc\.dll|libmonobdwgc-2\.0\.(so|dylib))$/.test(f.l)) add('unity', { path: f.path, kind: 'unity-mono-runtime' }, { variant: 'mono' });
    else if (/_data\/app\.info$/.test(f.l)) {
      const b = await head(f, 512);
      const [company, product] = te.decode(b).split('\n');
      add('unity', { path: f.path, kind: 'unity-app-info', detail: { company, product } });
    }
  }
  for (const f of has(/il2cpp_data\/metadata\/global-metadata\.dat$/)) {
    const m = parseIl2cppMetadata(await head(f, 8));
    if (m) add('unity', { path: f.path, kind: 'il2cpp-metadata-header', offset: 0, detail: { metadataVersion: m.version } }, { variant: 'il2cpp' });
  }
  for (const f of list.filter((x) => UNITY_DATA_FILES.has(x.b) || /\.(assets|bundle|unity3d|ab)$/.test(x.b) || /_data\//.test(x.l)).slice(0, 400)) {
    if (f.size < 20) continue;
    const b = await head(f, 128);
    const fs = parseUnityFsHeader(b);
    if (fs) { add('unity', { path: f.path, kind: 'unityfs-header', offset: 0, detail: fs }, { version: fs.engine }); continue; }
    if (UNITY_DATA_FILES.has(f.b) || /\.assets$/.test(f.b)) {
      const s = parseUnitySerializedHeader(b, f.size);
      if (s) add('unity', { path: f.path, kind: 'unity-serialized-file', offset: 0, detail: s }, { version: s.unityVersion });
    }
  }

  // ----- Unreal -----
  for (const f of list) {
    if (/(^|\/)engine\/binaries\//.test(f.l) || /(^|\/)engine\/content\//.test(f.l)) { add('unreal', { path: f.path, kind: 'unreal-engine-folder' }); }
    else if (/-(win64|linux|mac)-shipping(\.exe)?$/.test(f.b)) add('unreal', { path: f.path, kind: 'unreal-shipping-executable' });
  }
  for (const f of has(/\/paks\/[^/]+\.pak$|\.pak$/).slice(0, 200)) {
    const ft = parseUnrealPakFooter(await tail(f, 512), f.size);
    if (ft) add('unreal', { path: f.path, kind: 'unreal-pak-footer', offset: ft.footerOffset, detail: { pakVersion: ft.version } });
  }
  for (const f of has(/\.utoc$/).slice(0, 200)) {
    const u = parseUnrealUtoc(await head(f, 32));
    if (u) add('unreal', { path: f.path, kind: 'unreal-iostore-toc', offset: 0, detail: u });
  }

  // ----- Godot -----
  for (const f of has(/\.pck$/).slice(0, 100)) {
    const g = parseGodotPck(await head(f, 24));
    if (g) add('godot', { path: f.path, kind: 'godot-pck-header', offset: 0, detail: g }, { version: g.engine });
  }
  for (const f of list) {
    if (/(^|\/)godotsharp\.dll$/.test(f.l) || /(^|\/)data_[^/]+\/godotsharp\.dll$/.test(f.l)) add('godot', { path: f.path, kind: 'godot-dotnet-assembly' }, { variant: 'dotnet' });
    else if (/\.gdextension$/.test(f.l) || /libgodot/.test(f.b)) add('godot', { path: f.path, kind: 'godot-extension' });
  }

  // ----- GameMaker -----
  for (const f of list.filter((x) => /^(data\.win|game\.unx|game\.ios|game\.droid|data\.ios|data\.droid)$/.test(x.b)).slice(0, 20)) {
    const b = await head(f, 80);
    const g = parseGameMakerHeader(b, f.size);
    if (!g) continue;
    let name: string | undefined;
    if (g.nameOffset && g.nameOffset + 4 <= f.size) { try { const nb = await read(f.path, g.nameOffset - 4, 260); const len = dvOf(nb).getUint32(0, true); if (len < 256) name = te.decode(nb.subarray(4, 4 + len)); } catch { /* optional */ } }
    add('gamemaker', { path: f.path, kind: 'gamemaker-form-gen8', offset: 0, detail: { ...g, gameName: name } }, { version: g.ideVersion && g.ideVersion !== '0.0.0.0' ? g.ideVersion : undefined });
  }
  for (const f of list) if (/(^|\/)options\.ini$/.test(f.l) && list.some((x) => x.b === 'data.win')) add('gamemaker', { path: f.path, kind: 'gamemaker-options' });

  // ----- Ren'Py -----
  for (const f of list) {
    if (/(^|\/)renpy\/__init__\.pyc?$/.test(f.l) || /(^|\/)renpy\/bootstrap\.pyc?$/.test(f.l)) add('renpy', { path: f.path, kind: 'renpy-runtime-package' });
    else if (/(^|\/)renpy\/vc_version\.pyc?$/.test(f.l) && f.l.endsWith('.py')) {
      const t = te.decode(await head(f, 2048));
      const v = /^version\s*=\s*['"]([\d.]+)['"]/m.exec(t)?.[1];
      add('renpy', { path: f.path, kind: 'renpy-version-file', detail: { version: v } }, { version: v });
    } else if (/(^|\/)game\/[^/]+\.rpy$/.test(f.l)) add('renpy', { path: f.path, kind: 'renpy-script-source' });
  }
  for (const f of list.filter((x) => /\.(rpa|rpyc|rpymc)$/.test(x.b)).slice(0, 200)) {
    const r = parseRenpyHeader(await head(f, 64));
    if (r) add('renpy', { path: f.path, kind: r.kind === 'rpa' ? 'renpy-archive' : 'renpy-compiled-script', offset: 0, detail: r });
  }

  // ----- RPG Maker -----
  for (const f of list.filter((x) => /(^|\/)js\/(rpg_core|rmmz_core)\.js$/.test(x.l)).slice(0, 4)) {
    const t = te.decode(await head(f, 64 * 1024));
    const name = /Utils\.RPGMAKER_NAME\s*=\s*['"](\w+)['"]/.exec(t)?.[1];
    const ver = /Utils\.RPGMAKER_VERSION\s*=\s*['"]([\w.]+)['"]/.exec(t)?.[1];
    add('rpgmaker', { path: f.path, kind: 'rpgmaker-core-script', detail: { name, version: ver } }, { variant: name ?? (f.l.includes('rmmz') ? 'MZ' : 'MV'), version: ver });
  }
  for (const f of list.filter((x) => /(^|\/)data\/system\.json$/.test(x.l)).slice(0, 4)) {
    if (!list.some((x) => /(^|\/)js\/(rpg_core|rmmz_core|rpg_managers|rmmz_managers)\.js$/.test(x.l))) continue;
    const t = te.decode(await head(f, 4 * 1024 * 1024));
    let enc: Record<string, unknown> = {};
    try { const j = JSON.parse(t) as Record<string, unknown>; enc = { hasEncryptedImages: j.hasEncryptedImages === true, hasEncryptedAudio: j.hasEncryptedAudio === true, hasKey: typeof j.encryptionKey === 'string' && j.encryptionKey.length > 0, gameTitle: typeof j.gameTitle === 'string' ? j.gameTitle.slice(0, 200) : undefined }; } catch { /* not JSON */ }
    add('rpgmaker', { path: f.path, kind: 'rpgmaker-system-json', detail: enc });
  }
  for (const f of list.filter((x) => /\.(rpgmvp|rpgmvo|rpgmvm|rpgmvw|png_|ogg_|m4a_)$/.test(x.b)).slice(0, 20)) {
    const r = parseRpgMakerHeader(await head(f, 16));
    if (r) add('rpgmaker', { path: f.path, kind: 'rpgmaker-encrypted-asset', offset: 0, detail: r }, { variant: /_(?:$)/.test(f.b) ? 'MZ' : undefined });
  }
  for (const f of list.filter((x) => /(^|\/)game\.(rgssad|rgss2a|rgss3a)$/.test(x.l))) {
    const r = parseRpgMakerHeader(await head(f, 8));
    const variant = f.l.endsWith('rgss3a') ? 'VX Ace' : f.l.endsWith('rgss2a') ? 'VX' : 'XP';
    if (r) add('rpgmaker', { path: f.path, kind: 'rgss-archive', offset: 0, detail: r }, { variant });
  }
  for (const f of list.filter((x) => /(^|\/)game\.ini$/.test(x.l)).slice(0, 2)) {
    const t = te.decode(await head(f, 8192));
    const lib = /^Library\s*=\s*(.+)$/mi.exec(t)?.[1]?.trim();
    if (lib && /rgss/i.test(lib)) { const n = /RGSS(\d)/i.exec(lib)?.[1]; add('rpgmaker', { path: f.path, kind: 'rgss-game-ini', detail: { library: lib } }, { variant: n === '3' ? 'VX Ace' : n === '2' ? 'VX' : n === '1' ? 'XP' : undefined }); }
  }
  for (const f of list) if (/(^|\/)rgss\d\d\d[a-z]?\.dll$/.test(f.l)) add('rpgmaker', { path: f.path, kind: 'rgss-runtime-library' });

  // ----- .NET -----
  const runtimeConfigs = list.filter((x) => /\.runtimeconfig\.json$/.test(x.b)).slice(0, 50);
  for (const f of runtimeConfigs) {
    const t = te.decode(await head(f, 256 * 1024));
    try {
      const j = JSON.parse(t) as { runtimeOptions?: { tfm?: string; framework?: { name?: string; version?: string }; frameworks?: { name?: string; version?: string }[]; includedFrameworks?: { name?: string; version?: string }[] } };
      const ro = j.runtimeOptions ?? {};
      const fw = [ro.framework, ...(ro.frameworks ?? [])].filter(Boolean) as { name?: string; version?: string }[];
      const inc = ro.includedFrameworks ?? [];
      add('dotnet', { path: f.path, kind: 'dotnet-runtimeconfig', detail: { tfm: ro.tfm, frameworks: fw, includedFrameworks: inc.length ? inc : undefined } }, { version: fw[0]?.version ?? inc[0]?.version, variant: inc.length ? 'self-contained' : 'framework-dependent' });
    } catch { warnings.push(`${f.path}: not valid JSON`); }
  }
  for (const f of list.filter((x) => /\.deps\.json$/.test(x.b)).slice(0, 50)) add('dotnet', { path: f.path, kind: 'dotnet-deps-json' });
  for (const f of list) {
    if (/(^|\/)(coreclr\.dll|libcoreclr\.(so|dylib)|hostfxr\.dll|libhostfxr\.(so|dylib)|system\.private\.corelib\.dll)$/.test(f.l)) add('dotnet', { path: f.path, kind: 'dotnet-runtime-file' }, { variant: 'self-contained' });
  }
  // managed assemblies: PE with a CLI header (look at the .dll and .exe files, bounded)
  let managed = 0;
  for (const f of list.filter((x) => /\.(dll|exe)$/.test(x.b) && x.size >= 128 && x.size < 512 * 1024 * 1024).slice(0, 300)) {
    const b = await head(f, 4096);
    const pe = parsePeHeader(b);
    if (!pe?.managed) continue;
    managed++;
    let runtimeVersion: string | undefined;
    const cliOff = peRvaToOffset(b, pe.cliRva!);
    if (cliOff !== undefined) {
      try {
        const cli = await read(f.path, cliOff, 72);
        const mdRva = dvOf(cli).getUint32(8, true);
        const mdOff = peRvaToOffset(b, mdRva);
        if (mdOff !== undefined) { const md = await read(f.path, mdOff, 64); if (ascii(md, 0, 4) === 'BSJB') { const len = dvOf(md).getUint32(12, true); runtimeVersion = cstr(md, 16, Math.min(len, 40)); } }
      } catch { /* header ranges only */ }
    }
    const isUnity = /_data\/managed\//.test(f.l), isGodot = /godotsharp\.dll$/.test(f.l);
    if (managed <= 40) add('dotnet', { path: f.path, kind: 'managed-assembly', offset: cliOff, detail: { cliRva: pe.cliRva, cliSize: pe.cliSize, machine: pe.machine, metadataVersion: runtimeVersion, partOf: isUnity ? 'unity' : isGodot ? 'godot' : undefined } });
  }
  // single-file bundles and apphosts: native executables carrying the bundle signature
  const natives = list.filter((x) => x.size >= 4096 && x.size <= maxScan && !/\.(dll|so|dylib|json|pdb|txt|pak|pck|assets)$/.test(x.b)).slice(0, 60);
  for (const f of natives) {
    const h = await head(f, 4);
    const isNative = (h[0] === 0x7f && h[1] === 0x45) || (h[0] === 0x4d && h[1] === 0x5a) || (h[0] === 0xcf && h[1] === 0xfa) || (h[0] === 0xca && h[1] === 0xfe);
    if (!isNative) continue;
    // also look for a Godot pack appended to an executable
    const t = await tail(f, 12);
    const gs = godotEmbeddedStart(t, f.size);
    if (gs !== undefined) {
      const g = parseGodotPck(await read(f.path, gs, 24).catch(() => new Uint8Array(0)));
      if (g) add('godot', { path: f.path, kind: 'godot-embedded-pck', offset: gs, detail: g }, { version: g.engine, variant: 'embedded pack' });
    }
    const pos = await findBytes(read, f.path, f.size, DOTNET_BUNDLE_SIGNATURE, maxScan);
    if (pos === undefined || pos < 8) continue;
    const hdr = await read(f.path, pos - 8, 8);
    const headerOffset = Number(dvOf(hdr).getBigInt64(0, true));
    if (headerOffset === 0) { add('dotnet', { path: f.path, kind: 'dotnet-apphost', offset: pos - 8 }); continue; }
    if (headerOffset < 0 || headerOffset >= f.size) continue;
    try {
      const mb = await read(f.path, headerOffset, Math.min(f.size - headerOffset, 4 * 1024 * 1024));
      const bundle = parseDotnetBundle(mb, 0);
      add('dotnet', { path: f.path, kind: 'dotnet-single-file-bundle', offset: headerOffset, detail: { bundleVersion: `${bundle.major}.${bundle.minor}`, fileCount: bundle.fileCount, bundleId: bundle.bundleId, files: bundle.files.slice(0, 200).map((x) => x.path) } }, { variant: 'single-file' });
    } catch (e) { warnings.push(`${f.path}: bundle manifest: ${(e as Error).message}`); }
  }

  // ----- confidence: two independent kinds of evidence, or one strong header, is high -----
  const strong = new Set(['unityfs-header', 'unity-serialized-file', 'il2cpp-metadata-header', 'unreal-pak-footer', 'unreal-iostore-toc', 'godot-pck-header', 'godot-embedded-pck', 'gamemaker-form-gen8', 'renpy-archive', 'renpy-compiled-script', 'rpgmaker-core-script', 'rgss-archive', 'rpgmaker-encrypted-asset', 'dotnet-runtimeconfig', 'dotnet-single-file-bundle', 'managed-assembly']);
  const out = [...found.values()];
  for (const f of out) {
    const kinds = new Set(f.evidence.map((e) => e.kind));
    const strongN = [...kinds].filter((k) => strong.has(k)).length;
    f.confidence = strongN >= 1 && kinds.size >= 2 ? 'high' : strongN >= 1 || kinds.size >= 2 ? 'medium' : 'low';
  }
  // .NET found only inside Unity or Godot folders is part of that engine, not a separate app runtime
  const dn = found.get('dotnet');
  if (dn && dn.evidence.every((e) => e.detail?.partOf)) { dn.confidence = 'low'; dn.variant = dn.variant ?? 'engine scripting'; }
  const rank = { high: 0, medium: 1, low: 2 };
  out.sort((a, b) => rank[a.confidence] - rank[b.confidence] || b.evidence.length - a.evidence.length);
  return { engines: out, probed, warnings };
}

/** Find a byte pattern in a file through the reader, in overlapping 1 MiB windows. */
export async function findBytes(read: RangeReader, path: string, size: number, pat: Uint8Array, max: number): Promise<number | undefined> {
  const win = 1024 * 1024;
  const limit = Math.min(size, max);
  for (let off = 0; off < limit; off += win - pat.length) {
    const b = await read(path, off, Math.min(win, limit - off));
    outer: for (let i = b.indexOf(pat[0]!); i >= 0 && i + pat.length <= b.length; i = b.indexOf(pat[0]!, i + 1)) {
      for (let k = 1; k < pat.length; k++) if (b[i + k] !== pat[k]) continue outer;
      return off + i;
    }
    if (b.length < win) break;
  }
  return undefined;
}
