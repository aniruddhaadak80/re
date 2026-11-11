// PyInstaller CArchive and PYZ reader, plus Nuitka and py2exe detection. Never executes anything.
import { unzlibSync } from 'fflate';
import { ByteReader, ParseError, LIMITS, latin1, utf8, ascii, indexOfBytes, lastIndexOfBytes } from '../util.js';
import { unmarshal, type PyValue } from './marshal.js';
import { pycHeader, PYC_MAGIC, versionForMagic } from './pyc.js';

const COOKIE_MAGIC = Uint8Array.from([0x4d, 0x45, 0x49, 0x0c, 0x0b, 0x0a, 0x0b, 0x0e]); // MEI\014\013\012\013\016
const COOKIE_LEN_NEW = 88; // PyInstaller >= 2.1: magic, len, toc, toclen, pyver, pylibname[64]
const COOKIE_LEN_OLD = 24;

export interface CArchiveEntry {
  name: string;
  /** typecode: s script, m module, M package, b binary, z PYZ, x data, o option, d dependency, n symlink */
  type: string;
  typeName: string;
  /** absolute file offset of the stored data */
  offset: number;
  storedSize: number;
  size: number;
  compressed: boolean;
}

export interface CArchive {
  cookieOffset: number;
  packageOffset: number;
  packageLength: number;
  tocOffset: number;
  tocLength: number;
  pyver: number;
  pythonVersion: string;
  pylibName: string;
  format: 'pyinstaller>=2.1' | 'pyinstaller<2.1';
  entries: CArchiveEntry[];
  options: string[];
}

const TYPE_NAMES: Record<string, string> = {
  s: 'script', m: 'module', M: 'package', b: 'binary', z: 'pyz', Z: 'zipfile', x: 'data', o: 'runtime option', d: 'dependency', n: 'symlink', l: 'splash',
};

export function findCookie(bytes: Uint8Array): number {
  // The cookie is near the end; on Linux the archive sits in an ELF section so trailing data can follow.
  return lastIndexOfBytes(bytes, COOKIE_MAGIC);
}

export function isPyInstaller(bytes: Uint8Array): boolean { return findCookie(bytes) >= 0; }

/** Parse the CArchive cookie and table of contents. */
export function parseCArchive(bytes: Uint8Array): CArchive {
  const cookie = findCookie(bytes);
  if (cookie < 0) throw new ParseError('no PyInstaller cookie (MEI magic) found');
  const r = new ByteReader(bytes, cookie, false);
  r.skip(8);
  const packageLength = r.u32();
  const tocOffset = r.u32();
  const tocLength = r.u32();
  const pyver = r.u32();
  let format: CArchive['format'] = 'pyinstaller<2.1';
  let pylibName = '';
  let cookieLen = COOKIE_LEN_OLD;
  if (cookie + COOKIE_LEN_NEW <= bytes.length) {
    const nameBytes = bytes.subarray(cookie + 24, cookie + COOKIE_LEN_NEW);
    const end = nameBytes.indexOf(0);
    const candidate = latin1(nameBytes.subarray(0, end < 0 ? 64 : end));
    if (/^[\x20-\x7e]+$/.test(candidate) && /python|\.dll|\.so|\.dylib/i.test(candidate)) { pylibName = candidate; format = 'pyinstaller>=2.1'; cookieLen = COOKIE_LEN_NEW; }
  }
  const packageOffset = cookie + cookieLen - packageLength;
  if (packageOffset < 0) throw new ParseError('PyInstaller package length larger than file', cookie);
  const tocAbs = packageOffset + tocOffset;
  if (tocAbs < 0 || tocAbs + tocLength > bytes.length) throw new ParseError('PyInstaller TOC out of range', cookie);
  const entries: CArchiveEntry[] = [];
  const options: string[] = [];
  const t = new ByteReader(bytes.subarray(tocAbs, tocAbs + tocLength), 0, false);
  while (t.remaining() >= 18 && entries.length < LIMITS.maxEntries) {
    const start = t.pos;
    const entrySize = t.u32();
    if (entrySize < 18 || start + entrySize > t.length) throw new ParseError('bad TOC entry size', tocAbs + start);
    const pos = t.u32(), stored = t.u32(), size = t.u32();
    const flag = t.u8();
    const type = String.fromCharCode(t.u8());
    const nameRaw = t.take(entrySize - 18);
    const z = nameRaw.indexOf(0);
    const name = utf8(nameRaw.subarray(0, z < 0 ? nameRaw.length : z));
    t.seek(start + entrySize);
    if (type === 'o') { options.push(name); continue; }
    entries.push({ name, type, typeName: TYPE_NAMES[type] ?? 'unknown', offset: packageOffset + pos, storedSize: stored, size, compressed: flag === 1 });
  }
  const major = Math.floor(pyver / 100) >= 3 ? Math.floor(pyver / 100) : Math.floor(pyver / 10);
  const minor = pyver >= 100 ? pyver % 100 : pyver % 10;
  return { cookieOffset: cookie, packageOffset, packageLength, tocOffset: tocAbs, tocLength, pyver, pythonVersion: `${major}.${minor}`, pylibName, format, entries, options };
}

/** Raw (decompressed) bytes of one CArchive entry. */
export function readCArchiveEntry(bytes: Uint8Array, e: CArchiveEntry, maxOut = LIMITS.maxOutputBytes): Uint8Array {
  if (e.offset < 0 || e.offset + e.storedSize > bytes.length) throw new ParseError(`entry ${e.name} out of range`, e.offset);
  const raw = bytes.subarray(e.offset, e.offset + e.storedSize);
  if (!e.compressed) return raw;
  if (e.size > maxOut) throw new ParseError(`entry ${e.name} too large to inflate (${e.size} bytes)`);
  try { return unzlibSync(raw, { out: new Uint8Array(e.size) }); } catch (err) { throw new ParseError(`zlib error in ${e.name}: ${err instanceof Error ? err.message : err}`); }
}

function looksLikePycHeader(b: Uint8Array): boolean {
  return b.length >= 16 && b[2] === 0x0d && b[3] === 0x0a && versionForMagic((b[0] as number) | ((b[1] as number) << 8)) !== undefined;
}

/** Turn a stored code object into a loadable .pyc by prepending a header when it lacks one. */
export function fixPyc(data: Uint8Array, pythonVersion: string, magicOverride?: Uint8Array): Uint8Array {
  if (looksLikePycHeader(data)) return data;
  let header: Uint8Array;
  if (magicOverride && magicOverride.length === 4) { header = new Uint8Array(16); header.set(magicOverride, 0); }
  else header = pycHeader(pythonVersion);
  const out = new Uint8Array(header.length + data.length);
  out.set(header, 0); out.set(data, header.length);
  return out;
}

export interface PyzEntry { name: string; type: number; typeName: string; offset: number; length: number; ispkg: boolean }
export interface Pyz { magic: Uint8Array; pythonVersion?: string; tocOffset: number; entries: PyzEntry[] }

const PYZ_TYPES = ['module', 'package', 'data', 'nspkg'];

/** Parse a PYZ archive (bytes start at the PYZ magic). */
export function parsePyz(pyz: Uint8Array, fallbackVersion?: string): Pyz {
  if (pyz.length < 12 || latin1(pyz.subarray(0, 4)) !== 'PYZ\0') throw new ParseError('bad PYZ magic');
  const magic = pyz.slice(4, 8);
  const ver = versionForMagic((magic[0] as number) | ((magic[1] as number) << 8)) ?? fallbackVersion;
  const tocOffset = new DataView(pyz.buffer, pyz.byteOffset).getInt32(8, false);
  if (tocOffset < 12 || tocOffset >= pyz.length) throw new ParseError('PYZ TOC offset out of range');
  const minor = Number((ver ?? '3.12').split('.')[1]);
  const { value } = unmarshal(pyz, { minor, maxObjects: LIMITS.maxEntries * 8 }, tocOffset);
  const list: [PyValue, PyValue][] = [];
  if (value && typeof value === 'object' && 'kind' in value) {
    if (value.kind === 'list' || value.kind === 'tuple') for (const it of value.items) if (it && typeof it === 'object' && 'kind' in it && it.kind === 'tuple' && it.items.length === 2) list.push([it.items[0] as PyValue, it.items[1] as PyValue]);
    if (value.kind === 'dict') list.push(...value.entries);
  }
  const entries: PyzEntry[] = [];
  for (const [k, v] of list) {
    if (typeof k !== 'string' || !v || typeof v !== 'object' || !('kind' in v) || v.kind !== 'tuple' || v.items.length < 3) continue;
    const [a, b, c] = v.items as [PyValue, PyValue, PyValue];
    const type = typeof a === 'boolean' ? (a ? 1 : 0) : Number(a);
    entries.push({ name: k, type, typeName: PYZ_TYPES[type] ?? 'unknown', offset: Number(b), length: Number(c), ispkg: type === 1 });
    if (entries.length >= LIMITS.maxEntries) break;
  }
  return { magic, pythonVersion: ver, tocOffset, entries };
}

export function readPyzEntry(pyz: Uint8Array, e: PyzEntry, maxOut = 64 * 1024 * 1024): Uint8Array {
  if (e.type === 3) return new Uint8Array(0);
  if (e.offset < 0 || e.offset + e.length > pyz.length) throw new ParseError(`PYZ entry ${e.name} out of range`);
  const raw = pyz.subarray(e.offset, e.offset + e.length);
  let out: Uint8Array;
  try { out = unzlibSync(raw); } catch (err) { throw new ParseError(`zlib error in PYZ entry ${e.name} (encrypted PYZ from PyInstaller < 6 is not supported)`); }
  if (out.length > maxOut) throw new ParseError('PYZ entry too large');
  return out;
}

export interface ExtractedFile { path: string; source: 'carchive' | 'pyz'; type: string; size: number; data: Uint8Array; fixedHeader: boolean }

/**
 * Expand a PyInstaller executable to the file set pyinstxtractor would write:
 * scripts and modules become .pyc with a valid header, PYZ members go under PYZ.pyz_extracted/.
 */
export function extractPyInstaller(bytes: Uint8Array, opts: { includeBinaries?: boolean; filter?: (path: string) => boolean; maxFiles?: number; maxTotalBytes?: number } = {}): { archive: CArchive; files: ExtractedFile[]; errors: string[] } {
  const archive = parseCArchive(bytes);
  const files: ExtractedFile[] = [];
  const errors: string[] = [];
  const maxFiles = opts.maxFiles ?? 20000;
  let total = 0;
  const maxTotal = opts.maxTotalBytes ?? 512 * 1024 * 1024;
  const push = (f: ExtractedFile) => {
    if (opts.filter && !opts.filter(f.path)) return;
    if (files.length >= maxFiles || total + f.size > maxTotal) { errors.push(`limit reached before ${f.path}`); return; }
    total += f.size; files.push(f);
  };
  const ver = PYC_MAGIC[archive.pythonVersion] ? archive.pythonVersion : '3.12';
  let pyzMagic: Uint8Array | undefined;
  for (const e of archive.entries) {
    if (e.type === 'z' || e.type === 'Z') {
      try {
        const pyzBytes = readCArchiveEntry(bytes, e);
        const pyz = parsePyz(pyzBytes, archive.pythonVersion);
        pyzMagic = pyz.magic;
        push({ path: e.name, source: 'carchive', type: 'pyz', size: pyzBytes.length, data: pyzBytes, fixedHeader: false });
        for (const pe of pyz.entries) {
          if (pe.type === 3) continue;
          const rel = pe.name.replace(/\.\./g, '__').replace(/\./g, '/');
          const path = `${e.name}_extracted/${rel}${pe.ispkg ? '/__init__' : ''}.pyc`;
          if (opts.filter && !opts.filter(path)) continue;
          try {
            const raw = readPyzEntry(pyzBytes, pe);
            const data = pe.type === 2 ? raw : fixPyc(raw, ver, pyz.magic);
            push({ path: pe.type === 2 ? `${e.name}_extracted/${pe.name}` : path, source: 'pyz', type: pe.typeName, size: data.length, data, fixedHeader: pe.type !== 2 });
          } catch (err) { errors.push(`${pe.name}: ${err instanceof Error ? err.message : err}`); }
        }
      } catch (err) { errors.push(`${e.name}: ${err instanceof Error ? err.message : err}`); }
      continue;
    }
    if (e.type === 'b' && !opts.includeBinaries) continue;
    if (e.type === 'd' || e.type === 'n') continue;
    try {
      const raw = readCArchiveEntry(bytes, e);
      if (e.type === 's' || e.type === 'm' || e.type === 'M') {
        const data = fixPyc(raw, ver, pyzMagic);
        const path = e.type === 'M' ? `${e.name}/__init__.pyc` : `${e.name}.pyc`;
        push({ path, source: 'carchive', type: e.typeName, size: data.length, data, fixedHeader: data !== raw });
      } else {
        push({ path: e.name, source: 'carchive', type: e.typeName, size: raw.length, data: raw, fixedHeader: false });
      }
    } catch (err) { errors.push(`${e.name}: ${err instanceof Error ? err.message : err}`); }
  }
  return { archive, files, errors };
}

export interface PackerHit { packer: 'pyinstaller' | 'nuitka' | 'py2exe' | 'cx_freeze' | 'pyoxidizer' | 'bbfreeze'; evidence: string; offset?: number }

/** Detect Python freezers by structural markers and strings. */
export function detectPythonPackers(bytes: Uint8Array): PackerHit[] {
  const hits: PackerHit[] = [];
  const c = findCookie(bytes);
  if (c >= 0) hits.push({ packer: 'pyinstaller', evidence: 'MEI cookie', offset: c });
  const probe = (needle: string, packer: PackerHit['packer'], what: string) => {
    if (hits.some((h) => h.packer === packer)) return;
    const at = indexOfBytes(bytes, ascii(needle));
    if (at >= 0) hits.push({ packer, evidence: what, offset: at });
  };
  probe('__nuitka_binary_dir', 'nuitka', 'string __nuitka_binary_dir');
  probe('NUITKA_ONEFILE_PARENT', 'nuitka', 'string NUITKA_ONEFILE_PARENT');
  probe('nuitka_', 'nuitka', 'string nuitka_');
  probe('PYTHONSCRIPT', 'py2exe', 'resource name PYTHONSCRIPT');
  probe('py2exe', 'py2exe', 'string py2exe');
  probe('cx_Freeze', 'cx_freeze', 'string cx_Freeze');
  probe('__startup__', 'cx_freeze', 'string __startup__');
  probe('pyembed', 'pyoxidizer', 'string pyembed');
  probe('PyOxidizer', 'pyoxidizer', 'string PyOxidizer');
  probe('_MEIPASS', 'pyinstaller', 'string _MEIPASS');
  return hits;
}
