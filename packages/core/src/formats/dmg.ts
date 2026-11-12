// Apple disk images (UDIF .dmg): the koly trailer, the XML resource map with its blkx partition table,
// and the chunk table of each partition. Partitions can be decompressed (raw, zero fill, zlib, bzip2,
// ADC and LZFSE) and their CRC-32 checked against the stored checksum, then HFS+ volumes are listed and
// APFS containers are identified. Pure TypeScript; no hdiutil, no mounting.

import { BinView, FormatError, crc32 } from './util.js';
import { parsePlistXml, isDict, type PlistValue } from './plist.js';
import { bunzip2 } from './bzip2.js';
import { adcDecompress } from './adc.js';
import { lzfseDecompress, UnsupportedCodec } from './lzfse.js';
import { readHfsPlus, isHfsPlus, type HfsVolume } from './hfsplus.js';
import { readApfsContainer, isApfs, type ApfsContainer } from './apfs.js';
import { decompress } from '../archive/inflate.js';
import { decodeUtf8 } from '../bytes.js';

export const CHUNK_TYPES: Record<number, string> = {
  0x00000000: 'zero', 0x00000001: 'raw', 0x00000002: 'ignore', 0x80000004: 'adc', 0x80000005: 'zlib',
  0x80000006: 'bzip2', 0x80000007: 'lzfse', 0x80000008: 'lzma', 0x7ffffffe: 'comment', 0xffffffff: 'end',
};
const CHECKSUM_TYPES: Record<number, string> = { 0: 'none', 1: 'crc32-ccitt', 2: 'crc32', 4: 'md5', 5: 'sha1' };
const SECTOR = 512;

export interface DmgChecksum { type: string; typeId: number; bits: number; value: string }
export interface DmgChunk { type: string; typeId: number; sector: number; sectors: number; offset: number; length: number }
export interface DmgPartition {
  index: number;
  id: number | null;
  name: string;
  attributes: string | number | null;
  firstSector: number;
  sectorCount: number;
  size: number;
  dataOffset: number;
  checksum: DmgChecksum;
  chunkCount: number;
  methods: Record<string, number>;
  compressedBytes: number;
}
export interface DmgInfo {
  format: 'dmg';
  koly: {
    offset: number; version: number; headerSize: number; flags: number;
    dataForkOffset: number; dataForkLength: number; rsrcForkOffset: number; rsrcForkLength: number;
    xmlOffset: number; xmlLength: number; segmentNumber: number; segmentCount: number; segmentId: string;
    imageVariant: number; sectorCount: number;
  };
  dataChecksum: DmgChecksum;
  masterChecksum: DmgChecksum;
  partitions: DmgPartition[];
  resourceKeys: string[];
  methods: Record<string, number>;
  /** expanded disk size in bytes */
  diskSize: number;
  warnings: string[];
}

function checksum(v: BinView, o: number): DmgChecksum {
  const typeId = v.u32be(o), bits = v.u32be(o + 4);
  const n = Math.min(128, Math.ceil(bits / 8));
  return { type: CHECKSUM_TYPES[typeId] ?? String(typeId), typeId, bits, value: v.hex(o + 8, n) };
}

/** True when the file ends with a UDIF koly trailer. */
export function isDmg(b: Uint8Array): boolean {
  if (b.length < 512) return false;
  const t = b.length - 512;
  return b[t] === 0x6b && b[t + 1] === 0x6f && b[t + 2] === 0x6c && b[t + 3] === 0x79 && b[t + 8] === 0 && b[t + 9] === 0 && b[t + 10] === 2 && b[t + 11] === 0;
}

const chunkCache = new WeakMap<Uint8Array, Map<number, DmgChunk[]>>();

function parseMish(data: Uint8Array, warnings: string[], maxChunks: number): { first: number; count: number; dataOffset: number; checksum: DmgChecksum; chunks: DmgChunk[] } {
  const v = new BinView(data);
  if (v.ascii(0, 4) !== 'mish') throw new FormatError('blkx entry has no mish header');
  const first = v.u64be(8), count = v.u64be(16), dataOffset = v.u64be(24);
  const cs = checksum(v, 64);
  const n = v.u32be(200);
  if (204 + n * 40 > data.length) warnings.push(`blkx table claims ${n} chunks but holds ${Math.floor((data.length - 204) / 40)}`);
  const chunks: DmgChunk[] = [];
  const lim = Math.min(n, Math.floor((data.length - 204) / 40), maxChunks);
  for (let i = 0; i < lim; i++) {
    const o = 204 + i * 40;
    const typeId = v.u32be(o);
    chunks.push({ type: CHUNK_TYPES[typeId] ?? `0x${typeId.toString(16)}`, typeId, sector: v.u64be(o + 8), sectors: v.u64be(o + 16), offset: v.u64be(o + 24), length: v.u64be(o + 32) });
  }
  return { first, count, dataOffset, checksum: cs, chunks };
}

/** Parse the trailer and partition map without decompressing anything. */
export function parseDmg(bytes: Uint8Array, opts: { maxPartitions?: number; maxChunks?: number } = {}): DmgInfo {
  const maxParts = opts.maxPartitions ?? 256, maxChunks = opts.maxChunks ?? 1_000_000;
  if (!isDmg(bytes)) throw new FormatError('no koly trailer in the last 512 bytes');
  const v = new BinView(bytes);
  const t = bytes.length - 512;
  const koly = {
    offset: t, version: v.u32be(t + 4), headerSize: v.u32be(t + 8), flags: v.u32be(t + 12),
    dataForkOffset: v.u64be(t + 24), dataForkLength: v.u64be(t + 32), rsrcForkOffset: v.u64be(t + 40), rsrcForkLength: v.u64be(t + 48),
    segmentNumber: v.u32be(t + 56), segmentCount: v.u32be(t + 60), segmentId: v.hex(t + 64, 16),
    xmlOffset: v.u64be(t + 216), xmlLength: v.u64be(t + 224), imageVariant: v.u32be(t + 488), sectorCount: v.u64be(t + 492),
  };
  const warnings: string[] = [];
  const info: DmgInfo = {
    format: 'dmg', koly, dataChecksum: checksum(v, t + 80), masterChecksum: checksum(v, t + 352),
    partitions: [], resourceKeys: [], methods: {}, diskSize: koly.sectorCount * SECTOR, warnings,
  };
  if (koly.dataForkOffset + koly.dataForkLength > t) warnings.push('the data fork runs past the trailer');
  if (!koly.xmlLength) { warnings.push('no XML resource map (an old resource fork image); partitions are not listed'); return info; }
  if (!v.has(koly.xmlOffset, koly.xmlLength) || koly.xmlLength > 256 * 1024 * 1024) { warnings.push('the XML resource map is outside the file'); return info; }
  let pl: PlistValue;
  try { pl = parsePlistXml(decodeUtf8(bytes.subarray(koly.xmlOffset, koly.xmlOffset + koly.xmlLength))); } catch (e) { warnings.push(`resource map is not a readable plist: ${(e as Error).message}`); return info; }
  const rf = isDict(pl) ? pl['resource-fork'] : undefined;
  if (!isDict(rf)) { warnings.push('resource map has no resource-fork dictionary'); return info; }
  info.resourceKeys = Object.keys(rf);
  const blkx = rf.blkx;
  if (!Array.isArray(blkx)) { warnings.push('resource map has no blkx array'); return info; }
  const cache = new Map<number, DmgChunk[]>();
  for (let i = 0; i < blkx.length && i < maxParts; i++) {
    const e = blkx[i];
    if (!isDict(e) || !(e.Data instanceof Uint8Array)) continue;
    let m;
    try { m = parseMish(e.Data, warnings, maxChunks); } catch (err) { warnings.push(`partition ${i}: ${(err as Error).message}`); continue; }
    const methods: Record<string, number> = {};
    let compressed = 0;
    for (const c of m.chunks) {
      if (c.type === 'end' || c.type === 'comment') continue;
      methods[c.type] = (methods[c.type] ?? 0) + 1;
      info.methods[c.type] = (info.methods[c.type] ?? 0) + 1;
      compressed += c.length;
    }
    const name = typeof e.Name === 'string' ? e.Name : typeof e.CFName === 'string' ? e.CFName : '';
    const id = typeof e.ID === 'number' ? e.ID : typeof e.ID === 'string' && /^-?\d+$/.test(e.ID) ? Number(e.ID) : null;
    const attr = e.Attributes;
    cache.set(info.partitions.length, m.chunks);
    info.partitions.push({
      index: info.partitions.length, id, name, attributes: typeof attr === 'string' || typeof attr === 'number' ? attr : null,
      firstSector: m.first, sectorCount: m.count, size: m.count * SECTOR, dataOffset: m.dataOffset, checksum: m.checksum,
      chunkCount: m.chunks.length, methods, compressedBytes: compressed,
    });
  }
  chunkCache.set(bytes, cache);
  return info;
}

/** Chunk table of one partition. */
export function dmgChunks(bytes: Uint8Array, info: DmgInfo, index: number): DmgChunk[] {
  let c = chunkCache.get(bytes);
  if (!c) { parseDmg(bytes); c = chunkCache.get(bytes); }
  const chunks = c?.get(index);
  if (!chunks || !info.partitions[index]) throw new FormatError(`no partition ${index}`);
  return chunks;
}

export interface ExtractedPartition { bytes: Uint8Array; crc32: string; checksumMatches: boolean | null; unsupported: string[] }

/** Expand one partition to its raw sectors and check its CRC-32 when the image stores one. */
export async function extractDmgPartition(bytes: Uint8Array, info: DmgInfo, index: number, opts: { maxBytes?: number } = {}): Promise<ExtractedPartition> {
  const maxBytes = opts.maxBytes ?? 512 * 1024 * 1024;
  const p = info.partitions[index];
  if (!p) throw new FormatError(`no partition ${index}`);
  if (p.size > maxBytes) throw new FormatError(`partition ${index} expands to ${p.size} bytes, over the ${maxBytes} byte limit`);
  const out = new Uint8Array(p.size);
  const unsupported = new Set<string>();
  const base = info.koly.dataForkOffset + p.dataOffset;
  for (const c of dmgChunks(bytes, info, index)) {
    if (c.type === 'end') break;
    if (c.type === 'comment' || c.type === 'zero' || c.type === 'ignore') continue;
    const dst = c.sector * SECTOR, want = c.sectors * SECTOR;
    if (dst + want > out.length) throw new FormatError(`chunk at sector ${c.sector} runs past the partition`);
    const src = base + c.offset;
    if (src < 0 || src + c.length > bytes.length) throw new FormatError(`chunk data at ${src} is outside the file`);
    const data = bytes.subarray(src, src + c.length);
    let dec: Uint8Array;
    switch (c.type) {
      case 'raw': dec = data; break;
      case 'zlib': dec = await decompress(data, 'deflate', want); break;
      case 'bzip2': dec = bunzip2(data, want); break;
      case 'adc': dec = adcDecompress(data, want); break;
      case 'lzfse':
        try { dec = lzfseDecompress(data, want); } catch (e) { if (e instanceof UnsupportedCodec) { unsupported.add('lzfse'); continue; } throw e; }
        break;
      default: unsupported.add(c.type); continue;
    }
    out.set(dec.subarray(0, Math.min(dec.length, want)), dst);
  }
  const crc = crc32(out);
  const crcHex = crc.toString(16).padStart(8, '0');
  // Like 7-Zip, a partition with ignored (free) chunks is not checked: its stored checksum does not cover zero filled gaps.
  const matches = p.checksum.typeId === 2 && !unsupported.size && !p.methods.ignore ? p.checksum.value.slice(0, 8) === crcHex : null;
  return { bytes: out, crc32: crcHex, checksumMatches: matches, unsupported: [...unsupported] };
}

export interface DmgPartitionReport extends DmgPartition {
  decoded?: { crc32: string; checksumMatches: boolean | null; unsupported: string[]; filesystem: string; hfs?: HfsVolume; apfs?: ApfsContainer; error?: string };
}
export interface DmgReport extends Omit<DmgInfo, 'partitions'> { partitions: DmgPartitionReport[]; dataForkCrc32?: string; dataChecksumMatches?: boolean | null; masterChecksumMatches?: boolean | null }

function fsOf(b: Uint8Array): string {
  if (isHfsPlus(b)) return b[1025] === 0x58 ? 'hfsx' : 'hfs+';
  if (isApfs(b)) return 'apfs';
  if (b.length > 512 && b[510] === 0x55 && b[511] === 0xaa) return 'mbr';
  if (b.length >= 8 && decodeUtf8(b.subarray(0, 8)) === 'EFI PART') return 'gpt-header';
  if (b.length > 0x8001 + 5 && decodeUtf8(b.subarray(0x8001, 0x8006)) === 'CD001') return 'iso9660';
  return 'unknown';
}

/**
 * Full disk image view: trailer, partitions, data fork CRC, and for each partition that holds a file
 * system (or every partition with decode: 'all') the decompressed CRC check plus the HFS+ file list
 * or the APFS container and volume names.
 */
export async function inspectDmg(bytes: Uint8Array, opts: { decode?: 'filesystems' | 'all' | 'none'; maxEntries?: number; maxPartitionBytes?: number } = {}): Promise<DmgReport> {
  const info = parseDmg(bytes);
  const report: DmgReport = { ...info, partitions: info.partitions.map((p) => ({ ...p })) };
  if (info.dataChecksum.typeId === 2 && info.koly.dataForkLength <= bytes.length) {
    const crc = crc32(bytes.subarray(info.koly.dataForkOffset, info.koly.dataForkOffset + info.koly.dataForkLength)).toString(16).padStart(8, '0');
    report.dataForkCrc32 = crc;
    report.dataChecksumMatches = info.dataChecksum.value.slice(0, 8) === crc;
  }
  // The master checksum is the CRC-32 of every partition checksum, concatenated.
  if (info.masterChecksum.typeId === 2 && info.partitions.length && info.partitions.every((p) => p.checksum.typeId === 2)) {
    const all = new Uint8Array(info.partitions.length * 4);
    info.partitions.forEach((p, i) => { const x = parseInt(p.checksum.value.slice(0, 8), 16); all[i * 4] = x >>> 24; all[i * 4 + 1] = (x >>> 16) & 255; all[i * 4 + 2] = (x >>> 8) & 255; all[i * 4 + 3] = x & 255; });
    report.masterChecksumMatches = crc32(all).toString(16).padStart(8, '0') === info.masterChecksum.value.slice(0, 8);
  }
  const mode = opts.decode ?? 'filesystems';
  if (mode === 'none') return report;
  const looksFs = (p: DmgPartition): boolean => /apple_hfs|apple_hfsx|apfs|hfs|disk image|apple_ufs/i.test(p.name) || (info.partitions.length === 1);
  for (const p of report.partitions) {
    if (mode === 'filesystems' && !looksFs(p)) continue;
    try {
      const x = await extractDmgPartition(bytes, info, p.index, { maxBytes: opts.maxPartitionBytes ?? 512 * 1024 * 1024 });
      const filesystem = fsOf(x.bytes);
      p.decoded = { crc32: x.crc32, checksumMatches: x.checksumMatches, unsupported: x.unsupported, filesystem };
      if (filesystem === 'hfs+' || filesystem === 'hfsx') p.decoded.hfs = readHfsPlus(x.bytes, { maxEntries: opts.maxEntries ?? 20_000 });
      else if (filesystem === 'apfs') p.decoded.apfs = readApfsContainer(x.bytes);
    } catch (e) {
      p.decoded = { crc32: '', checksumMatches: null, unsupported: [], filesystem: 'unknown', error: (e as Error).message };
    }
  }
  return report;
}

/** Hex helper kept for callers that want the segment id as a UUID. */
export function dmgSegmentUuid(info: DmgInfo): string {
  const h = info.koly.segmentId;
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

