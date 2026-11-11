// Firmware container parsers: U-Boot uImage, FDT/DTB and FIT images, Intel HEX, Motorola
// S-records, UF2, DfuSe, ESP32 app images, Android boot images, SquashFS (superblock and,
// for gzip images, the file listing), CPIO (newc, odc, binary), UEFI firmware volumes,
// TRX, plus a bounded signature scan that finds embedded images at any offset.

import { View, ParseError, crc32, toHex, latin1, utf8, guid, inflate, startsWithBytes, ascii, unixTime } from '../util.js';
import { sha256 } from '@revlens/core';

// ---------------- uImage ----------------
const UIMAGE_OS: Record<number, string> = { 0: 'invalid', 1: 'OpenBSD', 2: 'NetBSD', 3: 'FreeBSD', 4: '4.4BSD', 5: 'Linux', 6: 'SVR4', 14: 'QNX', 17: 'U-Boot', 20: 'ARM Trusted Firmware', 22: 'OP-TEE', 23: 'OpenSBI', 24: 'EFI' };
const UIMAGE_ARCH: Record<number, string> = { 0: 'invalid', 1: 'alpha', 2: 'arm', 3: 'x86', 4: 'ia64', 5: 'mips', 6: 'mips64', 7: 'ppc', 8: 's390', 9: 'sh', 10: 'sparc', 11: 'sparc64', 12: 'm68k', 15: 'microblaze', 16: 'nios2', 17: 'blackfin', 18: 'avr32', 20: 'sandbox', 21: 'nds32', 22: 'openrisc', 23: 'arm64', 24: 'arc', 25: 'x86_64', 26: 'xtensa', 27: 'riscv' };
const UIMAGE_TYPE: Record<number, string> = { 1: 'standalone', 2: 'kernel', 3: 'ramdisk', 4: 'multi', 5: 'firmware', 6: 'script', 7: 'filesystem', 8: 'flat_dt', 9: 'kwbimage', 10: 'imximage' };
const UIMAGE_COMP: Record<number, string> = { 0: 'none', 1: 'gzip', 2: 'bzip2', 3: 'lzma', 4: 'lzo', 5: 'lz4', 6: 'zstd' };

export interface UImage { offset: number; name: string; size: number; loadAddress: number; entryPoint: number; created: string | null; os: string; arch: string; type: string; compression: string; headerCrc: string; headerCrcValid: boolean; dataCrc: string; dataCrcValid: boolean | null; multi?: number[] }

export function parseUImage(b: Uint8Array, off = 0): UImage {
  const v = new View(b, false);
  if (v.u32(off) !== 0x27051956) throw new ParseError('not a uImage', off);
  v.need(off, 64);
  const hdr = b.slice(off, off + 64);
  const hcrc = v.u32(off + 4);
  hdr[4] = hdr[5] = hdr[6] = hdr[7] = 0;
  const size = v.u32(off + 12);
  const dcrc = v.u32(off + 24);
  const type = v.u8(off + 30);
  const dataOk = v.has(off + 64, size);
  const out: UImage = {
    offset: off, name: latin1(v.sub(off + 32, 32)).replace(/\0[\s\S]*$/, ''), size, loadAddress: v.u32(off + 16), entryPoint: v.u32(off + 20),
    created: unixTime(v.u32(off + 8)), os: UIMAGE_OS[v.u8(off + 28)] ?? String(v.u8(off + 28)), arch: UIMAGE_ARCH[v.u8(off + 29)] ?? String(v.u8(off + 29)),
    type: UIMAGE_TYPE[type] ?? String(type), compression: UIMAGE_COMP[v.u8(off + 31)] ?? String(v.u8(off + 31)),
    headerCrc: hcrc.toString(16).padStart(8, '0'), headerCrcValid: crc32(hdr) === hcrc,
    dataCrc: dcrc.toString(16).padStart(8, '0'), dataCrcValid: dataOk ? crc32(b, off + 64, off + 64 + size) === dcrc : null,
  };
  if (type === 4 && dataOk) {
    const sizes: number[] = [];
    for (let p = off + 64; p + 4 <= off + 64 + size && sizes.length < 64; p += 4) { const s = v.u32(p); if (!s) break; sizes.push(s); }
    out.multi = sizes;
  }
  return out;
}

// ---------------- FDT / FIT ----------------
export interface FdtProp { length: number; offset: number; text?: string; u32?: number[]; hex?: string }
export interface FdtNode { name: string; path: string; props: Record<string, FdtProp>; children: FdtNode[] }
export interface Fdt { offset: number; totalSize: number; version: number; bootCpu: number; reserved: { address: string; size: string }[]; root: FdtNode; nodeCount: number; model?: string; compatible?: string[]; fit?: FitInfo }
export interface FitInfo { description?: string; images: { name: string; type?: string; arch?: string; os?: string; compression?: string; description?: string; dataSize: number; dataOffset?: number; load?: number; entry?: number; hashes: { algo: string; value: string; matches: boolean | null }[] }[]; configurations: { name: string; refs: Record<string, string> }[]; defaultConfig?: string }

function propValue(rawb: Uint8Array): { text?: string; u32?: number[]; hex?: string } {
  if (rawb.length > 0 && rawb[rawb.length - 1] === 0) {
    const parts = latin1(rawb.subarray(0, rawb.length - 1)).split('\0');
    if (parts.every((s) => s.length > 0 && /^[\x20-\x7e]+$/.test(s))) return { text: parts.join('\0') };
  }
  if (rawb.length % 4 === 0 && rawb.length <= 64) {
    const v = new View(rawb, false);
    const u: number[] = [];
    for (let i = 0; i < rawb.length; i += 4) u.push(v.u32(i));
    return { u32: u };
  }
  return { hex: toHex(rawb.subarray(0, 64)) };
}

export function parseFdt(b: Uint8Array, off = 0, opts: { maxNodes?: number } = {}): Fdt {
  const v = new View(b, false);
  if (v.u32(off) !== 0xd00dfeed) throw new ParseError('not a device tree blob', off);
  const total = v.u32(off + 4), structOff = off + v.u32(off + 8), strOff = off + v.u32(off + 12), rsvOff = off + v.u32(off + 16);
  const version = v.u32(off + 20);
  const structSize = version >= 17 ? v.u32(off + 36) : total;
  const end = Math.min(off + total, b.length, structOff + structSize);
  const reserved: Fdt['reserved'] = [];
  for (let p = rsvOff; p + 16 <= b.length && reserved.length < 64; p += 16) {
    const a = v.u64(p), s = v.u64(p + 8);
    if (a === 0n && s === 0n) break;
    reserved.push({ address: '0x' + a.toString(16), size: '0x' + s.toString(16) });
  }
  const maxNodes = opts.maxNodes ?? 20000;
  let count = 0;
  const root: FdtNode = { name: '', path: '/', props: {}, children: [] };
  const stack: FdtNode[] = [];
  let p = structOff;
  let cur: FdtNode | null = null;
  while (p + 4 <= end) {
    const tok = v.u32(p);
    p += 4;
    if (tok === 1) {
      const name = v.cstr(p, 1024);
      p = (p + name.length + 1 + 3) & ~3;
      if (++count > maxNodes) throw new ParseError('too many FDT nodes', p);
      if (stack.length > 64) throw new ParseError('FDT nesting too deep', p);
      const parent = stack[stack.length - 1];
      const node: FdtNode = parent ? { name, path: (parent.path === '/' ? '' : parent.path) + '/' + name, props: {}, children: [] } : root;
      if (parent) parent.children.push(node);
      stack.push(node);
      cur = node;
    } else if (tok === 3) {
      const len = v.u32(p), nameoff = v.u32(p + 4);
      const name = v.cstr(strOff + nameoff, 256);
      const dataOff = p + 8;
      v.need(dataOff, len);
      if (cur) cur.props[name] = { length: len, offset: dataOff, ...(len <= 4096 ? propValue(v.sub(dataOff, len)) : { hex: toHex(v.sub(dataOff, 32)) }) };
      p = (dataOff + len + 3) & ~3;
    } else if (tok === 2) {
      stack.pop();
      cur = stack[stack.length - 1] ?? null;
    } else if (tok === 4) continue;
    else if (tok === 9) break;
    else throw new ParseError(`bad FDT token ${tok}`, p - 4);
  }
  const fdt: Fdt = { offset: off, totalSize: total, version, bootCpu: v.u32(off + 28), reserved, root, nodeCount: count };
  if (root.props.model?.text) fdt.model = root.props.model.text;
  if (root.props.compatible?.text) fdt.compatible = root.props.compatible.text.split('\0');
  const images = root.children.find((c) => c.name === 'images');
  if (images) fdt.fit = fitInfo(b, fdt, images);
  return fdt;
}

function fitInfo(b: Uint8Array, fdt: Fdt, images: FdtNode): FitInfo {
  const t = (n: FdtNode, k: string): string | undefined => n.props[k]?.text;
  const u = (n: FdtNode, k: string): number | undefined => { const a = n.props[k]?.u32; return a ? a[a.length - 1] : undefined; };
  const info: FitInfo = { images: [], configurations: [] };
  const d = t(fdt.root, 'description');
  if (d) info.description = d;
  for (const img of images.children.slice(0, 256)) {
    const data = img.props.data;
    let dataOffset: number | undefined, dataSize = 0;
    if (data) { dataOffset = data.offset; dataSize = data.length; }
    else if (img.props['data-offset'] || img.props['data-position']) {
      const rel = u(img, 'data-offset');
      const abs = u(img, 'data-position');
      dataSize = u(img, 'data-size') ?? 0;
      dataOffset = abs !== undefined ? fdt.offset + abs : rel !== undefined ? fdt.offset + ((fdt.totalSize + 3) & ~3) + rel : undefined;
    }
    const hashes: FitInfo['images'][number]['hashes'] = [];
    for (const h of img.children.filter((c) => c.name.startsWith('hash'))) {
      const algo = t(h, 'algo') ?? '';
      const val = h.props.value;
      const value = val ? toHex(b.subarray(val.offset, val.offset + val.length)) : '';
      let matches: boolean | null = null;
      if (dataOffset !== undefined && dataOffset + dataSize <= b.length) {
        const bytes = b.subarray(dataOffset, dataOffset + dataSize);
        if (algo === 'crc32') matches = crc32(bytes).toString(16).padStart(8, '0') === value;
        else if (algo === 'sha256') matches = sha256(bytes) === value;
      }
      hashes.push({ algo, value, matches });
    }
    const opt = <K extends string>(k: K, val: unknown): Record<string, unknown> => (val !== undefined ? { [k]: val } : {});
    info.images.push({
      name: img.name, ...opt('type', t(img, 'type')), ...opt('arch', t(img, 'arch')), ...opt('os', t(img, 'os')),
      ...opt('compression', t(img, 'compression')), ...opt('description', t(img, 'description')),
      dataSize, ...opt('dataOffset', dataOffset), ...opt('load', u(img, 'load')), ...opt('entry', u(img, 'entry')), hashes,
    } as FitInfo['images'][number]);
  }
  const conf = fdt.root.children.find((c) => c.name === 'configurations');
  if (conf) {
    const def = t(conf, 'default');
    if (def) info.defaultConfig = def;
    for (const c of conf.children.slice(0, 256)) {
      const refs: Record<string, string> = {};
      for (const [k, p] of Object.entries(c.props)) if (p.text && k !== 'description') refs[k] = p.text;
      info.configurations.push({ name: c.name, refs });
    }
  }
  return info;
}

// ---------------- Intel HEX and S-records ----------------
export interface Region { start: number; end: number; size: number }
export interface HexImage { format: 'intel-hex' | 'srec'; records: number; badChecksums: number[]; dataBytes: number; regions: Region[]; startAddress?: number; header?: string; errors: string[] }

function mergeRegions(chunks: [number, number][]): Region[] {
  chunks.sort((a, b) => a[0] - b[0]);
  const out: Region[] = [];
  for (const [s, l] of chunks) {
    const last = out[out.length - 1];
    if (last && s <= last.end) { last.end = Math.max(last.end, s + l); last.size = last.end - last.start; }
    else out.push({ start: s, end: s + l, size: l });
  }
  return out;
}

export function parseIntelHex(text: string, opts: { toBinary?: boolean; maxBytes?: number } = {}): HexImage & { data?: { address: number; bytes: Uint8Array }[] } {
  const res: HexImage & { data?: { address: number; bytes: Uint8Array }[] } = { format: 'intel-hex', records: 0, badChecksums: [], dataBytes: 0, regions: [], errors: [] };
  const chunks: [number, number][] = [];
  const data: { address: number; bytes: Uint8Array }[] = [];
  let base = 0;
  const lines = text.split(/\r?\n/);
  for (let ln = 0; ln < lines.length && ln < 5_000_000; ln++) {
    const line = (lines[ln] as string).trim();
    if (!line) continue;
    if (line.length > 600 || !/^:[0-9A-Fa-f]{10,}$/.test(line) || line.length % 2 === 0) { res.errors.push(`line ${ln + 1}: not a record`); if (res.errors.length > 50) break; continue; }
    const bytes: number[] = [];
    for (let i = 1; i < line.length; i += 2) bytes.push(parseInt(line.slice(i, i + 2), 16));
    const n = bytes[0] as number;
    if (bytes.length !== n + 5) { res.errors.push(`line ${ln + 1}: length mismatch`); continue; }
    if (bytes.reduce((a, c) => (a + c) & 0xff, 0) !== 0) res.badChecksums.push(ln + 1);
    res.records++;
    const addr = ((bytes[1] as number) << 8) | (bytes[2] as number);
    const type = bytes[3] as number;
    const payload = bytes.slice(4, 4 + n);
    const be32 = (): number => ((((payload[0] ?? 0) << 24) | ((payload[1] ?? 0) << 16) | ((payload[2] ?? 0) << 8) | (payload[3] ?? 0)) >>> 0);
    if (type === 0) {
      chunks.push([base + addr, n]);
      res.dataBytes += n;
      if (opts.toBinary && res.dataBytes <= (opts.maxBytes ?? 16 << 20)) data.push({ address: base + addr, bytes: new Uint8Array(payload) });
    } else if (type === 1) break;
    else if (type === 2) base = (((payload[0] ?? 0) << 8) | (payload[1] ?? 0)) * 16;
    else if (type === 4) base = (((payload[0] ?? 0) << 8) | (payload[1] ?? 0)) * 65536;
    else if (type === 3) res.startAddress = (((payload[0] ?? 0) << 8 | (payload[1] ?? 0)) * 16) + (((payload[2] ?? 0) << 8) | (payload[3] ?? 0));
    else if (type === 5) res.startAddress = be32();
  }
  res.regions = mergeRegions(chunks);
  if (opts.toBinary) res.data = data;
  return res;
}

export function parseSrec(text: string): HexImage {
  const res: HexImage = { format: 'srec', records: 0, badChecksums: [], dataBytes: 0, regions: [], errors: [] };
  const chunks: [number, number][] = [];
  const lines = text.split(/\r?\n/);
  for (let ln = 0; ln < lines.length && ln < 5_000_000; ln++) {
    const line = (lines[ln] as string).trim();
    if (!line) continue;
    if (line.length > 600 || !/^S[0-9][0-9A-Fa-f]{6,}$/.test(line)) { res.errors.push(`line ${ln + 1}: not a record`); if (res.errors.length > 50) break; continue; }
    const t = Number(line[1]);
    const bytes: number[] = [];
    for (let i = 2; i < line.length; i += 2) bytes.push(parseInt(line.slice(i, i + 2), 16));
    const count = bytes[0] as number;
    if (bytes.length !== count + 1) { res.errors.push(`line ${ln + 1}: length mismatch`); continue; }
    const sum = bytes.slice(0, -1).reduce((a, c) => (a + c) & 0xff, 0);
    if (((~sum) & 0xff) !== bytes[bytes.length - 1]) res.badChecksums.push(ln + 1);
    res.records++;
    const alen = t === 0 || t === 1 || t === 5 || t === 9 ? 2 : t === 2 || t === 6 || t === 8 ? 3 : 4;
    let addr = 0;
    for (let i = 0; i < alen; i++) addr = addr * 256 + (bytes[1 + i] ?? 0);
    const payload = bytes.slice(1 + alen, -1);
    if (t === 0) res.header = latin1(new Uint8Array(payload));
    else if (t >= 1 && t <= 3) { chunks.push([addr, payload.length]); res.dataBytes += payload.length; }
    else if (t >= 7 && t <= 9) res.startAddress = addr;
  }
  res.regions = mergeRegions(chunks);
  return res;
}

// ---------------- UF2 ----------------
const UF2_FAMILIES: Record<number, string> = {
  0xe48bff56: 'RP2040', 0xe48bff59: 'RP2350 ARM secure', 0xe48bff5b: 'RP2350 ARM non-secure', 0xe48bff5a: 'RP2350 RISC-V', 0x68ed2b88: 'SAMD21', 0x55114460: 'SAMD51',
  0xada52840: 'nRF52840', 0x1b57745f: 'nRF52', 0x57755a57: 'STM32F4', 0x5ee21072: 'STM32F1', 0x5d1a0a2e: 'STM32F2', 0x6b846188: 'STM32F3', 0x53b80f00: 'STM32F7',
  0x6d0922fa: 'STM32F407', 0xbfdd4eee: 'ESP32-S2', 0xc47e5767: 'ESP32-S3', 0xd42ba06c: 'ESP32-C3', 0x2b88d29c: 'ESP32-C2', 0x332726f6: 'ESP32-H2', 0x540ddf62: 'ESP32-C6', 0x1c5f21b0: 'ESP32',
  0x16573617: 'Microchip ATmega32', 0x4fb2d5bd: 'MIMXRT10XX', 0x2abc77ec: 'LPC55', 0x00ff6919: 'STM32L4', 0x4c71240a: 'STM32G4',
};
export interface Uf2Info { blocks: number; declaredBlocks: number; missingBlocks: number[]; families: { id: string; name: string; blocks: number }[]; regions: Region[]; payloadBytes: number; flags: string[]; invalidBlocks: number[] }

export function parseUf2(b: Uint8Array): Uf2Info {
  const v = new View(b, true);
  const info: Uf2Info = { blocks: 0, declaredBlocks: 0, missingBlocks: [], families: [], regions: [], payloadBytes: 0, flags: [], invalidBlocks: [] };
  const fam = new Map<number, number>();
  const seen = new Set<number>();
  const chunks: [number, number][] = [];
  const flagSet = new Set<string>();
  for (let i = 0; i * 512 + 512 <= b.length && i < 1_000_000; i++) {
    const o = i * 512;
    if (v.u32(o) !== 0x0a324655 || v.u32(o + 4) !== 0x9e5d5157 || v.u32(o + 508) !== 0x0ab16f30) { info.invalidBlocks.push(i); if (info.invalidBlocks.length > 1000) break; continue; }
    info.blocks++;
    const flags = v.u32(o + 8), addr = v.u32(o + 12), size = v.u32(o + 16), no = v.u32(o + 20), num = v.u32(o + 24), famId = v.u32(o + 28);
    if (flags & 1) flagSet.add('NOT_MAIN_FLASH');
    if (flags & 0x1000) flagSet.add('FILE_CONTAINER');
    if (flags & 0x2000) { flagSet.add('FAMILY_ID_PRESENT'); fam.set(famId, (fam.get(famId) ?? 0) + 1); }
    if (flags & 0x4000) flagSet.add('MD5_PRESENT');
    if (flags & 0x8000) flagSet.add('EXTENSION_TAGS');
    info.declaredBlocks = Math.min(Math.max(info.declaredBlocks, num), 1_000_000);
    seen.add(no);
    if (!(flags & 1) && size <= 476) { chunks.push([addr, size]); info.payloadBytes += size; }
  }
  for (let i = 0; i < info.declaredBlocks && info.missingBlocks.length < 1000; i++) if (!seen.has(i)) info.missingBlocks.push(i);
  info.families = [...fam.entries()].map(([id, n]) => ({ id: '0x' + id.toString(16).padStart(8, '0'), name: UF2_FAMILIES[id] ?? 'unknown', blocks: n }));
  info.regions = mergeRegions(chunks);
  info.flags = [...flagSet];
  return info;
}

// ---------------- DfuSe ----------------
export interface DfuInfo { kind: 'dfuse' | 'dfu'; version?: number; targets: { altSetting: number; name: string; elements: { address: number; size: number; offset: number }[] }[]; suffix?: { bcdDevice: string; idProduct: string; idVendor: string; bcdDFU: string; crc: string; crcValid: boolean } }

export function parseDfu(b: Uint8Array): DfuInfo {
  const v = new View(b, true);
  const info: DfuInfo = { kind: startsWithBytes(b, ascii('DfuSe')) ? 'dfuse' : 'dfu', targets: [] };
  if (b.length >= 16 && latin1(b.subarray(b.length - 8, b.length - 5)) === 'UFD') {
    const s = b.length - 16;
    const crc = v.u32(b.length - 4);
    const computed = (~crc32(b, 0, b.length - 4)) >>> 0;
    info.suffix = { bcdDevice: v.u16(s).toString(16), idProduct: v.u16(s + 2).toString(16).padStart(4, '0'), idVendor: v.u16(s + 4).toString(16).padStart(4, '0'), bcdDFU: v.u16(s + 6).toString(16), crc: crc.toString(16).padStart(8, '0'), crcValid: computed === crc };
  }
  if (info.kind === 'dfuse') {
    info.version = v.u8(5);
    const nTargets = v.u8(10);
    let p = 11;
    for (let t = 0; t < Math.min(nTargets, 255); t++) {
      if (latin1(v.sub(p, 6)) !== 'Target') throw new ParseError('bad DfuSe target', p);
      const alt = v.u8(p + 6);
      const named = v.u32(p + 7);
      const name = named ? latin1(v.sub(p + 11, 255)).replace(/\0[\s\S]*$/, '') : '';
      const nElem = v.u32(p + 270);
      let q = p + 274;
      const elements: { address: number; size: number; offset: number }[] = [];
      for (let e = 0; e < Math.min(nElem, 4096); e++) {
        const addr = v.u32(q), size = v.u32(q + 4);
        v.need(q + 8, size);
        elements.push({ address: addr, size, offset: q + 8 });
        q += 8 + size;
      }
      info.targets.push({ altSetting: alt, name, elements });
      p = q;
    }
  }
  return info;
}

// ---------------- ESP32 app image ----------------
const ESP_CHIPS: Record<number, string> = { 0: 'ESP32', 2: 'ESP32-S2', 5: 'ESP32-C3', 9: 'ESP32-S3', 12: 'ESP32-C2', 13: 'ESP32-C6', 16: 'ESP32-H2', 18: 'ESP32-P4', 23: 'ESP32-C5', 20: 'ESP32-C61' };
export interface EspImage { segments: { index: number; loadAddress: number; size: number; offset: number }[]; entry: number; chip: string; flash: { mode: number; sizeFreq: number }; checksum: number; checksumValid: boolean; hashAppended: boolean; sha256?: string; sha256Valid?: boolean; appDesc?: { version: string; project: string; time: string; date: string; idf: string } }

export function parseEspImage(b: Uint8Array, off = 0): EspImage {
  const v = new View(b, true);
  if (v.u8(off) !== 0xe9) throw new ParseError('not an ESP image', off);
  const nseg = v.u8(off + 1);
  const chipId = v.u16(off + 12);
  const hashAppended = v.u8(off + 23) === 1;
  let p = off + 24;
  let x = 0xef;
  const segments: EspImage['segments'] = [];
  for (let i = 0; i < Math.min(nseg, 16); i++) {
    const load = v.u32(p), size = v.u32(p + 4);
    v.need(p + 8, size);
    segments.push({ index: i, loadAddress: load, size, offset: p + 8 });
    for (let k = p + 8; k < p + 8 + size; k++) x ^= b[k] as number;
    p += 8 + size;
  }
  const padEnd = ((p - off + 1 + 15) & ~15) + off;
  const ck = v.u8(padEnd - 1);
  const img: EspImage = { segments, entry: v.u32(off + 4), chip: ESP_CHIPS[chipId] ?? `chip ${chipId}`, flash: { mode: v.u8(off + 2), sizeFreq: v.u8(off + 3) }, checksum: ck, checksumValid: ck === x, hashAppended };
  if (hashAppended && v.has(padEnd, 32)) {
    img.sha256 = toHex(v.sub(padEnd, 32));
    img.sha256Valid = sha256(b.subarray(off, padEnd)) === img.sha256;
  }
  for (const s of segments) {
    if (v.has(s.offset, 256) && v.u32(s.offset) === 0xabcd5432) {
      img.appDesc = { version: v.cstr(s.offset + 16, 32), project: v.cstr(s.offset + 48, 32), time: v.cstr(s.offset + 80, 16), date: v.cstr(s.offset + 96, 16), idf: v.cstr(s.offset + 112, 32) };
      break;
    }
  }
  return img;
}

// ---------------- Android boot image ----------------
export interface BootImage { headerVersion: number; pageSize: number; kernel: { size: number; offset: number; address?: number }; ramdisk: { size: number; offset: number; address?: number }; second?: { size: number; offset: number }; dtb?: { size: number; offset: number }; osVersion?: string; osPatchLevel?: string; name?: string; cmdline: string; kernelMagic?: string }

function sniffKernel(b: Uint8Array): string {
  if (startsWithBytes(b, [0x1f, 0x8b])) return 'gzip';
  if (startsWithBytes(b, [0x02, 0x21, 0x4c, 0x18])) return 'lz4-legacy';
  if (b.length >= 60 && b[56] === 0x41 && b[57] === 0x52 && b[58] === 0x4d && b[59] === 0x64) return 'arm64 Image';
  if (startsWithBytes(b, [0x4d, 0x5a])) return 'EFI zImage';
  return toHex(b.subarray(0, 4));
}

export function parseBootImage(b: Uint8Array): BootImage {
  const v = new View(b, true);
  if (latin1(v.sub(0, 8)) !== 'ANDROID!') throw new ParseError('not an Android boot image');
  const hv = v.u32(40);
  const osv = (x: number): { ver: string; patch: string } => {
    const ver = x >>> 11, patch = x & 0x7ff;
    return { ver: `${(ver >>> 14) & 0x7f}.${(ver >>> 7) & 0x7f}.${ver & 0x7f}`, patch: `${(patch >>> 4) + 2000}-${String(patch & 0xf).padStart(2, '0')}` };
  };
  const al = (n: number, pg: number): number => Math.ceil(n / pg) * pg;
  if (hv >= 3 && hv < 16) {
    const ks = v.u32(8), rs = v.u32(12), os = osv(v.u32(16)), hsize = v.u32(20);
    const pg = 4096;
    const kOff = al(hsize, pg);
    const rOff = kOff + al(ks, pg);
    const r: BootImage = { headerVersion: hv, pageSize: pg, kernel: { size: ks, offset: kOff }, ramdisk: { size: rs, offset: rOff }, osVersion: os.ver, osPatchLevel: os.patch, cmdline: v.cstr(44, 1536) };
    if (v.has(kOff, 64)) r.kernelMagic = sniffKernel(b.subarray(kOff, kOff + 64));
    return r;
  }
  const ks = v.u32(8), ka = v.u32(12), rs = v.u32(16), ra = v.u32(20), ss = v.u32(24), pg = v.u32(36) || 2048;
  if (pg > 1 << 20) throw new ParseError('bad page size');
  const os = osv(v.u32(44));
  const kOff = pg, rOff = kOff + al(ks, pg), sOff = rOff + al(rs, pg);
  const r: BootImage = { headerVersion: hv, pageSize: pg, kernel: { size: ks, offset: kOff, address: ka }, ramdisk: { size: rs, offset: rOff, address: ra }, osVersion: os.ver, osPatchLevel: os.patch, name: v.cstr(48, 16), cmdline: v.cstr(64, 512) + (v.has(608, 1) ? v.cstr(608, 1024) : '') };
  if (ss) r.second = { size: ss, offset: sOff };
  let next = sOff + al(ss, pg);
  if (hv >= 1 && v.has(1632, 16)) { const dtboSize = v.u32(1632); if (dtboSize) next += al(dtboSize, pg); }
  if (hv === 2 && v.has(1648, 12)) { const dtbSize = v.u32(1648); if (dtbSize) r.dtb = { size: dtbSize, offset: next }; }
  if (v.has(kOff, 64)) r.kernelMagic = sniffKernel(b.subarray(kOff, kOff + 64));
  return r;
}

// ---------------- SquashFS ----------------
const SQ_COMP: Record<number, string> = { 1: 'gzip', 2: 'lzma', 3: 'lzo', 4: 'xz', 5: 'lz4', 6: 'zstd' };
export interface SquashEntry { path: string; type: 'dir' | 'file' | 'symlink' | 'block' | 'char' | 'fifo' | 'socket'; mode: string; size?: number; target?: string; mtime: number; inode: number }
export interface Squashfs { offset: number; version: string; compression: string; blockSize: number; inodes: number; fragments: number; bytesUsed: number; mkfsTime: string | null; flags: string[]; entries?: SquashEntry[]; listingNote?: string }

const SQ_FLAGS: [number, string][] = [[0x1, 'UNCOMPRESSED_INODES'], [0x2, 'UNCOMPRESSED_DATA'], [0x8, 'UNCOMPRESSED_FRAGMENTS'], [0x10, 'NO_FRAGMENTS'], [0x20, 'ALWAYS_FRAGMENTS'], [0x40, 'DUPLICATES'], [0x80, 'EXPORTABLE'], [0x100, 'UNCOMPRESSED_XATTRS'], [0x200, 'NO_XATTRS'], [0x400, 'COMPRESSOR_OPTIONS'], [0x800, 'UNCOMPRESSED_IDS']];
interface SqInode { type: number; mode: number; mtime: number; inode: number; size?: number; target?: string; dirBlock?: number; dirOffset?: number; dirSize?: number }

export async function parseSquashfs(b: Uint8Array, off = 0, opts: { list?: boolean; maxEntries?: number } = {}): Promise<Squashfs> {
  const v = new View(b, true);
  const magic = v.u32(off);
  if (magic !== 0x73717368) throw new ParseError(magic === 0x68737173 ? 'big endian squashfs is not supported' : 'not a squashfs image', off);
  const flagsRaw = v.u16(off + 24);
  const comp = v.u16(off + 20);
  const sq: Squashfs = {
    offset: off, version: `${v.u16(off + 28)}.${v.u16(off + 30)}`, compression: SQ_COMP[comp] ?? String(comp), blockSize: v.u32(off + 12),
    inodes: v.u32(off + 4), fragments: v.u32(off + 16), bytesUsed: v.u64n(off + 40), mkfsTime: unixTime(v.u32(off + 8)),
    flags: SQ_FLAGS.filter(([f]) => flagsRaw & f).map(([, n]) => n),
  };
  if (!opts.list) return sq;
  if (sq.version !== '4.0') { sq.listingNote = 'listing supports squashfs 4.0 only'; return sq; }
  if (comp !== 1) { sq.listingNote = `listing needs a ${sq.compression} decompressor, which is not built in; superblock facts only`; return sq; }
  const rootRef = v.u64(off + 32);
  const inodeTable = v.u64n(off + 64), dirTable = v.u64n(off + 72);
  const cache = new Map<number, { data: Uint8Array; next: number }>();
  const meta = async (abs: number): Promise<{ data: Uint8Array; next: number }> => {
    const c = cache.get(abs);
    if (c) return c;
    const hdr = v.u16(abs);
    const len = hdr & 0x7fff;
    const rawb = v.sub(abs + 2, len);
    const data = hdr & 0x8000 ? rawb : await inflate(rawb, 'deflate', 1 << 16);
    const r = { data, next: abs + 2 + len };
    cache.set(abs, r);
    if (cache.size > 100000) throw new ParseError('too many metadata blocks');
    return r;
  };
  const readMeta = async (tableStart: number, block: number, offset: number, n: number): Promise<{ bytes: Uint8Array; block: number; offset: number }> => {
    const out = new Uint8Array(n);
    let got = 0, blk = block, o = offset;
    for (let guard = 0; got < n; guard++) {
      if (guard > 4096) throw new ParseError('metadata read did not progress');
      const m = await meta(off + tableStart + blk);
      const take = Math.min(n - got, m.data.length - o);
      if (take <= 0) { if (m.next >= b.length) throw new ParseError('metadata out of range'); blk = m.next - off - tableStart; o = 0; continue; }
      out.set(m.data.subarray(o, o + take), got);
      got += take;
      o += take;
      if (o >= m.data.length) { blk = m.next - off - tableStart; o = 0; }
    }
    return { bytes: out, block: blk, offset: o };
  };
  const entries: SquashEntry[] = [];
  const max = opts.maxEntries ?? 20000;
  const readInode = async (ref: bigint): Promise<SqInode> => {
    const h = await readMeta(inodeTable, Number(ref >> 16n), Number(ref & 0xffffn), 16);
    const hv = new View(h.bytes, true);
    const type = hv.u16(0);
    const r: SqInode = { type, mode: hv.u16(2), mtime: hv.u32(8), inode: hv.u32(12) };
    if (type === 1) { const x = new View((await readMeta(inodeTable, h.block, h.offset, 16)).bytes, true); r.dirBlock = x.u32(0); r.dirSize = x.u16(8); r.dirOffset = x.u16(10); }
    else if (type === 8) { const x = new View((await readMeta(inodeTable, h.block, h.offset, 24)).bytes, true); r.dirSize = x.u32(4); r.dirBlock = x.u32(8); r.dirOffset = x.u16(18); }
    else if (type === 2) { const x = new View((await readMeta(inodeTable, h.block, h.offset, 16)).bytes, true); r.size = x.u32(12); }
    else if (type === 9) { const x = new View((await readMeta(inodeTable, h.block, h.offset, 40)).bytes, true); r.size = x.u64n(8); }
    else if (type === 3 || type === 10) {
      const x1 = await readMeta(inodeTable, h.block, h.offset, 8);
      const tl = new View(x1.bytes, true).u32(4);
      if (tl < 4096) r.target = utf8((await readMeta(inodeTable, x1.block, x1.offset, tl)).bytes);
    }
    return r;
  };
  const TYPE: Record<number, SquashEntry['type']> = { 1: 'dir', 2: 'file', 3: 'symlink', 4: 'block', 5: 'char', 6: 'fifo', 7: 'socket', 8: 'dir', 9: 'file', 10: 'symlink', 11: 'block', 12: 'char', 13: 'fifo', 14: 'socket' };
  const walk = async (ino: SqInode, path: string, depth: number): Promise<void> => {
    if (depth > 64 || ino.dirBlock === undefined || ino.dirSize === undefined || ino.dirOffset === undefined) return;
    let remaining = ino.dirSize - 3;
    let blk = ino.dirBlock, o = ino.dirOffset;
    while (remaining > 12 && entries.length < max) {
      const hdr = await readMeta(dirTable, blk, o, 12);
      blk = hdr.block; o = hdr.offset; remaining -= 12;
      const hv = new View(hdr.bytes, true);
      const count = hv.u32(0) + 1, start = hv.u32(4);
      if (count > 256) throw new ParseError('bad directory header');
      for (let i = 0; i < count && remaining > 0; i++) {
        const e = await readMeta(dirTable, blk, o, 8);
        const ev = new View(e.bytes, true);
        const ioff = ev.u16(0), nameSize = ev.u16(6) + 1;
        const nm = await readMeta(dirTable, e.block, e.offset, nameSize);
        blk = nm.block; o = nm.offset; remaining -= 8 + nameSize;
        const name = utf8(nm.bytes);
        const child = await readInode((BigInt(start) << 16n) | BigInt(ioff));
        const p = `${path}/${name}`;
        const t = TYPE[child.type] ?? 'file';
        entries.push({ path: p, type: t, mode: (child.mode & 0o7777).toString(8).padStart(4, '0'), ...(child.size !== undefined ? { size: child.size } : {}), ...(child.target !== undefined ? { target: child.target } : {}), mtime: child.mtime, inode: child.inode });
        if (t === 'dir') await walk(child, p, depth + 1);
        if (entries.length >= max) break;
      }
    }
  };
  await walk(await readInode(rootRef), '', 0);
  sq.entries = entries;
  return sq;
}

// ---------------- CPIO ----------------
export interface CpioEntry { name: string; mode: string; type: string; size: number; offset: number; mtime: number; uid: number; gid: number; ino: number; target?: string }
const cpioType = (mode: number): string => ({ 0o040000: 'dir', 0o100000: 'file', 0o120000: 'symlink', 0o020000: 'char', 0o060000: 'block', 0o010000: 'fifo', 0o140000: 'socket' } as Record<number, string>)[mode & 0o170000] ?? 'unknown';

export function parseCpio(b: Uint8Array, off = 0, max = 50000): { format: string; entries: CpioEntry[]; trailer: boolean; end: number } {
  const entries: CpioEntry[] = [];
  let p = off;
  let format = '';
  let trailer = false;
  const push = (name: string, mode: number, size: number, dataStart: number, mtime: number, uid: number, gid: number, ino: number): void => {
    const e: CpioEntry = { name, mode: (mode & 0o7777).toString(8).padStart(4, '0'), type: cpioType(mode), size, offset: dataStart, mtime, uid, gid, ino };
    if (e.type === 'symlink' && size < 4096) e.target = latin1(b.subarray(dataStart, dataStart + size));
    entries.push(e);
  };
  while (p + 6 <= b.length && entries.length < max) {
    const magic = latin1(b.subarray(p, p + 6));
    if (magic === '070701' || magic === '070702') {
      format = magic === '070701' ? 'newc' : 'crc';
      if (p + 110 > b.length) break;
      const f = (i: number): number => parseInt(latin1(b.subarray(p + 6 + i * 8, p + 14 + i * 8)), 16);
      const nameSize = f(11), size = f(6);
      if (!Number.isFinite(nameSize) || !Number.isFinite(size)) break;
      const nameStart = p + 110;
      if (nameSize < 1 || nameStart + nameSize > b.length || nameSize > 4096) break;
      const name = latin1(b.subarray(nameStart, nameStart + nameSize - 1));
      const dataStart = (nameStart + nameSize + 3) & ~3;
      if (name === 'TRAILER!!!') { trailer = true; p = dataStart; break; }
      if (dataStart + size > b.length) break;
      push(name, f(1), size, dataStart, f(5), f(2), f(3), f(0));
      p = (dataStart + size + 3) & ~3;
    } else if (magic === '070707') {
      format = 'odc';
      if (p + 76 > b.length) break;
      const o = (s: number, l: number): number => parseInt(latin1(b.subarray(p + s, p + s + l)), 8);
      const nameSize = o(59, 6), size = o(65, 11);
      if (!Number.isFinite(nameSize) || !Number.isFinite(size)) break;
      const nameStart = p + 76;
      if (nameSize < 1 || nameStart + nameSize > b.length || nameSize > 4096) break;
      const name = latin1(b.subarray(nameStart, nameStart + nameSize - 1));
      const dataStart = nameStart + nameSize;
      if (name === 'TRAILER!!!') { trailer = true; p = dataStart; break; }
      if (dataStart + size > b.length) break;
      push(name, o(18, 6), size, dataStart, o(48, 11), o(24, 6), o(30, 6), o(12, 6));
      p = dataStart + size;
    } else if (b[p] === 0xc7 && b[p + 1] === 0x71) {
      format = 'binary';
      const v = new View(b, true);
      if (!v.has(p, 26)) break;
      const nameSize = v.u16(p + 20), size = v.u16(p + 22) * 65536 + v.u16(p + 24);
      const nameStart = p + 26;
      if (nameSize < 1 || nameStart + nameSize > b.length) break;
      const name = latin1(b.subarray(nameStart, nameStart + nameSize - 1));
      const dataStart = nameStart + nameSize + (nameSize & 1);
      if (name === 'TRAILER!!!') { trailer = true; p = dataStart; break; }
      if (dataStart + size > b.length) break;
      push(name, v.u16(p + 6), size, dataStart, v.u16(p + 16) * 65536 + v.u16(p + 18), v.u16(p + 8), v.u16(p + 10), v.u16(p + 4));
      p = dataStart + size + (size & 1);
    } else break;
  }
  if (!format) throw new ParseError('not a cpio archive', off);
  return { format, entries, trailer, end: p };
}

// ---------------- UEFI firmware volumes ----------------
const FFS_TYPES: Record<number, string> = { 1: 'RAW', 2: 'FREEFORM', 3: 'SECURITY_CORE', 4: 'PEI_CORE', 5: 'DXE_CORE', 6: 'PEIM', 7: 'DRIVER', 8: 'COMBINED_PEIM_DRIVER', 9: 'APPLICATION', 0xa: 'MM', 0xb: 'FIRMWARE_VOLUME_IMAGE', 0xc: 'COMBINED_MM_DXE', 0xd: 'MM_CORE', 0xe: 'MM_STANDALONE', 0xf: 'MM_CORE_STANDALONE', 0xf0: 'FFS_PAD' };
const SECTION_TYPES: Record<number, string> = { 1: 'COMPRESSION', 2: 'GUID_DEFINED', 3: 'DISPOSABLE', 0x10: 'PE32', 0x11: 'PIC', 0x12: 'TE', 0x13: 'DXE_DEPEX', 0x14: 'VERSION', 0x15: 'USER_INTERFACE', 0x16: 'COMPATIBILITY16', 0x17: 'FIRMWARE_VOLUME_IMAGE', 0x18: 'FREEFORM_SUBTYPE_GUID', 0x19: 'RAW', 0x1b: 'PEI_DEPEX', 0x1c: 'MM_DEPEX' };
const KNOWN_GUIDS: Record<string, string> = {
  '8C8CE578-8A3D-4F1C-9935-896185C32DD3': 'EFI_FIRMWARE_FILE_SYSTEM2_GUID', '5473C07A-3DCB-4DCA-BD6F-1E9689E7349A': 'EFI_FIRMWARE_FILE_SYSTEM3_GUID',
  '7A9354D9-0468-444A-81CE-0BF617D890DF': 'EFI_FIRMWARE_FILE_SYSTEM_GUID', 'FFF12B8D-7696-4C8B-A985-2747075B4F50': 'NVRAM (EFI_SYSTEM_NV_DATA_FV_GUID)',
  'EE4E5898-3914-4259-9D6E-DC7BD79403CF': 'LZMA_CUSTOM_DECOMPRESS_GUID', 'A31280AD-481E-41B6-95E8-127F4C984779': 'TIANO_CUSTOM_DECOMPRESS_GUID',
  'FC1BCDB0-7D31-49AA-936A-A4600D9DD083': 'EFI_CRC32_GUIDED_SECTION_EXTRACTION_GUID',
};
export interface UefiFile { guid: string; name?: string; type: string; size: number; offset: number; state: number; sections: { type: string; offset: number; size: number; guid?: string; text?: string }[] }
export interface UefiVolume { offset: number; length: number; fileSystem: string; fileSystemGuid: string; attributes: number; headerLength: number; checksumValid: boolean; files: UefiFile[]; nestedVolumes: number }

export function parseUefiVolume(b: Uint8Array, off: number, depth = 0, maxFiles = 5000): UefiVolume {
  const v = new View(b, true);
  if (latin1(v.sub(off + 40, 4)) !== '_FVH') throw new ParseError('not a firmware volume', off);
  const fsGuid = guid(b, off + 16);
  const length = v.u64n(off + 32);
  const attrs = v.u32(off + 44);
  const hlen = v.u16(off + 48);
  let sum = 0;
  for (let i = 0; i + 1 < hlen; i += 2) sum = (sum + v.u16(off + i)) & 0xffff;
  const vol: UefiVolume = { offset: off, length, fileSystem: KNOWN_GUIDS[fsGuid] ?? 'unknown', fileSystemGuid: fsGuid, attributes: attrs, headerLength: hlen, checksumValid: sum === 0, files: [], nestedVolumes: 0 };
  if (!/^EFI_FIRMWARE_FILE_SYSTEM/.test(vol.fileSystem)) return vol;
  const erase = attrs & 0x800 ? 0xff : 0;
  const end = Math.min(b.length, off + length);
  // files start right after the header; the extended header, when present, lives in the first pad file
  let p = (off + hlen + 7) & ~7;
  while (p + 24 <= end && vol.files.length < maxFiles) {
    if (b.subarray(p, p + 24).every((x) => x === erase)) break;
    const g = guid(b, p);
    const type = v.u8(p + 18), attr = v.u8(p + 19);
    let size = v.u8(p + 20) | (v.u8(p + 21) << 8) | (v.u8(p + 22) << 16);
    let hdr = 24;
    if (attr & 0x01 && size === 0) { size = v.u64n(p + 24); hdr = 32; }
    if (size < hdr || p + size > end) break;
    const file: UefiFile = { guid: g, type: FFS_TYPES[type] ?? `0x${type.toString(16)}`, size, offset: p, state: v.u8(p + 23), sections: [] };
    if (type !== 0xf0 && type !== 1) {
      let s = p + hdr;
      while (s + 4 <= p + size && file.sections.length < 64) {
        let ssize = v.u8(s) | (v.u8(s + 1) << 8) | (v.u8(s + 2) << 16);
        const stype = v.u8(s + 3);
        let shdr = 4;
        if (ssize === 0xffffff) { ssize = v.u32(s + 4); shdr = 8; }
        if (ssize < shdr || s + ssize > p + size) break;
        const sec: UefiFile['sections'][number] = { type: SECTION_TYPES[stype] ?? `0x${stype.toString(16)}`, offset: s, size: ssize };
        if (stype === 0x15) { sec.text = v.utf16z(s + shdr, 256); file.name = sec.text; }
        if (stype === 0x14) sec.text = v.utf16z(s + shdr + 2, 64);
        if (stype === 0x02) { sec.guid = guid(b, s + shdr); const n = KNOWN_GUIDS[sec.guid]; if (n) sec.text = n; }
        if (stype === 0x17 && depth < 4) {
          try { const nested = parseUefiVolume(b, s + shdr, depth + 1, maxFiles - vol.files.length); vol.nestedVolumes++; vol.files.push(...nested.files); } catch { /* not a volume */ }
        }
        file.sections.push(sec);
        s = (s + ssize + 3) & ~3;
      }
    }
    vol.files.push(file);
    p = (p + size + 7) & ~7;
  }
  return vol;
}

// ---------------- TRX ----------------
export function parseTrx(b: Uint8Array, off = 0): { length: number; crc: string; crcValid: boolean; version: number; flags: number; partitions: number[] } {
  const v = new View(b, true);
  if (latin1(v.sub(off, 4)) !== 'HDR0') throw new ParseError('not a TRX image', off);
  const len = v.u32(off + 4), crc = v.u32(off + 8), fv = v.u32(off + 12);
  const version = fv >>> 16;
  const parts: number[] = [];
  for (let i = 0; i < (version >= 2 ? 4 : 3); i++) parts.push(v.u32(off + 16 + i * 4));
  const end = Math.min(b.length, off + len);
  const computed = (~crc32(b, off + 12, end)) >>> 0;
  return { length: len, crc: crc.toString(16).padStart(8, '0'), crcValid: computed === crc, version, flags: fv & 0xffff, partitions: parts };
}

// ---------------- signature scan ----------------
export interface ScanHit { offset: number; type: string; description: string; size?: number; confidence: 'high' | 'medium' | 'low' }

/** Find embedded images at any offset (binwalk style), validating headers before reporting them. */
export function scanFirmware(b: Uint8Array, opts: { maxHits?: number; start?: number; end?: number } = {}): ScanHit[] {
  const hits: ScanHit[] = [];
  const max = opts.maxHits ?? 2000;
  const start = Math.max(0, opts.start ?? 0);
  const end = Math.min(b.length, opts.end ?? b.length);
  const v = new View(b, true);
  const be = new View(b, false);
  let skipUntil = -1;
  for (let i = start; i + 4 <= end && hits.length < max; i++) {
    if (i < skipUntil) continue;
    const c0 = b[i] as number, c1 = b[i + 1] as number, c2 = b[i + 2] as number, c3 = b[i + 3] as number;
    try {
      if (c0 === 0x27 && c1 === 0x05 && c2 === 0x19 && c3 === 0x56) {
        const u = parseUImage(b, i);
        if (u.headerCrcValid) hits.push({ offset: i, type: 'uimage', description: `uImage "${u.name}", ${u.os} ${u.arch} ${u.type}, ${u.compression}, ${u.size} bytes, load 0x${u.loadAddress.toString(16)}, data CRC ${u.dataCrcValid ? 'ok' : 'bad'}`, size: 64 + u.size, confidence: 'high' });
      } else if (c0 === 0xd0 && c1 === 0x0d && c2 === 0xfe && c3 === 0xed) {
        const total = be.u32(i + 4), ver = be.u32(i + 20);
        if (total >= 40 && total <= b.length - i && ver >= 16 && ver <= 17) { hits.push({ offset: i, type: 'fdt', description: `device tree blob v${ver}, ${total} bytes`, size: total, confidence: 'high' }); skipUntil = i + total; }
      } else if (c0 === 0x68 && c1 === 0x73 && c2 === 0x71 && c3 === 0x73) {
        const major = v.u16(i + 28), comp = v.u16(i + 20), used = v.has(i + 40, 8) ? v.u64n(i + 40) : 0;
        if (major === 4 && SQ_COMP[comp] && used > 96 && used <= b.length - i + 4096) { hits.push({ offset: i, type: 'squashfs', description: `squashfs 4.0, ${SQ_COMP[comp]}, ${v.u32(i + 4)} inodes, ${used} bytes`, size: used, confidence: 'high' }); skipUntil = i + used; }
      } else if (c0 === 0x30 && c1 === 0x37 && c2 === 0x30 && c3 === 0x37 && b[i + 4] === 0x30 && (b[i + 5] === 0x31 || b[i + 5] === 0x32 || b[i + 5] === 0x37)) {
        const r = parseCpio(b, i, 100000);
        if (r.entries.length) { hits.push({ offset: i, type: 'cpio', description: `cpio ${r.format} archive, ${r.entries.length} entries${r.trailer ? '' : ', no trailer'}`, size: r.end - i, confidence: 'high' }); skipUntil = r.end; }
      } else if (c0 === 0x1f && c1 === 0x8b && c2 === 0x08) {
        if ((c3 & 0xe0) === 0) hits.push({ offset: i, type: 'gzip', description: `gzip compressed data${c3 & 8 ? ', has original name' : ''}`, confidence: 'medium' });
      } else if (c0 === 0xfd && c1 === 0x37 && c2 === 0x7a && c3 === 0x58 && b[i + 4] === 0x5a && b[i + 5] === 0x00) {
        hits.push({ offset: i, type: 'xz', description: 'xz compressed data', confidence: 'high' });
      } else if (c0 === 0x28 && c1 === 0xb5 && c2 === 0x2f && c3 === 0xfd) {
        hits.push({ offset: i, type: 'zstd', description: 'zstd compressed data', confidence: 'medium' });
      } else if (c0 === 0x04 && c1 === 0x22 && c2 === 0x4d && c3 === 0x18) {
        hits.push({ offset: i, type: 'lz4', description: 'LZ4 frame', confidence: 'medium' });
      } else if (c0 === 0x42 && c1 === 0x5a && c2 === 0x68 && c3 >= 0x31 && c3 <= 0x39 && b[i + 4] === 0x31 && b[i + 5] === 0x41) {
        hits.push({ offset: i, type: 'bzip2', description: 'bzip2 compressed data', confidence: 'high' });
      } else if (c0 === 0x5d && c1 === 0x00 && c2 === 0x00 && [0x80, 0x00, 0x04, 0x10, 0x01, 0x02, 0x08].includes(c3)) {
        const dict = v.u32(i + 1);
        const usize = v.has(i + 5, 8) ? v.u64(i + 5) : 0n;
        if (dict >= 4096 && (dict & (dict - 1)) === 0 && (usize === 0xffffffffffffffffn || usize < 1n << 34n)) hits.push({ offset: i, type: 'lzma', description: `LZMA data, dictionary ${dict}`, confidence: 'low' });
      } else if (c0 === 0x7f && c1 === 0x45 && c2 === 0x4c && c3 === 0x46 && (b[i + 4] === 1 || b[i + 4] === 2) && (b[i + 5] === 1 || b[i + 5] === 2) && b[i + 6] === 1) {
        hits.push({ offset: i, type: 'elf', description: `ELF ${b[i + 4] === 2 ? '64' : '32'}-bit ${b[i + 5] === 1 ? 'LSB' : 'MSB'}`, confidence: 'high' });
      } else if (c0 === 0x50 && c1 === 0x4b && c2 === 0x03 && c3 === 0x04) {
        hits.push({ offset: i, type: 'zip', description: 'ZIP local file header', confidence: 'medium' });
      } else if (c0 === 0x37 && c1 === 0x7a && c2 === 0xbc && c3 === 0xaf && b[i + 4] === 0x27 && b[i + 5] === 0x1c) {
        hits.push({ offset: i, type: '7z', description: '7-Zip archive', confidence: 'high' });
      } else if (c0 === 0x55 && c1 === 0x42 && c2 === 0x49 && c3 === 0x23) {
        hits.push({ offset: i, type: 'ubi', description: 'UBI erase counter header', confidence: 'high' });
      } else if (c0 === 0x85 && c1 === 0x19 && [1, 2, 3, 4, 6].includes(c2)) {
        hits.push({ offset: i, type: 'jffs2', description: 'JFFS2 node (little endian)', confidence: 'low' });
      } else if (c0 === 0x45 && c1 === 0x3d && c2 === 0xcd && c3 === 0x28) {
        hits.push({ offset: i, type: 'cramfs', description: 'CramFS', confidence: 'high' });
      } else if (c0 === 0x3a && c1 === 0xff && c2 === 0x26 && c3 === 0xed) {
        hits.push({ offset: i, type: 'android-sparse', description: 'Android sparse image', confidence: 'high' });
      } else if (c0 === 0x41 && c1 === 0x4e && c2 === 0x44 && c3 === 0x52 && latin1(b.subarray(i, i + 8)) === 'ANDROID!') {
        hits.push({ offset: i, type: 'android-boot', description: 'Android boot image', confidence: 'high' });
      } else if (c0 === 0x5f && c1 === 0x46 && c2 === 0x56 && c3 === 0x48 && i >= 40) {
        const fv = parseUefiVolume(b, i - 40, 0, 1);
        hits.push({ offset: i - 40, type: 'uefi-fv', description: `UEFI firmware volume, ${fv.fileSystem}, ${fv.length} bytes, header checksum ${fv.checksumValid ? 'ok' : 'bad'}`, size: fv.length, confidence: 'high' });
      } else if (c0 === 0x48 && c1 === 0x44 && c2 === 0x52 && c3 === 0x30) {
        const t = parseTrx(b, i);
        if (t.length > 28 && t.length <= b.length - i) hits.push({ offset: i, type: 'trx', description: `TRX v${t.version}, ${t.length} bytes, CRC ${t.crcValid ? 'ok' : 'bad'}`, size: t.length, confidence: t.crcValid ? 'high' : 'low' });
      } else if (c0 === 0x2d && c1 === 0x2d && c2 === 0x2d && c3 === 0x2d && latin1(b.subarray(i, i + 11)) === '-----BEGIN ') {
        const label = latin1(b.subarray(i + 11, Math.min(end, i + 60))).split('-----')[0] ?? '';
        hits.push({ offset: i, type: 'pem', description: `PEM ${label}`, confidence: 'high' });
      } else if (c0 === 0x24 && c1 === 0x46 && c2 === 0x50 && c3 === 0x54) {
        hits.push({ offset: i, type: 'intel-me-fpt', description: 'Intel ME flash partition table ($FPT)', confidence: 'medium' });
      } else if (c0 === 0x55 && c1 === 0x46 && c2 === 0x32 && c3 === 0x0a && v.has(i + 4, 4) && v.u32(i + 4) === 0x9e5d5157) {
        let n = 0;
        while (v.has(i + n * 512 + 8, 0) && i + n * 512 + 8 <= b.length && v.u32(i + n * 512) === 0x0a324655 && v.u32(i + n * 512 + 4) === 0x9e5d5157 && n < 1_000_000) n++;
        hits.push({ offset: i, type: 'uf2', description: `UF2 image, ${n} blocks`, size: n * 512, confidence: 'high' });
        skipUntil = i + n * 512;
      }
    } catch { /* header did not validate */ }
  }
  for (let i = start; i + 1082 <= end && hits.length < max; i += 512) {
    if (v.u16(i + 1080) === 0xef53 && v.u32(i + 1024 + 24) <= 6 && v.u32(i + 1024) > 0) hits.push({ offset: i, type: 'ext', description: `ext2/3/4 filesystem, ${v.u32(i + 1024)} inodes`, confidence: 'medium' });
  }
  return hits.sort((a, c) => a.offset - c.offset);
}
