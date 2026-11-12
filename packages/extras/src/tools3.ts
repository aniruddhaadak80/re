// Agent tools added in round 3 for formats: RF and logic recordings, compressed streams,
// squashfs images, recursive firmware extraction, game packages and ROM headers, and app graphs.
// Browser safe. Writing extracted files to disk goes through a writer that the Node entry installs.

import { sha256 } from '@revlens/core';
import { inputBytes, page, ParseError, PATH_INPUT, toHex, type ToolDef, type InputSpec } from './util.js';
import { decodeSignalRecording, inspectSignalDecoders } from './signals/index.js';
import { readSigrokSession, decodeLogic } from './signals/logic.js';
import { isZip, zipEntries } from './compress/zip.js';
import { decompressAuto, COMPRESSION_FORMATS } from './compress/auto.js';
import { extractSquashfs } from './firmware/squashfs.js';
import { extractFirmware, extractionSummary, type ExtractResult } from './firmware/extract.js';
import { inspectGodotPck, godotPckFile } from './containers/godot.js';
import { parseInes } from './containers/nes.js';

const P = PATH_INPUT;
const LIMIT: Record<string, InputSpec> = {
  offset: { type: 'number', description: 'Index of the first item to return (paging)', optional: true },
  limit: { type: 'number', description: 'Maximum items to return, default 200', optional: true },
};
const num = (x: unknown, d: number): number => (typeof x === 'number' && Number.isFinite(x) ? x : typeof x === 'string' && x.trim() !== '' && Number.isFinite(Number(x)) ? Number(x) : d);

/** Writes an extraction to a directory. Installed by the Node entry; absent in browsers. */
export type ExtractionWriter = (r: ExtractResult, outDir: string, opts: { symlinks?: 'skip' | 'inside'; overwrite?: boolean }) => Promise<{ outDir: string; written: number; bytes: number; skipped: { path: string; reason: string }[]; manifest: string }>;
let writer: ExtractionWriter | undefined;
export function setExtractionWriter(w: ExtractionWriter): void { writer = w; }

const isSigrok = (b: Uint8Array): boolean => { try { return zipEntries(b, { maxEntries: 100000 }).some((e) => e.name === 'metadata'); } catch { return false; } };

export const FORMAT_R3_TOOLS: ToolDef[] = [
  {
    name: 'x_signal_decoders',
    description: 'Catalog of the signal recording decoders: readable containers and sample formats (raw IQ, WAV, SigMF, sigrok .sr), modulations, rtl_433 style flex spec keys and logic decoders (UART, I2C, SPI).',
    inputSchema: {},
    async run() { return inspectSignalDecoders(); },
  },
  {
    name: 'x_signal_decode',
    description: 'Decode an RF recording (raw IQ such as .cu8/.cs16/.cf32, WAV, SigMF) into facts, a spectrum summary, OOK/FSK pulse packages, an automatic coding guess and bit rows from rtl_433 style flex specs. A sigrok .sr session is decoded with a logic decoder (uart, i2c, spi) instead. Offsets are sample indexes.',
    inputSchema: {
      ...P,
      dataPath: { type: 'string', description: 'SigMF .sigmf-data file when path is a .sigmf-meta', optional: true },
      name: { type: 'string', description: 'File name used for hints such as g001_433.92M_250k.cu8 (defaults to path)', optional: true },
      format: { type: 'string', description: 'Raw sample format: cu8, cs8, cs16, cu16, cs32, cf32, cf64, ru8, rs8, rs16, rf32', optional: true },
      sampleRate: { type: 'number', description: 'Sample rate in Hz for raw files', optional: true },
      centerFreq: { type: 'number', description: 'Center frequency in Hz', optional: true },
      flex: { type: 'array', description: 'Flex specs, for example n=remote,m=OOK_PWM,s=400,l=1200,r=10000', optional: true },
      spectrum: { type: 'boolean', description: 'Include the spectrum summary (default true)', optional: true },
      analyze: { type: 'boolean', description: 'Include the automatic coding guess (default true)', optional: true },
      pulseDetail: { type: 'number', description: 'Pulse and gap widths to list per package (0 to 2000)', optional: true },
      decoder: { type: 'string', description: 'Logic decoder for .sr sessions: uart, i2c or spi', optional: true },
      options: { type: 'object', description: 'Logic decoder options in sigrok names, for example {"rx":"D0","baudrate":115200} or {"scl":"1","sda":"2"}', optional: true },
      ...LIMIT,
    },
    async run(i) {
      const b = await inputBytes(i);
      const name = i.name ?? i.path;
      if (isZip(b) && isSigrok(b)) {
        const cap = readSigrokSession(b);
        const facts = { sampleRate: cap.sampleRate, samples: cap.samples, channels: cap.channels, unitSize: cap.unitSize };
        if (!i.decoder) return { kind: 'logic', capture: facts, hint: 'pass decoder (uart, i2c, spi) and options' };
        const ann = decodeLogic(cap, String(i.decoder), (i.options ?? {}) as Record<string, string | number | boolean>);
        return { kind: 'logic', capture: facts, decoder: i.decoder, annotations: page(ann, num(i.offset, 0), num(i.limit, 500)) };
      }
      const data = i.dataPath ? await inputBytes({ path: i.dataPath }) : undefined;
      const flex = i.flex === undefined ? undefined : Array.isArray(i.flex) ? i.flex.map(String) : String(i.flex);
      const r = decodeSignalRecording(b, { name, data, format: i.format, sampleRate: i.sampleRate, centerFreq: i.centerFreq, flex, spectrum: i.spectrum, analyze: i.analyze, pulseDetail: i.pulseDetail });
      return { kind: 'rf', ...r };
    },
  },
  {
    name: 'x_decompress',
    description: `Decode one compressed stream with pure TypeScript decoders: ${COMPRESSION_FORMATS.join(', ')}. The format is detected from magic bytes unless given. Returns the format, where the stream ends in the input, the output size and SHA-256, checks (CRC, Adler-32, xz block checks) and a hex preview. Pass returnBase64 to get the output bytes.`,
    inputSchema: {
      ...P,
      format: { type: 'string', description: `auto (default) or one of ${COMPRESSION_FORMATS.join(', ')}`, optional: true },
      start: { type: 'number', description: 'Input offset of the stream (default 0)', optional: true },
      size: { type: 'number', description: 'Decoded size, needed for lz4-block and helpful for lzo1x', optional: true },
      dictSize: { type: 'number', description: 'Dictionary size for raw lzma2', optional: true },
      maxOut: { type: 'number', description: 'Output cap in bytes (default 64 MiB, max 1 GiB)', optional: true },
      preview: { type: 'number', description: 'Bytes of hex preview (default 64, max 4096)', optional: true },
      returnBase64: { type: 'boolean', description: 'Include the output as base64 (refused above 8 MiB)', optional: true },
    },
    async run(i) {
      const b = await inputBytes(i);
      const r = decompressAuto(b, { format: i.format, start: num(i.start, 0), maxOut: num(i.maxOut, 64 << 20), ...(i.size !== undefined ? { size: num(i.size, 0) } : {}), ...(i.dictSize !== undefined ? { dictSize: num(i.dictSize, 1 << 26) } : {}) });
      const pv = Math.max(0, Math.min(4096, num(i.preview, 64)));
      const out: Record<string, unknown> = { format: r.format, inputStart: num(i.start, 0), inputEnd: r.inputEnd, outputSize: r.data.length, sha256: sha256(r.data), details: r.details, previewHex: toHex(r.data.subarray(0, pv)) };
      if (i.returnBase64) {
        if (r.data.length > 8 << 20) throw new ParseError('output is larger than 8 MiB; use the Node CLI or a smaller maxOut');
        let s = '';
        for (let k = 0; k < r.data.length; k += 0x8000) s += String.fromCharCode(...r.data.subarray(k, k + 0x8000));
        out.base64 = btoa(s);
      }
      return out;
    },
  },
  {
    name: 'x_squashfs',
    description: 'List a squashfs 4.0 image (gzip, lzma, lzo, xz with BCJ filters, lz4, zstd; fragments and sparse files) like unsquashfs -lln, with the SHA-256 of every regular file. With file: that file\'s size, hash and a hex preview.',
    inputSchema: { ...P, at: { type: 'number', description: 'Offset of the superblock in the input (default 0)', optional: true }, file: { type: 'string', description: 'Path inside the image to read', optional: true }, preview: { type: 'number', description: 'Hex preview bytes for file (default 256)', optional: true }, hashes: { type: 'boolean', description: 'Hash every file (default true)', optional: true }, ...LIMIT },
    async run(i) {
      const b = await inputBytes(i);
      const withData = i.hashes !== false || !!i.file;
      const r = extractSquashfs(b, num(i.at, 0), { withData, deadline: Date.now() + 60000 });
      if (i.file) {
        const want = String(i.file).replace(/^\/+/, '');
        const e = r.entries.find((x) => x.path.replace(/^\/+/, '') === want);
        if (!e) throw new ParseError(`no ${i.file} in the image`);
        const { data, ...rest } = e;
        return { ...rest, ...(data ? { sha256: sha256(data), previewHex: toHex(data.subarray(0, Math.max(0, Math.min(65536, num(i.preview, 256))))) } : {}) };
      }
      const rows = r.entries.map(({ data, ...e }) => ({ ...e, ...(data ? { sha256: sha256(data) } : {}) }));
      return { super: { ...r.super, rootInode: r.super.rootInode.toString() }, truncated: r.truncated, totalBytes: r.totalBytes, errors: r.errors.slice(0, 50), entries: page(rows, num(i.offset, 0), num(i.limit, 500)) };
    },
  },
  {
    name: 'x_firmware_extract',
    description: 'Recursively carve and unpack a firmware image (binwalk -Me style, pure TypeScript): gzip, xz, lzma, bzip2, zstd, lz4, lzop, zip, cpio, tar, squashfs, uImage, FIT, TRX, Android boot and vendor_boot, UEFI volumes (FFS files, LZMA and EFI/Tiano sections), ELF. Returns chunks with offsets, the file tree with SHA-256 and the unknown gaps. With outDir (Node only) the files are written there safely: names cannot leave outDir, symlinks are listed, not created, unless symlinks=inside.',
    inputSchema: {
      ...P,
      outDir: { type: 'string', description: 'Directory to write the extracted tree to (Node only, must be empty or new)', optional: true },
      symlinks: { type: 'string', description: 'skip (default, list them in manifest.json) or inside (create only links whose target stays inside outDir)', optional: true },
      maxDepth: { type: 'number', description: 'Recursion depth (default 6, max 16)', optional: true },
      maxFiles: { type: 'number', description: 'File count limit (default 20000)', optional: true },
      maxTotalBytes: { type: 'number', description: 'Total output limit (default 512 MiB)', optional: true },
      maxFileSize: { type: 'number', description: 'Per file limit (default 128 MiB)', optional: true },
      timeBudgetMs: { type: 'number', description: 'Time limit (default 60000)', optional: true },
      carveUnknown: { type: 'boolean', description: 'Also emit unrecognised gaps as files', optional: true },
      skip: { type: 'array', description: 'Format names not to unpack, for example ["elf","zip"]', optional: true },
      ...LIMIT,
    },
    async run(i) {
      const b = await inputBytes(i);
      const r = extractFirmware(b, { maxDepth: i.maxDepth, maxFiles: i.maxFiles, maxTotalBytes: i.maxTotalBytes, maxFileSize: i.maxFileSize, timeBudgetMs: i.timeBudgetMs, carveUnknown: i.carveUnknown, skip: Array.isArray(i.skip) ? i.skip.map(String) : undefined, keepData: !!i.outDir });
      let written: Awaited<ReturnType<ExtractionWriter>> | undefined;
      if (i.outDir) {
        if (!writer) throw new ParseError('outDir needs the Node entry (@revlens/extras/node)');
        written = await writer(r, String(i.outDir), { symlinks: i.symlinks === 'inside' ? 'inside' : 'skip' });
      }
      const s = extractionSummary(r);
      return { chunks: page(s.chunks, 0, 2000), files: page(s.files, num(i.offset, 0), num(i.limit, 500)), unknown: s.unknown.slice(0, 500), warnings: s.warnings.slice(0, 100), truncated: s.truncated, stats: s.stats, ...(written ? { written } : {}) };
    },
  },
  {
    name: 'x_godot_pck',
    description: 'Godot engine resource pack (.pck v0 to v3, Godot 3 and 4), standalone or embedded at the end of an exported game executable: engine version, flags (encrypted directory, relative file base), file table with offsets, sizes, MD5 and per-file encryption. With file: that entry\'s bytes as a hex preview and SHA-256 (unencrypted entries only).',
    inputSchema: { ...P, file: { type: 'string', description: 'res:// path or plain path of one entry to read', optional: true }, preview: { type: 'number', description: 'Hex preview bytes for file (default 256)', optional: true }, ...LIMIT },
    async run(i) {
      const b = await inputBytes(i);
      const p = inspectGodotPck(b);
      if (i.file) {
        const f = godotPckFile(b, p, String(i.file));
        return { entry: f.entry, sha256: sha256(f.data), previewHex: toHex(f.data.subarray(0, Math.max(0, Math.min(65536, num(i.preview, 256))))), md5Matches: f.md5Matches };
      }
      return { ...p, files: page(p.files, num(i.offset, 0), num(i.limit, 500)) };
    },
  },
  {
    name: 'x_nes_rom',
    description: 'iNES and NES 2.0 ROM header: format, mapper and submapper, PRG and CHR ROM sizes, PRG/CHR RAM and NVRAM sizes, mirroring, battery, trainer, console and timing, with CRC32 and SHA-1 of the PRG and CHR data for database lookups.',
    inputSchema: { ...P },
    async run(i) { return parseInes(await inputBytes(i)); },
  },
];
