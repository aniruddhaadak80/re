// Agent tools for @revlens/extras. Every tool takes a file `path` (or base64 `bytes`),
// returns JSON with offsets and addresses an agent can cite, and pages large lists.

import { inputBytes, page, utf8, ParseError, PATH_INPUT, type ToolDef, type InputSpec } from './util.js';
import { demangle } from './demangle/index.js';
import { parseBin, machoSlices, elfSymbols } from './bin/container.js';
import { readBytes, searchBytes, addressMap } from './bin/bytes.js';
import { checksec } from './bin/checksec.js';
import { goSymbols } from './go/pclntab.js';
import { rustInfo } from './rust/rust.js';
import { inspectPe, peExports, peResources, peAuthenticode, peVersionInfo, peManifest, peStringTable, richHeader, detectInstaller } from './pe/pe.js';
import { elfNotes, elfInitializers, kernelModule, kernelConfig, elfDynamic } from './elf/elfx.js';
import { elfUnwind } from './elf/unwind.js';
import { machoInfo, resolveDylibs, machoCodeSignature, machoSymbols } from './macho/machox.js';
import { scanFirmware, parseUImage, parseFdt, parseIntelHex, parseSrec, parseUf2, parseDfu, parseEspImage, parseBootImage, parseSquashfs, parseCpio, parseUefiVolume, parseTrx } from './firmware/firmware.js';
import { inspectJsEngine } from './v8/v8.js';
import { inspectGpu } from './gpu/gpu.js';
import { inspectModel } from './model/model.js';
import { parseLnk } from './windows/lnk.js';
import { parseIps } from './apple/ips.js';
import { Ledger, evidenceFor, type EvidenceRef } from './ledger/ledger.js';
import { EVAL_TASKS, scoreAnswers, publicTasks } from './eval/harness.js';
import { sha256 } from '@revlens/core';
import { GAP_TOOLS } from './tools2.js';

/** Make any value JSON safe: bigint to string, bytes to capped hex, Map and Set to plain values. */
export function jsonSafe(x: unknown, depth = 0): unknown {
  if (depth > 40) return '[depth limit]';
  if (typeof x === 'bigint') return x <= BigInt(Number.MAX_SAFE_INTEGER) && x >= -BigInt(Number.MAX_SAFE_INTEGER) ? Number(x) : x.toString();
  if (x instanceof Uint8Array) { let s = ''; for (const c of x.subarray(0, 64)) s += c.toString(16).padStart(2, '0'); return { hex: s, length: x.length }; }
  if (x instanceof Map) return Object.fromEntries([...x.entries()].map(([k, v]) => [String(k), jsonSafe(v, depth + 1)]));
  if (x instanceof Set) return [...x].map((v) => jsonSafe(v, depth + 1));
  if (Array.isArray(x)) return x.map((v) => jsonSafe(v, depth + 1));
  if (x && typeof x === 'object') {
    if ('view' in x && 'sections' in x && 'segments' in x) { const { view: _v, ...rest } = x as Record<string, unknown>; return jsonSafe(rest, depth + 1); }
    const o: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(x)) if (v !== undefined && typeof v !== 'function') o[k] = jsonSafe(v, depth + 1);
    return o;
  }
  return x;
}

const P = PATH_INPUT;
const LIMIT: Record<string, InputSpec> = {
  offset: { type: 'number', description: 'Index of the first item to return (paging)', optional: true },
  limit: { type: 'number', description: 'Maximum items to return, default 200', optional: true },
};
const num = (x: unknown, d: number): number => (typeof x === 'number' && Number.isFinite(x) ? x : typeof x === 'string' && x.trim() !== '' && Number.isFinite(Number(x)) ? Number(x) : d);
const parseNum = (x: unknown): number | undefined => (typeof x === 'number' ? x : typeof x === 'string' && x ? (x.startsWith('0x') ? parseInt(x, 16) : Number(x)) : undefined);

// ---------------- ledger state ----------------
let memLedger = new Ledger();
type LedgerStore = { load(path: string): Promise<string | undefined>; save(path: string, text: string): Promise<void> };
let store: LedgerStore | undefined;
/** Node entry installs file persistence for `ledgerPath`. */
export function setLedgerStore(s: LedgerStore): void { store = s; }
/** Reset the in-memory ledger (tests, new investigations). */
export function resetLedger(): void { memLedger = new Ledger(); }
async function withLedger<T>(input: { ledgerPath?: string }, f: (l: Ledger) => Promise<T> | T, write: boolean): Promise<T> {
  if (!input.ledgerPath) return f(memLedger);
  if (!store) throw new ParseError('ledgerPath needs the Node entry (@revlens/extras/node); in a browser use the in-memory ledger');
  const text = await store.load(input.ledgerPath);
  const l = text ? Ledger.import(text) : new Ledger();
  const r = await f(l);
  if (write) await store.save(input.ledgerPath, JSON.stringify(l.export(), null, 1));
  return r;
}

const LEDGER_PATH: Record<string, InputSpec> = { ledgerPath: { type: 'string', description: 'Ledger JSON file to load and save (Node only). Omit to use the session ledger in memory.', optional: true } };

export const TOOLS: ToolDef[] = [
  {
    name: 'x_demangle',
    description: 'Demangle C++ (Itanium), Rust (legacy and v0), MSVC and Swift (old _T and new $s/$S/_T0 mangling) symbols. Pass symbols, or a binary path to demangle its symbol table.',
    inputSchema: { symbols: { type: 'array', description: 'Mangled names', optional: true }, ...P, filter: { type: 'string', description: 'Keep demangled names containing this text', optional: true }, ...LIMIT },
    async run(i) {
      if (Array.isArray(i.symbols) || typeof i.symbols === 'string') {
        const list: string[] = (Array.isArray(i.symbols) ? i.symbols : [i.symbols]).map(String).slice(0, 10000);
        return { items: list.map((s) => demangle(s)) };
      }
      const b = await inputBytes(i);
      const img = parseBin(b);
      let names: { name: string; value: number }[] = [];
      if (img.format === 'elf') names = [...elfSymbols(img, 'symtab'), ...elfSymbols(img, 'dynsym')];
      else if (img.format === 'macho') names = machoSymbols(b).map((s) => ({ name: s.name.startsWith('__Z') || s.name.startsWith('__R') || s.name.startsWith('__T') ? s.name.slice(1) : s.name, value: s.value }));
      else { names = (peExports(b)?.functions ?? []).filter((f) => f.name).map((f) => ({ name: f.name as string, value: f.rva })); }
      const seen = new Set<string>();
      const rows: { mangled: string; demangled: string; scheme: string; address: string }[] = [];
      for (const s of names) {
        if (seen.has(s.name)) continue;
        seen.add(s.name);
        const d = demangle(s.name);
        if (!d.output) continue;
        if (i.filter && !d.output.includes(String(i.filter))) continue;
        rows.push({ mangled: s.name, demangled: d.output, scheme: d.scheme, address: '0x' + s.value.toString(16) });
      }
      return page(rows, num(i.offset, 0), num(i.limit, 200));
    },
  },
  {
    name: 'x_container',
    description: 'Unified container view of ELF, PE or Mach-O (fat slices too): machine, entry, sections and segments with file offsets and addresses.',
    inputSchema: { ...P, arch: { type: 'string', description: 'Mach-O fat slice to pick, for example arm64 or x86-64', optional: true } },
    async run(i) {
      const b = await inputBytes(i);
      const img = parseBin(b, i.arch ? { arch: String(i.arch) } : {});
      const slices = img.format === 'macho' ? machoSlices(b) : [];
      return jsonSafe({ format: img.format, machine: img.machine, bits: img.bits, endian: img.le ? 'little' : 'big', imageBase: '0x' + img.imageBase.toString(16), entry: '0x' + img.entry.toString(16), sliceOffset: img.sliceOffset, slices, sections: img.sections.map((s) => ({ ...s, vaddr: '0x' + s.vaddr.toString(16) })), segments: img.segments.map((s) => ({ ...s, vaddr: '0x' + s.vaddr.toString(16) })) });
    },
  },
  {
    name: 'x_read_bytes',
    description: 'Read up to 64 KiB of raw bytes at a file offset or at a virtual address, as hex and printable text.',
    inputSchema: { ...P, at: { type: 'number', description: 'File offset', optional: true }, va: { type: 'string', description: 'Virtual address (hex like 0x401000) instead of a file offset', optional: true }, length: { type: 'number', description: 'Bytes to read, default 256', optional: true } },
    async run(i) {
      const b = await inputBytes(i);
      let off = parseNum(i.at) ?? 0;
      if (i.va !== undefined) { const m = addressMap(b, { va: i.va }); if (m.offset === undefined) throw new ParseError(`address ${i.va} is not backed by file bytes`); off = m.offset; }
      return readBytes(b, off, num(i.length, 256));
    },
  },
  {
    name: 'x_search_bytes',
    description: 'Search a file for a hex pattern with ?? wildcards (for example "48 8b ?? 24") or a text string (ASCII and UTF-16LE). Hits include offset, address and section.',
    inputSchema: { ...P, hex: { type: 'string', description: 'Hex pattern, ?? is any byte', optional: true }, text: { type: 'string', description: 'Text to find', optional: true }, start: { type: 'number', description: 'Start offset', optional: true }, limit: { type: 'number', description: 'Maximum hits, default 100', optional: true } },
    async run(i) { const b = await inputBytes(i); return searchBytes(b, { hex: i.hex, text: i.text }, { start: num(i.start, 0), limit: num(i.limit, 100) }); },
  },
  {
    name: 'x_address_map',
    description: 'Convert a virtual address to a file offset, or a file offset to a virtual address, with the section and segment it falls in.',
    inputSchema: { ...P, va: { type: 'string', description: 'Virtual address, hex or decimal', optional: true }, at: { type: 'number', description: 'File offset', optional: true }, arch: { type: 'string', description: 'Mach-O fat slice', optional: true } },
    async run(i) { const b = await inputBytes(i); return addressMap(b, i.va !== undefined ? { va: i.va } : { offset: parseNum(i.at) }, i.arch); },
  },
  {
    name: 'x_checksec',
    description: 'Hardening checks for ELF, PE and Mach-O: RELRO, NX, PIE, canary, FORTIFY, CET, BTI and PAC, ASLR, CFG, SafeSEH, code signing, with byte evidence and a score.',
    inputSchema: { ...P },
    async run(i) { return checksec(await inputBytes(i)); },
  },
  {
    name: 'x_go_symbols',
    description: 'Recover Go function names, source files and packages from pclntab, also on stripped binaries (Go 1.2 to 1.24).',
    inputSchema: { ...P, filter: { type: 'string', description: 'Keep functions whose name contains this text', optional: true }, ...LIMIT },
    async run(i) {
      const g = goSymbols(await inputBytes(i));
      if (!g) return { found: false };
      const fns = i.filter ? g.functions.filter((f) => f.name.includes(String(i.filter))) : g.functions;
      return jsonSafe({ found: true, version: g.version, goVersionRange: g.goVersionRange, offset: g.offset, source: g.source, functionCount: g.functionCount, fileCount: g.fileCount, packages: g.packages.slice(0, 300), warnings: g.warnings, functions: page(fns.map((f) => ({ ...f, entry: '0x' + f.entry.toString(16) })), num(i.offset, 0), num(i.limit, 200)) });
    },
  },
  {
    name: 'x_rust_info',
    description: 'Rust toolchain and crate evidence: rustc version and commit, crates with versions from registry paths, symbol schemes, panic strings.',
    inputSchema: { ...P },
    async run(i) { return rustInfo(await inputBytes(i)); },
  },
  {
    name: 'x_pe_inspect',
    description: 'Deep PE view: headers and checksum, rich header, resources, version info, manifest, debug and PDB path, TLS callbacks, load config, exports, delay imports, overlay, installer detection (NSIS, Inno, MSI, WiX, InstallShield, PyInstaller and more), Authenticode.',
    inputSchema: { ...P },
    async run(i) { return jsonSafe(await inspectPe(await inputBytes(i))); },
  },
  {
    name: 'x_pe_resources',
    description: 'PE resources with type, name, language, file offset, size and sniffed content type, plus version info, manifest and string tables.',
    inputSchema: { ...P, ...LIMIT },
    async run(i) {
      const b = await inputBytes(i);
      const safe = <T>(f: () => T): T | null => { try { return f(); } catch { return null; } };
      return jsonSafe({ resources: page(peResources(b, { limit: 50000 }), num(i.offset, 0), num(i.limit, 200)), versionInfo: safe(() => peVersionInfo(b)), manifest: safe(() => peManifest(b)), strings: safe(() => peStringTable(b, 2000)), richHeader: safe(() => richHeader(b)), installers: safe(() => detectInstaller(b)) });
    },
  },
  {
    name: 'x_pe_authenticode',
    description: 'Authenticode signatures of a PE: recomputes the image digest, compares it with the signed digest, verifies the signer signature, lists certificates, signing time and countersignature.',
    inputSchema: { ...P },
    async run(i) { const s = await peAuthenticode(await inputBytes(i)); return jsonSafe({ signed: s.length > 0, signatures: s }); },
  },
  {
    name: 'x_elf_inspect',
    description: 'ELF notes (build-id, ABI tag, GNU properties, Go and package notes), dynamic section (NEEDED, SONAME, RPATH, RUNPATH, flags) and init/fini array targets.',
    inputSchema: { ...P },
    async run(i) {
      const b = await inputBytes(i);
      const safe = <T>(f: () => T): T | { error: string } => { try { return f(); } catch (e) { return { error: (e as Error).message }; } };
      return jsonSafe({ notes: safe(() => elfNotes(b)), dynamic: safe(() => elfDynamic(parseBin(b))), initializers: safe(() => elfInitializers(b)) });
    },
  },
  {
    name: 'x_elf_unwind',
    description: 'Function ranges from .eh_frame_hdr and .eh_frame FDEs (start, end, size, FDE and CIE offsets). Useful function boundaries for stripped binaries.',
    inputSchema: { ...P, ...LIMIT },
    async run(i) { return elfUnwind(await inputBytes(i), { offset: num(i.offset, 0), limit: num(i.limit, 1000) }); },
  },
  {
    name: 'x_kernel_module',
    description: 'Linux kernel module (.ko) facts: modinfo, vermagic, dependencies, signature trailer, plus IKCONFIG kernel build config recovery from a kernel image.',
    inputSchema: { ...P, config: { type: 'boolean', description: 'Look for an embedded IKCONFIG build config instead', optional: true } },
    async run(i) {
      const b = await inputBytes(i);
      if (i.config) { const c = await kernelConfig(b); return c ? { found: true, offset: c.offset, options: c.options, selected: c.selected, text: c.text.slice(0, 20000) } : { found: false }; }
      return jsonSafe(kernelModule(b));
    },
  },
  {
    name: 'x_macho_inspect',
    description: 'Mach-O load commands, UUID, build version, dylibs with @rpath resolution, rpaths, encryption info and code signature (code directories, cdhash, entitlements, CMS signer, hardened runtime).',
    inputSchema: { ...P, arch: { type: 'string', description: 'Fat slice to pick', optional: true }, executablePath: { type: 'string', description: 'Install path used to expand @executable_path', optional: true } },
    async run(i) {
      const b = await inputBytes(i);
      const info = machoInfo(b, i.arch);
      const dylibs = resolveDylibs(info, { executablePath: i.executablePath });
      let sig: unknown = null;
      try { sig = machoCodeSignature(b, i.arch); } catch (e) { sig = { error: (e as Error).message }; }
      return jsonSafe({ ...info, dylibs, slices: machoSlices(b), codeSignature: sig });
    },
  },
  {
    name: 'x_firmware_scan',
    description: 'Find embedded images at any offset (binwalk style, headers validated): uImage, FIT/DTB, squashfs, cpio, UEFI volumes, TRX, UF2, Android boot and sparse, UBI, JFFS2, CramFS, ext, ELF, PEM, gzip, xz, zstd, lz4, lzma, bzip2, zip, 7z.',
    inputSchema: { ...P, start: { type: 'number', description: 'Start offset', optional: true }, end: { type: 'number', description: 'End offset', optional: true }, ...LIMIT },
    async run(i) { const b = await inputBytes(i); const hits = scanFirmware(b, { start: num(i.start, 0), end: i.end !== undefined ? num(i.end, b.length) : undefined, maxHits: 20000 }); return page(hits, num(i.offset, 0), num(i.limit, 200)); },
  },
  {
    name: 'x_firmware_parse',
    description: 'Parse one firmware structure at an offset: uimage, fdt (device tree or FIT), ihex, srec, uf2, dfu, esp, android-boot, squashfs (with file listing), cpio, uefi (firmware volume and files), trx.',
    inputSchema: { ...P, kind: { type: 'string', description: 'uimage | fdt | ihex | srec | uf2 | dfu | esp | android-boot | squashfs | cpio | uefi | trx' }, at: { type: 'number', description: 'Offset of the structure, default 0', optional: true }, ...LIMIT },
    async run(i) {
      const b = await inputBytes(i);
      const at = num(i.at, 0);
      const k = String(i.kind);
      const lim = (x: { entries?: unknown[] } & Record<string, unknown>, key: string) => { const arr = x[key] as unknown[] | undefined; return arr ? { ...x, [key]: page(arr, num(i.offset, 0), num(i.limit, 500)) } : x; };
      switch (k) {
        case 'uimage': return jsonSafe(parseUImage(b, at));
        case 'fdt': return jsonSafe(parseFdt(b, at, { maxNodes: 20000 }));
        case 'ihex': { const r = parseIntelHex(utf8(b)); const { data: _d, ...rest } = r; return jsonSafe(rest); }
        case 'srec': return jsonSafe(parseSrec(utf8(b)));
        case 'uf2': return jsonSafe(parseUf2(b));
        case 'dfu': return jsonSafe(parseDfu(b));
        case 'esp': return jsonSafe(parseEspImage(b, at));
        case 'android-boot': return jsonSafe(parseBootImage(b));
        case 'squashfs': return jsonSafe(lim(await parseSquashfs(b, at, { list: true, maxEntries: 100000 }) as unknown as Record<string, unknown>, 'entries'));
        case 'cpio': return jsonSafe(lim(parseCpio(b, at, 100000) as unknown as Record<string, unknown>, 'entries'));
        case 'uefi': return jsonSafe(parseUefiVolume(b, at));
        case 'trx': return jsonSafe(parseTrx(b, at));
        default: throw new ParseError(`unknown kind ${k}`);
      }
    },
  },
  {
    name: 'x_v8_inspect',
    description: 'JavaScript engine artifacts: V8 code cache and bytenode .jsc (magic, version hash, flag hash, source length, payload length), V8 startup snapshot blobs (version string), Hermes bytecode headers.',
    inputSchema: { ...P },
    async run(i) { const r = inspectJsEngine(await inputBytes(i)); return r ?? { found: false }; },
  },
  {
    name: 'x_gpu_inspect',
    description: 'GPU code objects: CUDA fatbin entries (PTX or cubin, sm_ target, compression), cubin kernels, PTX entries, AMD HSA code objects (gfx target, kernels), SPIR-V (version, capabilities, entry points), clang offload bundles in host binaries.',
    inputSchema: { ...P },
    async run(i) { const r = inspectGpu(await inputBytes(i)); return r ? jsonSafe(r) : { found: false }; },
  },
  {
    name: 'x_model_inspect',
    description: 'Model files: GGUF metadata and tensor table, safetensors header, NumPy .npy header. Checks tensor sizes against dtypes and file bounds.',
    inputSchema: { ...P, ...LIMIT },
    async run(i) {
      const r = inspectModel(await inputBytes(i), { maxTensors: 100000 });
      if (!r) return { found: false };
      if ('tensors' in r) return jsonSafe({ ...r, tensors: page(r.tensors as unknown[], num(i.offset, 0), num(i.limit, 200)) });
      return r;
    },
  },
  {
    name: 'x_lnk_inspect',
    description: 'Windows shortcut (.lnk): target path, arguments, working dir, icon, timestamps, volume serial and label, tracker machine id, extra data blocks.',
    inputSchema: { ...P },
    async run(i) { return parseLnk(await inputBytes(i)); },
  },
  {
    name: 'x_apple_ips',
    description: 'Apple .ips crash and diagnostic reports: process, OS, exception, termination reason, crashed thread frames joined to their images with absolute addresses.',
    inputSchema: { ...P, maxFrames: { type: 'number', description: 'Frames per thread, default 64', optional: true } },
    async run(i) { const r = parseIps(await inputBytes(i), { maxFrames: num(i.maxFrames, 64) }); return { ...r, threads: r.threads.slice(0, 16) }; },
  },
  {
    name: 'x_ledger_record',
    description: 'Record a claim about a file in the evidence ledger, bound to byte ranges by SHA-256. Optional check is a RevLens claim (contains-string, bytes-at, format-is, sha256-is) run on verify.',
    inputSchema: { ...P, statement: { type: 'string', description: 'What is claimed, in plain words' }, ranges: { type: 'array', description: 'Byte ranges as [{offset, length, note?}]', optional: true }, check: { type: 'object', description: 'Optional structured check, for example {"kind":"contains-string","value":"evil.com"}', optional: true }, links: { type: 'array', description: 'Ids of related claims or unknowns', optional: true }, author: { type: 'string', description: 'Who makes the claim', optional: true }, tool: { type: 'string', description: 'Tool that produced the fact', optional: true }, ...LEDGER_PATH },
    async run(i) {
      const b = await inputBytes(i);
      const fileSha = sha256(b);
      const ranges = Array.isArray(i.ranges) ? i.ranges as { offset: number; length: number; note?: string }[] : [];
      const evidence: EvidenceRef[] = ranges.slice(0, 64).map((r) => evidenceFor(b, num(r.offset, -1), num(r.length, -1), i.path, r.note, fileSha));
      if (!evidence.length && i.check) evidence.push(evidenceFor(b, 0, 0, i.path, 'whole file', fileSha));
      return withLedger(i, (l) => { const e = l.claim({ statement: String(i.statement ?? ''), evidence, check: i.check, links: i.links, author: i.author, tool: i.tool }); return { id: e.id, hash: e.hash, evidence }; }, true);
    },
  },
  {
    name: 'x_ledger_unknown',
    description: 'Record an open question (unknown) in the ledger, or resolve, reject or reopen a claim or unknown by id.',
    inputSchema: { statement: { type: 'string', description: 'The open question', optional: true }, id: { type: 'string', description: 'Existing id to update instead', optional: true }, status: { type: 'string', description: 'For updates: resolved | rejected | open | asserted', optional: true }, reason: { type: 'string', description: 'Why the status changed', optional: true }, links: { type: 'array', description: 'Related ids, for example the claim that resolves it', optional: true }, author: { type: 'string', description: 'Who records it', optional: true }, ...LEDGER_PATH },
    async run(i) {
      return withLedger(i, (l) => {
        if (i.id) { const st = String(i.status ?? 'resolved'); if (!['resolved', 'rejected', 'open', 'asserted'].includes(st)) throw new ParseError('status must be resolved, rejected, open or asserted'); const e = l.update(String(i.id), st as 'resolved', i.reason, i.links, i.author); return { id: e.id, target: e.target, status: e.status, hash: e.hash }; }
        const e = l.unknown({ statement: String(i.statement ?? ''), links: i.links, author: i.author });
        return { id: e.id, hash: e.hash };
      }, true);
    },
  },
  {
    name: 'x_ledger_verify',
    description: 'Re-read the files behind ledger claims and check every evidence hash and structured check. Claims become verified, refuted (bytes changed) or stale (file missing).',
    inputSchema: { ids: { type: 'array', description: 'Only these claim ids', optional: true }, files: { type: 'object', description: 'Optional map of evidence path to the path to read now (file moved)', optional: true }, ...LEDGER_PATH },
    async run(i) {
      const map = (i.files ?? {}) as Record<string, string>;
      return withLedger(i, async (l) => {
        const results = await l.verify(async (ref) => (ref.path ? inputBytes({ path: map[ref.path] ?? ref.path }) : undefined), { ids: i.ids });
        return { results, summary: l.summary() };
      }, true);
    },
  },
  {
    name: 'x_ledger_list',
    description: 'Current claims and unknowns with status, evidence and history, plus a summary (verified share, open unknowns, chain head).',
    inputSchema: { kind: { type: 'string', description: 'claim or unknown', optional: true }, status: { type: 'string', description: 'Filter by status', optional: true }, ...LIMIT, ...LEDGER_PATH },
    async run(i) { return withLedger(i, (l) => { let it = l.items(); if (i.kind) it = it.filter((x) => x.kind === i.kind); if (i.status) it = it.filter((x) => x.status === i.status); return { summary: l.summary(), items: page(it, num(i.offset, 0), num(i.limit, 200)) }; }, false); },
  },
  {
    name: 'x_ledger_export',
    description: 'Export the ledger as hash-chained JSON (revlens/ledger@1) or as a Markdown table for a report.',
    inputSchema: { format: { type: 'string', description: 'json (default) or markdown', optional: true }, ...LEDGER_PATH },
    async run(i) { return withLedger(i, (l) => (i.format === 'markdown' ? { markdown: l.toMarkdown() } : l.export()), false); },
  },
  {
    name: 'x_ledger_import',
    description: 'Import an exported ledger after checking its schema and hash chain. Replaces the session ledger, or writes ledgerPath.',
    inputSchema: { ledger: { type: 'object', description: 'The exported ledger JSON (or a JSON string)' }, ...LEDGER_PATH },
    async run(i) {
      const l = Ledger.import(i.ledger);
      if (i.ledgerPath) { if (!store) throw new ParseError('ledgerPath needs the Node entry'); await store.save(i.ledgerPath, JSON.stringify(l.export(), null, 1)); }
      else memLedger = l;
      return { imported: l.entries.length, summary: l.summary() };
    },
  },
  {
    name: 'x_eval_tasks',
    description: 'Reverse engineering eval tasks with hidden ground truth on the RevLens sample fixtures. Answer them with any tools, then score with x_eval_score.',
    inputSchema: { tag: { type: 'string', description: 'Only tasks with this tag', optional: true } },
    async run(i) { return { tasks: publicTasks(i.tag) }; },
  },
  {
    name: 'x_eval_score',
    description: 'Score answers to x_eval_tasks against ground truth verified with reference tools. Pass answers as {taskId: answer}.',
    inputSchema: { answers: { type: 'object', description: 'Map of task id to answer (string, number or list)' }, agent: { type: 'string', description: 'Label for the agent being scored', optional: true } },
    async run(i) { return scoreAnswers((i.answers ?? {}) as Record<string, unknown>, { agent: i.agent }); },
  },
  ...GAP_TOOLS,
];

export { EVAL_TASKS };
