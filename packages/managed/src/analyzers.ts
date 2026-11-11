// RevLens core Analyzer objects for managed and bytecode formats. Output goes to report.meta.managed.<area>.
import type { Analyzer, AnalyzerContext, Finding, Report } from '@revlens/core';
import { errMsg } from './util.js';
import { isPe } from './dotnet/pe.js';
import { hasCliHeader } from './dotnet/metadata.js';
import { loadAssembly, dotnetInfo, singleFileBundle } from './dotnet/assembly.js';
import { isPyc, parsePyc, walkCode, versionForMagic } from './python/pyc.js';
import { findCookie, parseCArchive, parsePyz, readCArchiveEntry, detectPythonPackers } from './python/pyinstaller.js';
import { isLuaBytecode, parseLua } from './lua/lua.js';
import { isBeam, parseBeam } from './beam/beam.js';
import { analyzeEvm, evmBytes } from './evm/evm.js';

function meta(report: Report): Record<string, unknown> {
  const m = (report.meta.managed ??= {}) as Record<string, unknown>;
  return m;
}
function finding(id: string, title: string, severity: Finding['severity'], detail: string, evidence: Finding['evidence'] = [], tags: string[] = [], attack?: string[]): Finding {
  return { id: `managed.${id}`, analyzer: id.split('.')[0] === 'dotnet' ? 'managed-dotnet' : `managed-${id.split('.')[0]}`, title, severity, detail, evidence, tags, ...(attack ? { attack } : {}) };
}

export const dotnetAnalyzer: Analyzer = {
  id: 'managed-dotnet',
  title: '.NET assembly',
  description: 'Reads ECMA-335 metadata: assembly identity, target framework, references, P/Invoke, resources, ReadyToRun, single-file bundles and obfuscator markers.',
  applies: (ctx) => (isPe(ctx.bytes) && hasCliHeader(ctx.bytes)) || ((ctx.format === 'elf' || ctx.format === 'macho' || ctx.format === 'pe') && (singleFileBundle(ctx.bytes)?.fileCount ?? 0) > 0),
  run(ctx) {
    const { report, bytes } = ctx;
    const out: Record<string, unknown> = {};
    const bundle = singleFileBundle(bytes);
    if (bundle && bundle.fileCount > 0) {
      out.singleFileBundle = { ...bundle, files: bundle.files.slice(0, 500) };
      report.findings.push(finding('dotnet.bundle', '.NET single-file bundle', 'info', `apphost carries ${bundle.fileCount} embedded files (bundle ${bundle.version}, id ${bundle.bundleId})`, [{ offset: bundle.headerOffset, snippet: 'bundle manifest' }], ['dotnet', 'bundle']));
    }
    if (hasCliHeader(bytes)) {
      const asm = loadAssembly(bytes);
      const info = dotnetInfo(asm, { maxAttributes: 200 });
      out.dotnet = { ...info, pinvoke: info.pinvoke.slice(0, 500), resources: info.resources.slice(0, 200) };
      report.file.arch = report.file.arch ?? info.machine;
      const libs = new Map<string, string[]>();
      for (const p of info.pinvoke) { const l = libs.get(p.library) ?? []; l.push(p.entry); libs.set(p.library, l); }
      for (const [library, symbols] of libs) report.imports.push({ library: `pinvoke:${library}`, symbols });
      for (const r of info.assemblyRefs) report.components.push({ name: r.name, version: r.version, ecosystem: 'unknown', confidence: 0.6, evidence: [{ snippet: `AssemblyRef ${r.name} ${r.version}` }] });
      report.findings.push(finding('dotnet.identity', `.NET assembly ${info.assembly?.name ?? info.module.name}`, 'info',
        `${info.assembly ? `${info.assembly.name} ${info.assembly.version}` : 'module'} for ${info.targetFramework ?? info.runtimeVersion}; ${info.counts.types} types, ${info.counts.methods} methods, ${info.assemblyRefs.length} assembly references`,
        [{ offset: info.metadata.offset, snippet: 'BSJB metadata root' }], ['dotnet']));
      for (const o of info.obfuscators) report.findings.push(finding('dotnet.obfuscator', `Obfuscator marker: ${o.name}`, 'medium', o.evidence, [{ snippet: o.evidence }], ['dotnet', 'obfuscation'], ['T1027']));
      if (info.pinvoke.length) report.findings.push(finding('dotnet.pinvoke', `${info.pinvoke.length} P/Invoke imports`, 'low', [...libs.keys()].slice(0, 10).join(', '), info.pinvoke.slice(0, 5).map((p) => ({ snippet: `${p.library}!${p.entry}` })), ['dotnet', 'native-interop']));
      if (info.readyToRun) report.findings.push(finding('dotnet.r2r', 'ReadyToRun (precompiled native code)', 'info', `R2R ${info.readyToRun.majorVersion}.${info.readyToRun.minorVersion} by ${info.readyToRun.compositeOrComponent ?? 'crossgen'}; IL is still present but native code runs first`, [], ['dotnet', 'r2r']));
      if (info.metadata.tableError) report.findings.push(finding('dotnet.tables', 'Metadata tables only partly readable', 'low', info.metadata.tableError, [], ['dotnet']));
    }
    meta(report).dotnet = out;
  },
};

export const pythonAnalyzer: Analyzer = {
  id: 'managed-python',
  title: 'Python bytecode and freezers',
  description: 'Parses .pyc headers and code objects, lists PyInstaller archives, and spots Nuitka, py2exe and cx_Freeze builds.',
  applies: (ctx) => ctx.format === 'pyc' || isPyc(ctx.bytes) || ((ctx.format === 'pe' || ctx.format === 'elf' || ctx.format === 'macho' || ctx.format === 'unknown') && ctx.bytes.length > 64),
  run(ctx) {
    const { report, bytes } = ctx;
    const out: Record<string, unknown> = {};
    if (isPyc(bytes)) {
      const magic = (bytes[0] as number) | ((bytes[1] as number) << 8);
      try {
        const p = parsePyc(bytes);
        const paths: string[] = [];
        walkCode(p.code, (_c, path) => { if (paths.length < 2000) paths.push(path); });
        out.pyc = { version: p.version, header: p.header, filename: p.code.filename, codeObjects: paths.length, paths: paths.slice(0, 500), names: p.code.names.slice(0, 200) };
        report.findings.push(finding('python.pyc', `Python ${p.version} bytecode`, 'info', `${p.code.filename}: ${paths.length} code objects`, [{ offset: 0, length: p.header.headerSize, snippet: `magic ${magic}` }], ['python']));
      } catch (e) { out.pyc = { version: versionForMagic(magic), error: errMsg(e) }; }
    }
    if (!isPyc(bytes)) {
      const packers = detectPythonPackers(bytes);
      if (packers.length) out.packers = packers;
      if (findCookie(bytes) >= 0) {
        try {
          const a = parseCArchive(bytes);
          const entry = a.entries.filter((e) => e.type === 's' && !e.name.startsWith('pyi')).map((e) => e.name);
          const pz = a.entries.find((e) => e.type === 'z');
          let modules: number | undefined;
          if (pz) { try { modules = parsePyz(readCArchiveEntry(bytes, pz), a.pythonVersion).entries.length; } catch { /* listed without PYZ */ } }
          out.pyinstaller = { cookieOffset: a.cookieOffset, pythonVersion: a.pythonVersion, pylibName: a.pylibName, entryPoints: entry, entries: a.entries.length, pyzModules: modules, toc: a.entries.slice(0, 300).map((e) => ({ name: e.name, type: e.type, offset: e.offset, size: e.size })) };
          report.findings.push(finding('python.pyinstaller', 'PyInstaller bundle', 'medium', `Python ${a.pythonVersion} app packed with PyInstaller; entry script(s): ${entry.join(', ') || 'unknown'}; ${a.entries.length} archive entries${modules !== undefined ? `, ${modules} PYZ modules` : ''}`, [{ offset: a.cookieOffset, length: 88, snippet: 'MEI cookie' }], ['python', 'packer'], ['T1027.002']));
        } catch (e) { out.pyinstaller = { error: errMsg(e) }; }
      } else {
        for (const p of packers) report.findings.push(finding('python.packer', `${p.packer} build marker`, 'low', p.evidence, [{ offset: p.offset, snippet: p.evidence }], ['python', 'packer']));
      }
    }
    if (Object.keys(out).length) meta(report).python = out;
  },
};

export const luaAnalyzer: Analyzer = {
  id: 'managed-lua',
  title: 'Lua bytecode',
  description: 'Lists Lua 5.1 to 5.4 and LuaJIT bytecode: header, functions, constants.',
  applies: (ctx) => isLuaBytecode(ctx.bytes),
  run(ctx) {
    const c = parseLua(ctx.bytes);
    const consts: string[] = [];
    const walk = (f: typeof c.main, d: number) => { if (d > 64) return; for (const k of f.constants) if (typeof k === 'string' && consts.length < 300) consts.push(k); f.children.forEach((x) => walk(x, d + 1)); };
    walk(c.main, 0);
    meta(ctx.report).lua = { flavor: c.flavor, version: c.version, header: c.header, stripped: c.stripped, functionCount: c.functionCount, mainInstructions: c.main.instructions.length, stringConstants: consts };
    ctx.report.findings.push(finding('lua.chunk', `${c.flavor === 'luajit' ? 'LuaJIT' : 'Lua'} ${c.version} bytecode`, 'info', `${c.functionCount} functions${c.stripped ? ', debug info stripped' : ''}`, [{ offset: 0, length: 4 }], ['lua']));
  },
};

export const beamAnalyzer: Analyzer = {
  id: 'managed-beam',
  title: 'Erlang BEAM',
  description: 'Lists BEAM chunks, atoms, exports and imports of Erlang and Elixir modules.',
  applies: (ctx) => isBeam(ctx.bytes),
  run(ctx) {
    const b = parseBeam(ctx.bytes);
    meta(ctx.report).beam = { module: b.module, elixir: b.elixir, chunks: b.chunks, exports: b.exports, imports: b.imports.slice(0, 1000), atomCount: b.atoms.length, code: b.code, compileInfo: b.compileInfo, hasDebugInfo: b.hasDebugInfo };
    ctx.report.exports.push(...b.exports.map((e) => `${e.name}/${e.arity}`));
    const byMod = new Map<string, string[]>();
    for (const i of b.imports) { const l = byMod.get(i.module) ?? []; l.push(`${i.name}/${i.arity}`); byMod.set(i.module, l); }
    for (const [library, symbols] of byMod) ctx.report.imports.push({ library, symbols });
    ctx.report.findings.push(finding('beam.module', `BEAM module ${b.module}`, 'info', `${b.exports.length} exports, ${b.imports.length} imports${b.hasDebugInfo ? ', carries debug info (source can be recovered)' : ''}`, [{ offset: 0, length: 12 }], ['erlang']));
  },
};

function looksLikeEvm(ctx: AnalyzerContext): boolean {
  const n = ctx.name.toLowerCase();
  if (/\.(evm|bytecode)$/.test(n)) return true;
  const head = ctx.bytes.subarray(0, 16);
  const text = String.fromCharCode(...head).trim().toLowerCase().replace(/^0x/, '');
  // Solidity runtime and creation code nearly always start with PUSH1 0x80 PUSH1 0x40 MSTORE.
  if ((ctx.format === 'text' || /\.(hex|bin)$/.test(n)) && /^6080604052/.test(text)) return true;
  return ctx.bytes.length > 5 && ctx.bytes[0] === 0x60 && ctx.bytes[1] === 0x80 && ctx.bytes[2] === 0x60 && ctx.bytes[3] === 0x40 && ctx.bytes[4] === 0x52;
}

export const evmAnalyzer: Analyzer = {
  id: 'managed-evm',
  title: 'EVM bytecode',
  description: 'Disassembles Ethereum bytecode, extracts function selectors, proxy patterns and Solidity metadata.',
  applies: looksLikeEvm,
  run(ctx) {
    const { instructions, opcodeStats, ...s } = analyzeEvm(evmBytes(ctx.bytes));
    void instructions;
    meta(ctx.report).evm = { ...s, opcodeStats };
    ctx.report.file.arch = 'evm';
    ctx.report.exports.push(...s.selectors.map((x) => x.signature ?? `0x${x.selector}`));
    ctx.report.findings.push(finding('evm.contract', 'EVM contract bytecode', 'info', `${s.codeSize} bytes of code, ${s.selectors.length} selectors${s.metadata?.solc ? `, solc ${s.metadata.solc}` : ''}`, [], ['evm']));
    for (const p of s.proxy) if (p.kind !== 'delegatecall' || s.proxy.length === 1) ctx.report.findings.push(finding('evm.proxy', `Proxy pattern: ${p.kind}`, 'low', p.evidence, [{ offset: p.pc, snippet: p.evidence }], ['evm', 'proxy']));
    if (s.flags.selfdestruct) ctx.report.findings.push(finding('evm.selfdestruct', 'SELFDESTRUCT present', 'medium', 'contract code can destroy itself or move all ether', [], ['evm']));
  },
};

export const ANALYZERS: Analyzer[] = [dotnetAnalyzer, pythonAnalyzer, luaAnalyzer, beamAnalyzer, evmAnalyzer];

/** Run every managed analyzer that applies against an existing report (for example one from core analyze()). */
export async function runManagedAnalyzers(bytes: Uint8Array, report: Report, name = report.file.name): Promise<Report> {
  const ctx: AnalyzerContext = {
    bytes, name, format: report.file.format, depth: 0, report,
    options: { maxStrings: 400, recurse: false, maxDepth: 0 },
  };
  for (const a of ANALYZERS) {
    let ok = false;
    try { ok = a.applies(ctx); } catch { ok = false; }
    if (!ok) continue;
    try { await a.run(ctx); } catch (e) {
      report.findings.push({ id: `${a.id}.error`, analyzer: a.id, title: `${a.title} could not finish`, severity: 'info', detail: errMsg(e), evidence: [] });
    }
  }
  return report;
}
