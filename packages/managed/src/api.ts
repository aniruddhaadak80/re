// Plain async functions behind the agent tools. Each takes a path or bytes and returns JSON with evidence.
import { page, hex32, LIMITS, ParseError } from './util.js';
import { loadInput, toBase64, writeFiles, type InputSpec } from './io.js';
import {
  loadAssembly, dotnetInfo, listTypes, findMethods, methodIl, xrefs, singleFileBundle, pinvokes, type DotnetAssembly,
} from './dotnet/assembly.js';
import { rows, getString, listUserStrings, row, tokenOf } from './dotnet/metadata.js';
import { parsePyc, disassemble, walkCode, summarizeCode, disText, isPyc } from './python/pyc.js';
import { parseCArchive, extractPyInstaller, parsePyz, readCArchiveEntry, detectPythonPackers } from './python/pyinstaller.js';
import { parseLua, luaListing } from './lua/lua.js';
import { parseBeam } from './beam/beam.js';
import { analyzeEvm } from './evm/evm.js';

export interface Paging { offset?: number; limit?: number }

// Small cache so a burst of tool calls on one assembly does not re-parse it.
const asmCache = new Map<string, DotnetAssembly>();
async function assemblyFor(input: InputSpec): Promise<DotnetAssembly> {
  const key = input.path ? `p:${input.path}` : undefined;
  if (key && asmCache.has(key)) return asmCache.get(key) as DotnetAssembly;
  const { bytes } = await loadInput(input);
  const asm = loadAssembly(bytes);
  if (key) { if (asmCache.size > 4) asmCache.clear(); asmCache.set(key, asm); }
  return asm;
}

/** .NET assembly overview: identity, target framework, references, P/Invoke, resources, counts, obfuscators, ReadyToRun. */
export async function dotnetInfoTool(input: InputSpec): Promise<unknown> {
  const { bytes } = await loadInput(input);
  const bundle = singleFileBundle(bytes);
  let asm: DotnetAssembly;
  try { asm = loadAssembly(bytes); } catch (e) {
    if (bundle && bundle.fileCount > 0) return { singleFileBundle: bundle, note: 'apphost bundle; extract an assembly by its offset to inspect it' };
    throw e;
  }
  asmCache.clear();
  return { ...dotnetInfo(asm), singleFileBundle: bundle };
}

/** List .NET types (optionally with methods and fields), filtered by namespace or substring. */
export async function dotnetTypesTool(input: InputSpec & Paging & { namespace?: string; filter?: string; members?: boolean }): Promise<unknown> {
  const asm = await assemblyFor(input);
  let types = listTypes(asm, { members: !!input.members });
  if (input.namespace !== undefined) types = types.filter((t) => t.namespace === input.namespace);
  if (input.filter) { const f = input.filter.toLowerCase(); types = types.filter((t) => t.fullName.toLowerCase().includes(f)); }
  return page(types, input.offset, input.limit ?? 100, 2000);
}

/** CIL disassembly of one method, by token (0x06xxxxxx) or Type::Method, with tokens resolved. */
export async function dotnetMethodIlTool(input: InputSpec & { method: string; index?: number; maxInstructions?: number; format?: 'text' | 'json' }): Promise<unknown> {
  const asm = await assemblyFor(input);
  const rids = findMethods(asm, input.method);
  if (!rids.length) throw new ParseError(`no method matches ${input.method}`);
  const rid = rids[Math.min(Math.max(0, input.index ?? 0), rids.length - 1)] as number;
  const il = methodIl(asm, rid, Math.min(input.maxInstructions ?? 5000, LIMITS.maxInstructions));
  const overloads = rids.map((r) => asm.tokenText(tokenOf(0x06, r)));
  if (input.format === 'text') return { token: il.token, name: il.name, overloads, text: il.text, error: il.error };
  return { ...il, overloads };
}

/** Search types, methods, fields, member refs, user strings and P/Invoke by substring, or find IL xrefs to a member. */
export async function dotnetSearchTool(input: InputSpec & Paging & { query: string; kind?: string }): Promise<unknown> {
  const asm = await assemblyFor(input);
  const md = asm.md;
  const q = String(input.query ?? '').toLowerCase();
  if (!q) throw new ParseError('query is required');
  const kind = input.kind ?? 'all';
  const out: { kind: string; token?: string; text: string; offset?: number }[] = [];
  const want = (k: string) => kind === 'all' || kind === k;
  const cap = 20000;
  if (want('type')) rows(md, 0x02).forEach((_, i) => { const t = asm.typeName(0x02, i + 1); if (t.toLowerCase().includes(q) && out.length < cap) out.push({ kind: 'type', token: hex32(tokenOf(0x02, i + 1)), text: t }); });
  if (want('typeref')) rows(md, 0x01).forEach((_, i) => { const t = asm.typeName(0x01, i + 1); if (t.toLowerCase().includes(q) && out.length < cap) out.push({ kind: 'typeref', token: hex32(tokenOf(0x01, i + 1)), text: t }); });
  if (want('method')) rows(md, 0x06).forEach((m, i) => { if (getString(md, m.Name as number).toLowerCase().includes(q) && out.length < cap) out.push({ kind: 'method', token: hex32(tokenOf(0x06, i + 1)), text: asm.tokenText(tokenOf(0x06, i + 1)) }); });
  if (want('field')) rows(md, 0x04).forEach((f, i) => { if (getString(md, f.Name as number).toLowerCase().includes(q) && out.length < cap) out.push({ kind: 'field', token: hex32(tokenOf(0x04, i + 1)), text: asm.tokenText(tokenOf(0x04, i + 1)) }); });
  if (want('memberref')) rows(md, 0x0a).forEach((_, i) => { const t = asm.tokenText(tokenOf(0x0a, i + 1)); if (t.toLowerCase().includes(q) && out.length < cap) out.push({ kind: 'memberref', token: hex32(tokenOf(0x0a, i + 1)), text: t }); });
  if (want('string')) for (const s of listUserStrings(md)) if (s.value.toLowerCase().includes(q) && out.length < cap) out.push({ kind: 'string', token: hex32(s.token), text: s.value, offset: md.usOffset + s.offset });
  if (want('pinvoke')) for (const p of pinvokes(asm)) if ((p.library + ' ' + p.entry + ' ' + p.member).toLowerCase().includes(q)) out.push({ kind: 'pinvoke', token: p.token, text: `${p.library}!${p.entry} -> ${p.member}` });
  if (kind === 'xref') {
    const token = /^(0x)?[0-9a-f]{8}$/i.test(input.query) ? parseInt(input.query, 16) : undefined;
    const res = xrefs(asm, (tok, text) => (token !== undefined ? tok === token : text.toLowerCase().includes(q)), { max: 5000 });
    return { ...page(res.xrefs, input.offset, input.limit ?? 100, 2000), scannedMethods: res.scannedMethods, budgetExhausted: res.budgetExhausted };
  }
  void row;
  return page(out, input.offset, input.limit ?? 100, 2000);
}

/** Disassemble a .pyc (3.7 to 3.13) like dis, as text or per instruction JSON, for the whole tree or one code path. */
export async function pycDisasmTool(input: InputSpec & Paging & { codePath?: string; format?: 'text' | 'json'; version?: string }): Promise<unknown> {
  const { bytes } = await loadInput(input);
  if (!isPyc(bytes) && !input.version) throw new ParseError('not a .pyc file (bad magic); pass version to force one');
  const pyc = parsePyc(bytes, input.version);
  const codes: { path: string; summary: ReturnType<typeof summarizeCode>; code: Parameters<typeof disassemble>[0] }[] = [];
  walkCode(pyc.code, (c, path) => codes.push({ path, summary: summarizeCode(c, path), code: c }));
  const header = pyc.header;
  if (input.format === 'json' || input.codePath) {
    const pick = input.codePath ? codes.filter((c) => c.path === input.codePath || c.path.endsWith('/' + input.codePath)) : codes;
    if (input.codePath && !pick.length) throw new ParseError(`no code object at ${input.codePath}; have ${codes.map((c) => c.path).slice(0, 50).join(', ')}`);
    const first = pick[0];
    if (input.codePath && first) {
      const d = disassemble(first.code, pyc.version);
      return { version: pyc.version, header, code: first.summary, instructions: page(d.instructions, input.offset, input.limit ?? 500, 5000), error: d.error, text: input.format === 'json' ? undefined : disText(first.code, pyc.version) };
    }
    return { version: pyc.version, header, codeObjects: page(codes.map((c) => c.summary), input.offset, input.limit ?? 100, 1000) };
  }
  const text = disText(pyc.code, pyc.version, { maxLines: Math.min(input.limit ?? 4000, 50000) });
  return { version: pyc.version, header, codeObjects: codes.map((c) => c.path), text };
}

/** List a PyInstaller executable: cookie, Python version, CArchive TOC and the PYZ module list. */
export async function pyinstallerListTool(input: InputSpec & Paging & { includePyz?: boolean }): Promise<unknown> {
  const { bytes } = await loadInput(input);
  const a = parseCArchive(bytes);
  let pyz: unknown;
  if (input.includePyz !== false) {
    const z = a.entries.find((e) => e.type === 'z');
    if (z) {
      try { const p = parsePyz(readCArchiveEntry(bytes, z), a.pythonVersion); pyz = { name: z.name, offset: z.offset, pythonVersion: p.pythonVersion, modules: p.entries.length, entries: page(p.entries, input.offset, input.limit ?? 200, 5000) }; }
      catch (e) { pyz = { error: e instanceof Error ? e.message : String(e) }; }
    }
  }
  return {
    cookieOffset: a.cookieOffset, packageOffset: a.packageOffset, format: a.format, pythonVersion: a.pythonVersion, pylibName: a.pylibName, options: a.options,
    entryPoints: a.entries.filter((e) => e.type === 's' && !e.name.startsWith('pyi')).map((e) => e.name),
    entries: page(a.entries, input.offset, input.limit ?? 200, 5000), pyz, packers: detectPythonPackers(bytes),
  };
}

/**
 * Extract PyInstaller contents with fixed .pyc headers. With outDir (Node) files are written there;
 * otherwise one `entry` can be returned as base64, and the rest is listed.
 */
export async function pyinstallerExtractTool(input: InputSpec & Paging & { outDir?: string; filter?: string; entry?: string; includeBinaries?: boolean }): Promise<unknown> {
  const { bytes } = await loadInput(input);
  const f = input.filter?.toLowerCase();
  const res = extractPyInstaller(bytes, { includeBinaries: !!input.includeBinaries || !!input.outDir, filter: f ? (p) => p.toLowerCase().includes(f) : undefined });
  const listing = res.files.map((x) => ({ path: x.path, source: x.source, type: x.type, size: x.size, fixedHeader: x.fixedHeader }));
  if (input.outDir) {
    const written = await writeFiles(input.outDir, res.files.map((x) => ({ path: x.path, data: x.data })));
    return { outDir: input.outDir, written: written.length, pythonVersion: res.archive.pythonVersion, errors: res.errors.slice(0, 100), files: page(listing, input.offset, input.limit ?? 200, 5000) };
  }
  if (input.entry) {
    const hit = res.files.find((x) => x.path === input.entry);
    if (!hit) throw new ParseError(`no extracted file named ${input.entry}`);
    if (hit.size > 8 * 1024 * 1024) throw new ParseError('entry larger than 8 MiB; use outDir');
    return { path: hit.path, size: hit.size, fixedHeader: hit.fixedHeader, base64: toBase64(hit.data) };
  }
  return { pythonVersion: res.archive.pythonVersion, errors: res.errors.slice(0, 100), files: page(listing, input.offset, input.limit ?? 200, 5000) };
}

/** Lua 5.1 to 5.4 or LuaJIT bytecode: header, function tree, constants and an optional luac -l style listing. */
export async function luaInfoTool(input: InputSpec & { listing?: boolean; maxLines?: number }): Promise<unknown> {
  const { bytes } = await loadInput(input);
  const c = parseLua(bytes);
  const fns: unknown[] = [];
  const walk = (f: typeof c.main, d: number) => {
    if (fns.length > 2000 || d > LIMITS.maxDepth) return;
    fns.push({ path: f.path, offset: f.offset, source: f.source, lines: [f.lineDefined, f.lastLineDefined], params: f.numParams, vararg: f.isVararg, maxStack: f.maxStack, upvalues: f.numUpvalues, instructions: f.instructions.length, constants: f.constants.slice(0, 100), locals: f.locals.slice(0, 100), upvalueNames: f.upvalueNames });
    f.children.forEach((k) => walk(k, d + 1));
  };
  walk(c.main, 0);
  return { flavor: c.flavor, version: c.version, header: c.header, stripped: c.stripped, functionCount: c.functionCount, functions: fns, listing: input.listing === false ? undefined : luaListing(c, Math.min(input.maxLines ?? 2000, 50000)) };
}

/** Erlang BEAM module: chunks, atoms, exports, imports, locals, attributes and compile info. */
export async function beamInfoTool(input: InputSpec & { maxAtoms?: number }): Promise<unknown> {
  const { bytes } = await loadInput(input);
  const b = parseBeam(bytes);
  return { ...b, atoms: b.atoms.slice(0, input.maxAtoms ?? 500), atomCount: b.atoms.length };
}

/** EVM disassembly with program counters (hex input or file). */
export async function evmDisasmTool(input: InputSpec & Paging): Promise<unknown> {
  const { bytes } = await loadInput(input);
  const s = analyzeEvm(bytes);
  const { instructions, ...summary } = s;
  return { size: summary.size, codeSize: summary.codeSize, metadata: summary.metadata, instructions: page(instructions, input.offset, input.limit ?? 500, 20000) };
}

/** EVM function selectors from the dispatcher with known names, proxy patterns, events and Solidity metadata. */
export async function evmSelectorsTool(input: InputSpec): Promise<unknown> {
  const { bytes } = await loadInput(input);
  const { instructions, opcodeStats, ...summary } = analyzeEvm(bytes);
  void instructions;
  return { ...summary, topOpcodes: Object.entries(opcodeStats).sort((a, b) => b[1] - a[1]).slice(0, 15) };
}
