// RevLens MCP server factory. Small, focused core tools with compact outputs so agents keep their
// context window for thinking, plus every RevLens package tool. Every answer cites offsets you can verify.
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { basename } from 'node:path';
import {
  diff, verifyClaim, scanRules, STARTER_RULES, toCycloneDX, toMarkdown, lookupOSV, REVLENS_VERSION,
  type Report, type Claim,
} from '@revlens/core';
import { analyzeAll, ALL_ANALYZERS, PACKAGE_TOOLS, TOOL_EFFECTS, TOOL_GROUPS, packageViews, readInput, type PackageTool, type ToolParam } from '@revlens/engine/node';

/** Largest text a single tool answer may carry. Larger answers are cut with a note on how to page. */
export const MAX_OUTPUT_CHARS = Math.max(4_000, Number(process.env.REVLENS_MCP_MAX_CHARS ?? 60_000));

const cache = new Map<string, { mtime: number; bytes: Uint8Array; report: Report }>();
const readFile = (path: string) => readInput(path);

async function reportFor(path: string, rules?: string): Promise<{ report: Report; bytes: Uint8Array }> {
  const { bytes, abs, mtime } = readFile(path);
  const key = abs + (rules ? `#${rules.length}` : '');
  const hit = cache.get(key);
  if (hit && hit.mtime === mtime) return hit;
  const report = await analyzeAll(bytes, { name: basename(abs), rules });
  const entry = { mtime, bytes, report };
  cache.set(key, entry);
  if (cache.size > 32) cache.delete(cache.keys().next().value as string);
  return entry;
}

/** JSON with bigint as text and byte arrays as short base64 previews, so nothing throws or explodes. */
export function toJson(v: unknown): string {
  return JSON.stringify(v, (_k, x) => {
    if (typeof x === 'bigint') return x.toString();
    if (x instanceof Uint8Array) return { bytes: x.length, base64: Buffer.from(x.subarray(0, 4096)).toString('base64'), truncated: x.length > 4096 };
    if (x instanceof Map) return Object.fromEntries(x);
    if (x instanceof Set) return [...x];
    return x;
  }, 1);
}

/** Cut long answers and say so, so agents know to page with limit and offset. */
export function capText(s: string, max = MAX_OUTPUT_CHARS): string {
  if (s.length <= max) return s;
  return `${s.slice(0, max)}\n\n[RevLens: output cut at ${max} of ${s.length} characters. Ask for less with limit, offset, filter or a narrower query.]`;
}

const text = (v: unknown) => ({ content: [{ type: 'text' as const, text: capText(typeof v === 'string' ? v : toJson(v)) }] });
const fail = (e: unknown) => ({ isError: true, content: [{ type: 'text' as const, text: `RevLens error: ${(e as Error).message}` }] });
const wrap = <A,>(fn: (a: A) => Promise<ReturnType<typeof text>>) => async (a: A) => { try { return await fn(a); } catch (e) { return fail(e); } };

const NEXT: Record<string, string> = {
  elf: 'disasm_list_functions, disasm_pseudocode, disasm_xrefs', pe: 'disasm_list_functions, disasm_pseudocode, disasm_xrefs', macho: 'disasm_list_functions, disasm_pseudocode',
  'macho-fat': 'disasm_info, disasm_list_functions', dotnet: 'managed_dotnet_types, managed_dotnet_method_il, managed_dotnet_search',
  apk: 'mobile_manifest, mobile_dex_classes, mobile_dex_method, mobile_dex_xrefs', dex: 'mobile_dex_classes, mobile_dex_method', class: 'mobile_java_class', jar: 'mobile_dex_search, mobile_java_class',
  ipa: 'mobile_ipa_info, mobile_app_framework', js: 'web_js_deobfuscate, web_bundle_modules, web_js_endpoints', sourcemap: 'web_sourcemap_recover', asar: 'web_asar_list, web_electron_audit',
  pcap: 'web_pcap_summary, web_pcap_flows', pcapng: 'web_pcap_summary, web_pcap_flows', sqlite: 'web_sqlite_tables, web_sqlite_query', har: 'web_har_summary',
  pyc: 'managed_pyc_disasm', lua: 'managed_lua_info', beam: 'managed_beam_info',
};

function overview(r: Report) {
  return {
    file: r.file, hardening: r.hardening, sections: r.sections.length, importLibraries: r.imports.map((i) => `${i.library} (${i.symbols.length})`).slice(0, 30),
    exports: r.exports.length, components: r.components.slice(0, 40).map((c) => `${c.name}${c.version ? '@' + c.version : ''}`),
    capabilities: r.capabilities.map((c) => `${c.name}${c.attack ? ` [${c.attack}]` : ''}`),
    deep: packageViews(r),
    findings: r.findings.slice(0, 25).map((f) => ({ severity: f.severity, title: f.title, where: f.evidence[0] })),
    findingTotals: Object.fromEntries(['critical', 'high', 'medium', 'low', 'info'].map((s) => [s, r.findings.filter((f) => f.severity === s).length])),
    members: r.meta.memberCount, timingsMs: r.timings.total,
    next: `${NEXT[r.file.format] ? `For this ${r.file.format} file try ${NEXT[r.file.format]}. ` : ''}Use list_findings, get_strings, get_imports, get_sections, sbom, check_vulns, scan_rules, hexdump or verify_claim to go deeper.`,
  };
}

type Annotations = { readOnlyHint?: boolean; destructiveHint?: boolean; idempotentHint?: boolean; openWorldHint?: boolean };
const READ_ONLY: Annotations = { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false };
const CORE_ANNOTATIONS: Record<string, Annotations> = { check_vulns: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true } };

/** MCP annotations for a package tool, from its declared effects. */
export function annotationsFor(name: string): Annotations {
  const e = TOOL_EFFECTS[name];
  if (!e) return READ_ONLY;
  return { readOnlyHint: !e.writes && !e.executes, destructiveHint: !!e.writes, idempotentHint: !e.network, openWorldHint: !!e.network };
}

/** Convert a package input spec into a zod 4 raw shape. */
export function zodShape(schema: Record<string, ToolParam>): Record<string, z.ZodType> {
  const out: Record<string, z.ZodType> = {};
  for (const [k, p] of Object.entries(schema)) {
    let t: z.ZodType;
    switch (p.type) {
      case 'string': t = z.string(); break;
      case 'number': t = z.number(); break;
      case 'boolean': t = z.boolean(); break;
      case 'array': t = z.array(z.union([z.string(), z.number(), z.boolean()])); break;
      default: t = z.record(z.string(), z.unknown()); break;
    }
    t = t.describe(p.description);
    out[k] = p.optional ? t.optional() : t;
  }
  return out;
}

export interface ToolInfo { name: string; group: string; description: string; annotations: Annotations }

/** Build a RevLens MCP server with every tool, two resources and the agent prompts. Connect it to a transport yourself. */
export function createServer(): { server: McpServer; tools: ToolInfo[] } {
  const server = new McpServer({ name: 'revlens', version: REVLENS_VERSION }, { instructions: 'RevLens reverse engineers local files. Start with analyze_file, follow its "next" hint to the package tools for the format, and check every claim with verify_claim before you report it. Tools only read files unless their annotations say otherwise.' });
  const tools: ToolInfo[] = [];
  const reg = <S extends z.ZodRawShape>(name: string, description: string, shape: S, cb: (a: z.infer<z.ZodObject<S>>) => Promise<unknown>) => {
    const annotations = CORE_ANNOTATIONS[name] ?? READ_ONLY;
    server.registerTool(name, { description, inputSchema: shape, annotations }, cb as never);
    tools.push({ name, group: 'core', description, annotations });
  };
  const P = { path: z.string().describe('Absolute or relative path to a local file') };

  reg('analyze_file', 'Triage any local file (ELF, PE, Mach-O, WASM, JS bundle, source map, npm tgz, ZIP/JAR/APK, CRX/XPI/VSIX, ASAR). Returns format, hashes, hardening, components, capabilities and top findings with offsets.',
    { ...P, rules: z.string().optional().describe('Extra yara-lite rule text') },
    wrap(async ({ path, rules }) => text(overview((await reportFor(path, rules)).report))));

  reg('list_findings', 'All findings for a file, optionally filtered by minimum severity or analyzer id.',
    { ...P, minSeverity: z.enum(['info', 'low', 'medium', 'high', 'critical']).optional(), analyzer: z.string().optional(), limit: z.number().int().min(1).max(500).optional() },
    wrap(async ({ path, minSeverity, analyzer, limit }) => {
      const order = ['info', 'low', 'medium', 'high', 'critical'];
      const min = order.indexOf(minSeverity ?? 'info');
      const list = (await reportFor(path)).report.findings.filter((f) => order.indexOf(f.severity) >= min && (!analyzer || f.analyzer === analyzer));
      return text(list.slice(0, limit ?? 100));
    }));

  reg('get_strings', 'Interesting strings with offsets. Filter by tag (url, ip, email, path, registry, command, guid, version) or a substring.',
    { ...P, tag: z.string().optional(), contains: z.string().optional(), limit: z.number().int().min(1).max(2000).optional() },
    wrap(async ({ path, tag, contains, limit }) => {
      const s = (await reportFor(path)).report.strings.filter((x) => (!tag || x.tag === tag) && (!contains || x.value.toLowerCase().includes(contains.toLowerCase())));
      return text(s.slice(0, limit ?? 150).map((x) => `${x.offset}\t${x.kind}\t${x.tag ?? ''}\t${x.value.slice(0, 300)}`).join('\n') || 'no matching strings');
    }));

  reg('get_sections', 'Sections or segments with file offsets, virtual addresses, sizes and entropy.', P,
    wrap(async ({ path }) => text((await reportFor(path)).report.sections)));

  reg('get_imports', 'Imported libraries and symbols, plus exports. Optional substring filter.',
    { ...P, contains: z.string().optional() },
    wrap(async ({ path, contains }) => {
      const r = (await reportFor(path)).report;
      const q = contains?.toLowerCase();
      return text({
        imports: r.imports.map((i) => ({ library: i.library, symbols: q ? i.symbols.filter((s) => s.toLowerCase().includes(q)) : i.symbols.slice(0, 400) })).filter((i) => i.symbols.length),
        exports: (q ? r.exports.filter((e) => e.toLowerCase().includes(q)) : r.exports).slice(0, 400),
      });
    }));

  reg('sbom', 'Software bill of materials. format "list" is compact, "cyclonedx" is a CycloneDX 1.5 document.',
    { ...P, format: z.enum(['list', 'cyclonedx']).optional() },
    wrap(async ({ path, format }) => {
      const r = (await reportFor(path)).report;
      if (format === 'cyclonedx') return text(toCycloneDX(r));
      return text(r.components.map((c) => `${c.name}\t${c.version ?? '?'}\t${c.ecosystem}\t${Math.round(c.confidence * 100)}%\t${c.purl ?? ''}`).join('\n') || 'no components detected');
    }));

  reg('check_vulns', 'Look up known vulnerabilities (CVE, GHSA) for detected components on OSV.dev. This makes a network request.', P,
    wrap(async ({ path }) => {
      const r = (await reportFor(path)).report;
      const v = await lookupOSV([r, ...(r.children ?? [])].flatMap((x) => x.components));
      return text(v.length ? v.map((f) => ({ severity: f.severity, title: f.title, detail: f.detail })) : 'No known vulnerabilities for components with a detected version.');
    }));

  reg('scan_rules', 'Run yara-lite rules (a YARA subset) against a file. The starter pack runs unless includeStarter is false.',
    { ...P, rules: z.string().optional(), includeStarter: z.boolean().optional() },
    wrap(async ({ path, rules, includeStarter }) => {
      const { bytes } = readFile(path);
      return text(scanRules(bytes, (includeStarter === false ? '' : STARTER_RULES) + '\n' + (rules ?? '')));
    }));

  reg('diff_files', 'Compare two versions of a file or package: dependencies, endpoints, imports, exports, capabilities, sections and findings.',
    { before: z.string(), after: z.string() },
    wrap(async ({ before, after }) => {
      const d = diff((await reportFor(before)).report, (await reportFor(after)).report);
      const trim = <T,>(c: { added: T[]; removed: T[]; changed?: unknown[] }) => ({ added: c.added.slice(0, 60), removed: c.removed.slice(0, 60), changed: c.changed?.slice(0, 60) });
      return text({ summary: d.summary, components: trim(d.components), endpoints: trim(d.endpoints), imports: trim(d.imports), exports: trim(d.exports), capabilities: trim(d.capabilities), findings: { added: d.findings.added.map((f) => f.title), removed: d.findings.removed.map((f) => f.title) } });
    }));

  const claimSchema = z.discriminatedUnion('kind', [
    z.object({ kind: z.literal('contains-string'), value: z.string() }),
    z.object({ kind: z.literal('imports-symbol'), symbol: z.string(), library: z.string().optional() }),
    z.object({ kind: z.literal('has-section'), name: z.string() }),
    z.object({ kind: z.literal('format-is'), format: z.string() }),
    z.object({ kind: z.literal('bytes-at'), offset: z.number().int().min(0), hex: z.string() }),
    z.object({ kind: z.literal('sha256-is'), value: z.string() }),
    z.object({ kind: z.literal('uses-component'), name: z.string(), version: z.string().optional() }),
  ]);
  reg('verify_claim', 'Check claims about a file against its bytes before you rely on them. Returns VERIFIED, REFUTED or UNKNOWN with evidence for each claim.',
    { ...P, claims: z.array(claimSchema).min(1).max(50) },
    wrap(async ({ path, claims }) => {
      const { report, bytes } = await reportFor(path);
      return text(claims.map((c) => verifyClaim(bytes, c as Claim, report)));
    }));

  reg('hexdump', 'Hex and ASCII view of a byte range, to inspect evidence offsets.',
    { ...P, offset: z.number().int().min(0), length: z.number().int().min(1).max(4096).optional() },
    wrap(async ({ path, offset, length }) => {
      const { bytes } = readFile(path);
      const end = Math.min(bytes.length, offset + (length ?? 256));
      const lines: string[] = [];
      for (let o = offset; o < end; o += 16) {
        const row = bytes.subarray(o, Math.min(end, o + 16));
        const hx = Array.from(row, (b) => b.toString(16).padStart(2, '0')).join(' ').padEnd(47);
        const as = Array.from(row, (b) => (b >= 32 && b < 127 ? String.fromCharCode(b) : '.')).join('');
        lines.push(`${o.toString(16).padStart(8, '0')}  ${hx}  ${as}`);
      }
      return text(lines.join('\n') || 'offset is past the end of the file');
    }));

  reg('report_markdown', 'The full report as Markdown, good for writing up results.', P,
    wrap(async ({ path }) => text(toMarkdown((await reportFor(path)).report))));

  reg('list_analyzers', 'What RevLens can analyze, one line per analyzer, across core and every package.', {},
    wrap(async () => text(ALL_ANALYZERS.map((a) => `${a.id} [${a.package}]: ${a.description}`).join('\n'))));


  for (const t of PACKAGE_TOOLS as (PackageTool & { group: string })[]) {
    const annotations = annotationsFor(t.name);
    server.registerTool(t.name, { description: t.description, inputSchema: zodShape(t.inputSchema), annotations }, (async (input: Record<string, unknown>) => {
      try { return text(await t.run(input ?? {})); } catch (e) { return fail(e); }
    }) as never);
    tools.push({ name: t.name, group: t.group, description: t.description, annotations });
  }

  server.registerResource('analyzers', 'revlens://analyzers', { title: 'RevLens analyzers', description: 'Every analyzer across core and the packages, with what it reads.', mimeType: 'application/json' },
    async (uri) => ({ contents: [{ uri: uri.href, mimeType: 'application/json', text: toJson(ALL_ANALYZERS) }] }));
  server.registerResource('tools', 'revlens://tools', { title: 'RevLens tools by area', description: 'Tool names grouped by area, with whether each one only reads.', mimeType: 'application/json' },
    async (uri) => ({ contents: [{ uri: uri.href, mimeType: 'application/json', text: toJson(tools.map((t) => ({ name: t.name, group: t.group, readOnly: t.annotations.readOnlyHint }))) }] }));

  server.registerPrompt('triage_file', {
    title: 'Triage a file',
    description: 'Walk through a first look at an unknown file: format, risk, behavior, then the right deep tools, with evidence for every claim.',
    argsSchema: { path: z.string().describe('Path to the file') },
  }, ({ path }) => ({ messages: [{ role: 'user', content: { type: 'text', text: [
    `Reverse engineer the file at ${path} with the RevLens tools.`,
    '1. Call analyze_file. Note the format, hashes, hardening, components and the top findings.',
    '2. Follow the "next" hint for the format: disasm_* for native code, managed_* for .NET, Python, Lua, BEAM and EVM, mobile_* for APK, DEX, class and IPA, web_* for JavaScript, Electron, PCAP, SQLite and HAR.',
    '3. For native code, list functions, read main or the entry point with disasm_pseudocode, and follow disasm_xrefs from interesting strings and imports.',
    '4. Before you state a fact, check it with verify_claim or cite the offset, address or path that shows it.',
    '5. Finish with a short report: what the file is, what it does, risks found, and the evidence for each point.',
  ].join('\n') } }] }));

  server.registerPrompt('explain_function', {
    title: 'Explain a native function',
    description: 'Disassemble one function, read its pseudo code and callers, and explain what it does with addresses as evidence.',
    argsSchema: { path: z.string().describe('Path to the binary'), function: z.string().describe('Function name or address, for example main or 0x401000') },
  }, ({ path, function: fn }) => ({ messages: [{ role: 'user', content: { type: 'text', text: [
    `Explain the function ${fn} in ${path}.`,
    'Call disasm_pseudocode and disasm_function for it, then disasm_xrefs to see who calls it and what it calls.',
    'Describe inputs, outputs, side effects and any strings or imports it uses. Cite addresses for each statement and say where you are unsure.',
  ].join('\n') } }] }));

  return { server, tools };
}

/** Tool names and groups without starting a server. */
export function toolCatalog(): ToolInfo[] { return createServer().tools; }

export { TOOL_GROUPS };
