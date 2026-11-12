// RevLens MCP server factory with lazy loading. Tool names, descriptions and input specs come from a
// generated manifest, so the server answers initialize and tools/list without loading the analysis
// packages. @revlens/core and @revlens/engine are imported on the first call that needs them.
// Also holds the platform tools: guidance, progressive catalog, providers and per-session settings.
import { McpServer, type RegisteredTool } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { openSync, fstatSync, readFileSync, closeSync } from 'node:fs';
import { basename, resolve } from 'node:path';
import type { Report, Claim } from '@revlens/core';
import { TOOL_MANIFEST } from './generated/tool-manifest.js';
import type { ManifestParam, ManifestTool } from './manifest-types.js';
import { AnalysisSettings, SettingsError, SETTING_DEFS, type SettingsOptions } from './settings.js';
import { guidance, readGuidanceSection, searchGuidance, serverInstructions, FORMAT_PLAYBOOKS } from './guidance/index.js';
import { WORKFLOWS, renderWorkflow } from './guidance/workflows.js';
import {
  buildCatalogIndex, contractSummary, discover, exampleFor, profileTools, specToJsonSchema, TOOL_PROFILES,
  type CatalogEntry, type CatalogIndex, type JsonSchema, type ToolProfile,
} from './catalog.js';

type EngineNode = typeof import('@revlens/engine/node');
type Core = typeof import('@revlens/core');

let enginePromise: Promise<EngineNode> | undefined;
let corePromise: Promise<Core> | undefined;
let engineReady = false;
let engineMod: EngineNode | undefined;
/** Import @revlens/engine/node once (it pulls in every analysis package). */
export function loadEngine(): Promise<EngineNode> {
  enginePromise ??= import('@revlens/engine/node').then((m) => { engineReady = true; engineMod = m; return m; });
  return enginePromise;
}
/** Import @revlens/core once. */
export function loadCore(): Promise<Core> { corePromise ??= import('@revlens/core'); return corePromise; }
/** True once the analysis packages are in memory. */
export function engineLoaded(): boolean { return engineReady; }
/** The engine module when already loaded, for synchronous exit paths. */
export function loadedEngine(): EngineNode | undefined { return engineMod; }
/** Close bridge sessions if the packages were ever loaded. */
export async function closeLoadedSessions(): Promise<number> { return engineMod ? engineMod.closeAllSessions() : 0; }
/** Kill bridge session processes right away, if the packages were ever loaded. */
export function killLoadedSessions(): void { engineMod?.killAllSessions(); }

/** Package version, read from the generated manifest so it needs no import. */
export const SERVER_VERSION = TOOL_MANIFEST.version;

/** Default cap for one tool answer. Sessions change it with update_analysis_settings (maxOutputChars). */
export const MAX_OUTPUT_CHARS = Math.max(4_000, Number(process.env.REVLENS_MCP_MAX_CHARS ?? 60_000));

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
  return `${s.slice(0, max)}\n\n[RevLens: output cut at ${max} of ${s.length} characters. Ask for less with limit, offset, filter or a narrower query, or raise maxOutputChars with update_analysis_settings.]`;
}

type Annotations = { readOnlyHint?: boolean; destructiveHint?: boolean; idempotentHint?: boolean; openWorldHint?: boolean };
type Effects = { writes?: boolean; network?: boolean; executes?: boolean };
const READ_ONLY: Annotations = { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false };

/** MCP annotations for a tool, from its declared effects. */
export function annotationsFor(name: string, effects: Record<string, Effects> = TOOL_MANIFEST.effects): Annotations {
  const e = effects[name];
  if (!e) return READ_ONLY;
  return { readOnlyHint: !e.writes && !e.executes, destructiveHint: !!e.writes, idempotentHint: !e.network, openWorldHint: !!e.network };
}

/** Convert a package input spec into a zod 4 raw shape. */
export function zodShape(schema: Record<string, ManifestParam>): Record<string, z.ZodType> {
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

export interface ToolInfo { name: string; group: string; description: string; annotations: Annotations; listed?: boolean; aliasOf?: string }

export interface ServerOptions extends SettingsOptions {
  /** minimal, standard or full (default). Hidden tools stay callable through call_tool and discover_tools { load: true }. */
  profile?: ToolProfile;
  /** share a settings object (tests); by default each server gets its own */
  settings?: AnalysisSettings;
}

/** Compatibility names (as other MCP reverse engineering servers call them) for RevLens tools. */
export const TOOL_ALIASES: Record<string, string> = {
  list_cutter_sessions: 'bridge_cutter_sessions',
  cutter_command: 'bridge_cutter_command',
};

const NEXT: Record<string, string> = {
  elf: 'disasm_list_functions, disasm_pseudocode, disasm_xrefs', pe: 'disasm_list_functions, disasm_pseudocode, disasm_xrefs', macho: 'disasm_list_functions, disasm_pseudocode',
  'macho-fat': 'disasm_info, disasm_list_functions', dotnet: 'managed_dotnet_types, managed_dotnet_method_il, managed_dotnet_search',
  apk: 'mobile_manifest, mobile_dex_classes, mobile_dex_method, mobile_dex_xrefs', dex: 'mobile_dex_classes, mobile_dex_method', class: 'mobile_java_class', jar: 'mobile_dex_search, mobile_java_class',
  ipa: 'mobile_ipa_info, mobile_app_framework', js: 'web_js_deobfuscate, web_bundle_modules, web_js_endpoints', sourcemap: 'web_sourcemap_recover', asar: 'web_asar_list, web_electron_audit',
  pcap: 'web_pcap_summary, web_pcap_flows', pcapng: 'web_pcap_summary, web_pcap_flows', sqlite: 'web_sqlite_tables, web_sqlite_query', har: 'web_har_summary',
  pyc: 'managed_pyc_disasm', lua: 'managed_lua_info', beam: 'managed_beam_info',
};

function overview(r: Report, views: string[]) {
  const fmt = r.file.format as string;
  return {
    file: r.file, hardening: r.hardening, sections: r.sections.length, importLibraries: r.imports.map((i) => `${i.library} (${i.symbols.length})`).slice(0, 30),
    exports: r.exports.length, components: r.components.slice(0, 40).map((c) => `${c.name}${c.version ? '@' + c.version : ''}`),
    capabilities: r.capabilities.map((c) => `${c.name}${c.attack ? ` [${c.attack}]` : ''}`),
    deep: views,
    findings: r.findings.slice(0, 25).map((f) => ({ severity: f.severity, title: f.title, where: f.evidence[0] })),
    findingTotals: Object.fromEntries(['critical', 'high', 'medium', 'low', 'info'].map((s) => [s, r.findings.filter((f) => f.severity === s).length])),
    members: r.meta.memberCount, timingsMs: r.timings.total,
    next: `${NEXT[fmt] ? `For this ${fmt} file try ${NEXT[fmt]}. ` : ''}${FORMAT_PLAYBOOKS[fmt] ? `Playbook: guidance { format: "${fmt}" }. ` : ''}Use list_findings, get_strings, get_imports, get_sections, sbom, check_vulns, scan_rules, hexdump or verify_claim to go deeper, or discover_tools { format: "${fmt}" }.`,
  };
}

/** Read a regular file through one descriptor, with a size cap. */
export function readInputFile(path: string, maxBytes: number): { bytes: Uint8Array; abs: string; mtime: number } {
  if (typeof path !== 'string' || !path || path.includes('\0')) throw new Error('path must be a non empty string');
  const abs = resolve(path);
  const fd = openSync(abs, 'r');
  try {
    const st = fstatSync(fd);
    if (!st.isFile()) throw new Error(`${abs} is not a regular file`);
    if (st.size > maxBytes) throw new Error(`${abs} is larger than ${maxBytes} bytes. Raise maxFileMB with update_analysis_settings or REVLENS_MAX_FILE_MB.`);
    return { bytes: new Uint8Array(readFileSync(fd)), abs, mtime: st.mtimeMs };
  } finally { closeSync(fd); }
}

class BudgetError extends Error {}
function withBudget<T>(p: Promise<T>, ms: number, what: string): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  const t = new Promise<never>((_, rej) => { timer = setTimeout(() => rej(new BudgetError(`${what} ran past its ${ms} ms budget. Raise it with update_analysis_settings or narrow the request.`)), ms); timer.unref?.(); });
  return Promise.race([p, t]).finally(() => clearTimeout(timer));
}

const CORE_NAMES = ['analyze_file', 'list_findings', 'get_strings', 'get_sections', 'get_imports', 'sbom', 'check_vulns', 'scan_rules', 'diff_files', 'verify_claim', 'hexdump', 'report_markdown', 'list_analyzers'];
const PLATFORM_NAMES = ['guidance', 'search_guidance', 'read_guidance_section', 'guided_workflows', 'discover_tools', 'capabilities', 'providers', 'inspect_input_contract', 'call_tool', 'inspect_analysis_settings', 'update_analysis_settings'];
const PLATFORM_EFFECTS: Record<string, Effects> = { check_vulns: { network: true }, update_analysis_settings: { writes: true }, call_tool: { writes: true, executes: true, network: true }, providers: { executes: true } };

/** Every tool name a server built from this manifest offers, before any lazy additions. */
export function staticToolNames(): string[] {
  const pkg = TOOL_MANIFEST.tools.map((t) => t.name);
  const aliases = Object.entries(TOOL_ALIASES).filter(([, to]) => pkg.includes(to)).map(([a]) => a);
  return [...CORE_NAMES, ...PLATFORM_NAMES, ...pkg, ...aliases];
}

type Handler = (args: Record<string, unknown>) => Promise<{ content: { type: 'text'; text: string }[]; isError?: boolean }>;
interface Registered { name: string; shape: Record<string, z.ZodType>; handler: Handler; tool: RegisteredTool; entry: CatalogEntry }

/** Build a RevLens MCP server with every tool, resources and the agent prompts. Connect it to a transport yourself. */
export function createServer(opts: ServerOptions = {}): { server: McpServer; tools: ToolInfo[]; settings: AnalysisSettings; profile: ToolProfile } {
  const profile = opts.profile ?? 'full';
  const settings = opts.settings ?? new AnalysisSettings(opts);
  const allNames = staticToolNames();
  const visible = profileTools(profile, allNames);
  const server = new McpServer({ name: 'revlens', version: SERVER_VERSION }, {
    instructions: serverInstructions({ profile, toolCount: visible.size, hidden: allNames.length - visible.size }),
    capabilities: { tools: { listChanged: true } },
  });
  const tools: ToolInfo[] = [];
  const registry = new Map<string, Registered>();
  let catalog: CatalogIndex | undefined;

  const cap = () => settings.get('maxOutputChars');
  const text = (v: unknown) => ({ content: [{ type: 'text' as const, text: capText(typeof v === 'string' ? v : toJson(v), cap()) }] });
  const fail = (e: unknown) => ({ isError: true, content: [{ type: 'text' as const, text: `RevLens error: ${(e as Error).message}` }] });

  // ---------- analysis cache, per session ----------
  const cache = new Map<string, { mtime: number; bytes: Uint8Array; report: Report }>();
  settings.onChange(() => cache.clear());
  const maxBytes = () => settings.get('maxFileMB') * 1024 * 1024;
  const readFile = (path: string) => readInputFile(path, maxBytes());
  async function reportFor(path: string, rules?: string): Promise<{ report: Report; bytes: Uint8Array }> {
    const { bytes, abs, mtime } = readFile(path);
    const key = abs + (rules ? `#${rules.length}:${rules.slice(0, 64)}` : '');
    const hit = cache.get(key);
    if (hit && hit.mtime === mtime) return hit;
    const eng = await loadEngine();
    const disabled = new Set(settings.get('disabledAnalyzers'));
    const pk = settings.get('packages');
    const analyzers = disabled.size ? TOOL_MANIFEST.analyzers.filter((a) => a.package !== 'bridges' && !disabled.has(a.id)).map((a) => a.id) : undefined;
    const report = await withBudget(eng.analyzeAllNode(bytes, { name: basename(abs), rules, maxStrings: settings.get('maxStrings'), recurse: settings.get('recurse'), packages: pk.length ? pk : undefined, analyzers }), settings.get('analyzeTimeoutMs'), 'analysis');
    const entry = { mtime, bytes, report };
    cache.set(key, entry);
    while (cache.size > settings.get('cacheEntries')) cache.delete(cache.keys().next().value as string);
    return entry;
  }

  // ---------- registration with session gates ----------
  function gate(name: string, effects: Effects, shape: Record<string, z.ZodType>, run: (a: Record<string, unknown>) => Promise<unknown>): Handler {
    return async (args) => {
      try {
        const a = { ...(args ?? {}) };
        if (effects.executes && settings.get('denyExecution')) return fail(new Error(`${name} starts a program and this session has denyExecution on.`));
        if (effects.network && !settings.get('allowNetwork')) return fail(new Error(`${name} reaches the network and this session has allowNetwork off. Turn it on with update_analysis_settings.`));
        if ('allowExecution' in shape && a.allowExecution === undefined && settings.get('allowExecution')) a.allowExecution = true;
        const out = await withBudget(run(a), settings.get('toolTimeoutMs'), name);
        if (out && typeof out === 'object' && 'content' in (out as object) && Array.isArray((out as { content: unknown }).content)) return out as Awaited<ReturnType<Handler>>;
        return text(out);
      } catch (e) { return fail(e); }
    };
  }
  function reg(name: string, group: string, description: string, shape: Record<string, z.ZodType>, run: (a: any) => Promise<unknown>, effects: Effects = {}, extra: { jsonSchema?: JsonSchema; aliasOf?: string } = {}): void {
    if (registry.has(name)) return;
    const annotations = Object.keys(effects).length ? annotationsFor(name, { [name]: effects }) : READ_ONLY;
    const handler = gate(name, effects, shape, run);
    const tool = server.registerTool(name, { description, inputSchema: shape, annotations }, ((a: Record<string, unknown>) => handler(a)) as never);
    const listed = visible.has(name);
    if (!listed) tool.disable();
    let schema: JsonSchema;
    try { schema = extra.jsonSchema ?? (z.toJSONSchema(z.object(shape)) as unknown as JsonSchema); } catch { schema = { type: 'object', properties: {}, required: [] }; }
    const entry: CatalogEntry = { name, group, description, inputSchema: schema, effects, aliasOf: extra.aliasOf };
    registry.set(name, { name, shape, handler, tool, entry });
    tools.push({ name, group, description, annotations, listed, ...(extra.aliasOf ? { aliasOf: extra.aliasOf } : {}) });
    catalog = undefined;
  }
  const core = (name: string, description: string, shape: Record<string, z.ZodType>, run: (a: any) => Promise<unknown>) => reg(name, 'core', description, shape, run, PLATFORM_EFFECTS[name] ?? {});
  const platform = (name: string, description: string, shape: Record<string, z.ZodType>, run: (a: any) => Promise<unknown>) => reg(name, 'platform', description, shape, run, PLATFORM_EFFECTS[name] ?? {});
  const P = { path: z.string().describe('Absolute or relative path to a local file') };

  // ---------- core tools ----------
  core('analyze_file', 'Triage any local file (ELF, PE, Mach-O, WASM, JS bundle, source map, npm tgz, ZIP/JAR/APK, CRX/XPI/VSIX, ASAR). Returns format, hashes, hardening, components, capabilities and top findings with offsets.',
    { ...P, rules: z.string().optional().describe('Extra yara-lite rule text') },
    async ({ path, rules }) => { const r = (await reportFor(path, rules)).report; return overview(r, (await loadEngine()).packageViews(r)); });

  core('list_findings', 'All findings for a file, optionally filtered by minimum severity or analyzer id.',
    { ...P, minSeverity: z.enum(['info', 'low', 'medium', 'high', 'critical']).optional(), analyzer: z.string().optional(), limit: z.number().int().min(1).max(500).optional() },
    async ({ path, minSeverity, analyzer, limit }) => {
      const order = ['info', 'low', 'medium', 'high', 'critical'];
      const min = order.indexOf(minSeverity ?? 'info');
      const list = (await reportFor(path)).report.findings.filter((f) => order.indexOf(f.severity) >= min && (!analyzer || f.analyzer === analyzer));
      return list.slice(0, limit ?? 100);
    });

  core('get_strings', 'Interesting strings with offsets. Filter by tag (url, ip, email, path, registry, command, guid, version) or a substring.',
    { ...P, tag: z.string().optional(), contains: z.string().optional(), limit: z.number().int().min(1).max(2000).optional() },
    async ({ path, tag, contains, limit }) => {
      const s = (await reportFor(path)).report.strings.filter((x) => (!tag || x.tag === tag) && (!contains || x.value.toLowerCase().includes(contains.toLowerCase())));
      return s.slice(0, limit ?? 150).map((x) => `${x.offset}\t${x.kind}\t${x.tag ?? ''}\t${x.value.slice(0, 300)}`).join('\n') || 'no matching strings';
    });

  core('get_sections', 'Sections or segments with file offsets, virtual addresses, sizes and entropy.', P,
    async ({ path }) => (await reportFor(path)).report.sections);

  core('get_imports', 'Imported libraries and symbols, plus exports. Optional substring filter.',
    { ...P, contains: z.string().optional() },
    async ({ path, contains }) => {
      const r = (await reportFor(path)).report;
      const q = contains?.toLowerCase();
      return {
        imports: r.imports.map((i) => ({ library: i.library, symbols: q ? i.symbols.filter((s) => s.toLowerCase().includes(q)) : i.symbols.slice(0, 400) })).filter((i) => i.symbols.length),
        exports: (q ? r.exports.filter((e) => e.toLowerCase().includes(q)) : r.exports).slice(0, 400),
      };
    });

  core('sbom', 'Software bill of materials. format "list" is compact, "cyclonedx" is a CycloneDX 1.5 document.',
    { ...P, format: z.enum(['list', 'cyclonedx']).optional() },
    async ({ path, format }) => {
      const r = (await reportFor(path)).report;
      if (format === 'cyclonedx') return (await loadCore()).toCycloneDX(r);
      return r.components.map((c) => `${c.name}\t${c.version ?? '?'}\t${c.ecosystem}\t${Math.round(c.confidence * 100)}%\t${c.purl ?? ''}`).join('\n') || 'no components detected';
    });

  core('check_vulns', 'Look up known vulnerabilities (CVE, GHSA) for detected components on OSV.dev. This makes a network request.', P,
    async ({ path }) => {
      const r = (await reportFor(path)).report;
      const v = await (await loadCore()).lookupOSV([r, ...(r.children ?? [])].flatMap((x) => x.components));
      return v.length ? v.map((f) => ({ severity: f.severity, title: f.title, detail: f.detail })) : 'No known vulnerabilities for components with a detected version.';
    });

  core('scan_rules', 'Run yara-lite rules (a YARA subset) against a file. The starter pack runs unless includeStarter is false.',
    { ...P, rules: z.string().optional(), includeStarter: z.boolean().optional() },
    async ({ path, rules, includeStarter }) => {
      const { bytes } = readFile(path);
      const c = await loadCore();
      return c.scanRules(bytes, (includeStarter === false ? '' : c.STARTER_RULES) + '\n' + (rules ?? ''));
    });

  core('diff_files', 'Compare two versions of a file or package: dependencies, endpoints, imports, exports, capabilities, sections and findings.',
    { before: z.string(), after: z.string() },
    async ({ before, after }) => {
      const d = (await loadCore()).diff((await reportFor(before)).report, (await reportFor(after)).report);
      const trim = <T,>(c: { added: T[]; removed: T[]; changed?: unknown[] }) => ({ added: c.added.slice(0, 60), removed: c.removed.slice(0, 60), changed: c.changed?.slice(0, 60) });
      return { summary: d.summary, components: trim(d.components), endpoints: trim(d.endpoints), imports: trim(d.imports), exports: trim(d.exports), capabilities: trim(d.capabilities), findings: { added: d.findings.added.map((f) => f.title), removed: d.findings.removed.map((f) => f.title) } };
    });

  const claimSchema = z.discriminatedUnion('kind', [
    z.object({ kind: z.literal('contains-string'), value: z.string() }),
    z.object({ kind: z.literal('imports-symbol'), symbol: z.string(), library: z.string().optional() }),
    z.object({ kind: z.literal('has-section'), name: z.string() }),
    z.object({ kind: z.literal('format-is'), format: z.string() }),
    z.object({ kind: z.literal('bytes-at'), offset: z.number().int().min(0), hex: z.string() }),
    z.object({ kind: z.literal('sha256-is'), value: z.string() }),
    z.object({ kind: z.literal('uses-component'), name: z.string(), version: z.string().optional() }),
  ]);
  core('verify_claim', 'Check claims about a file against its bytes before you rely on them. Returns VERIFIED, REFUTED or UNKNOWN with evidence for each claim.',
    { ...P, claims: z.array(claimSchema).min(1).max(50) },
    async ({ path, claims }) => {
      const { report, bytes } = await reportFor(path);
      const c = await loadCore();
      return (claims as Claim[]).map((x) => c.verifyClaim(bytes, x, report));
    });

  core('hexdump', 'Hex and ASCII view of a byte range, to inspect evidence offsets.',
    { ...P, offset: z.number().int().min(0), length: z.number().int().min(1).max(4096).optional() },
    async ({ path, offset, length }) => {
      const { bytes } = readFile(path);
      const end = Math.min(bytes.length, offset + (length ?? 256));
      const lines: string[] = [];
      for (let o = offset; o < end; o += 16) {
        const row = bytes.subarray(o, Math.min(end, o + 16));
        const hx = Array.from(row, (b) => b.toString(16).padStart(2, '0')).join(' ').padEnd(47);
        const as = Array.from(row, (b) => (b >= 32 && b < 127 ? String.fromCharCode(b) : '.')).join('');
        lines.push(`${o.toString(16).padStart(8, '0')}  ${hx}  ${as}`);
      }
      return lines.join('\n') || 'offset is past the end of the file';
    });

  core('report_markdown', 'The full report as Markdown, good for writing up results.', P,
    async ({ path }) => (await loadCore()).toMarkdown((await reportFor(path)).report));

  core('list_analyzers', 'What RevLens can analyze, one line per analyzer, across core and every package.', {},
    async () => TOOL_MANIFEST.analyzers.map((a) => `${a.id} [${a.package}]: ${a.description}`).join('\n'));

  // ---------- package tools: listed from the manifest, loaded on first call ----------
  const registerPackageTool = (t: ManifestTool, effects: Effects) => reg(t.name, t.group, t.description, zodShape(t.inputSchema), async (input) => {
    const eng = await loadEngine();
    reconcile(eng);
    const real = eng.PACKAGE_TOOLS.find((x) => x.name === t.name);
    if (!real) throw new Error(`${t.name} is listed but not present in this build of the packages. Rebuild the tool manifest.`);
    return real.run(input ?? {});
  }, effects, { jsonSchema: specToJsonSchema(t.inputSchema) });
  for (const t of TOOL_MANIFEST.tools) registerPackageTool(t, TOOL_MANIFEST.effects[t.name] ?? {});
  for (const [alias, to] of Object.entries(TOOL_ALIASES)) {
    const t = TOOL_MANIFEST.tools.find((x) => x.name === to);
    if (t) reg(alias, t.group, `Same as ${to}. ${t.description}`, zodShape(t.inputSchema), (a) => registry.get(to)!.handler(a), TOOL_MANIFEST.effects[to] ?? {}, { jsonSchema: specToJsonSchema(t.inputSchema), aliasOf: to });
  }
  let reconciled = false;
  /** Register tools the packages have that the manifest did not know about (a stale manifest never hides a tool). */
  function reconcile(eng: EngineNode): void {
    if (reconciled) return;
    reconciled = true;
    for (const t of eng.PACKAGE_TOOLS) if (!registry.has(t.name)) {
      visible.add(t.name);
      registerPackageTool({ name: t.name, group: t.group, description: t.description, inputSchema: t.inputSchema as Record<string, ManifestParam> }, eng.TOOL_EFFECTS[t.name] ?? {});
    }
  }

  // ---------- guidance ----------
  platform('guidance', 'How to work with RevLens. No input: overview, playbooks, workflows and docs. format: the playbook for a file format (elf, pe, macho, apk, ipa, dotnet, pyc, js, asar, firmware, pcap). topic: a docs page.',
    { format: z.string().optional().describe('file format, as analyze_file reports it'), topic: z.string().optional().describe('docs page name or a few words'), maxChars: z.number().int().min(500).max(60000).optional() },
    (a) => guidance(a));
  platform('search_guidance', 'Search RevLens docs and playbooks with a BM25 index. Returns ranked sections with snippets and ids for read_guidance_section. Reads no target.',
    { query: z.string().min(1).max(2000), limit: z.number().int().min(1).max(50).optional(), kind: z.enum(['doc', 'playbook']).optional(), requireAll: z.boolean().optional().describe('only sections holding every query word') },
    (a) => searchGuidance(a));
  platform('read_guidance_section', 'Read one docs or playbook section by the id search_guidance returned, optionally with its sub sections. Paged by characters; reports a stale hash.',
    { id: z.string().min(1).max(400), hash: z.string().max(16).optional(), includeChildren: z.boolean().optional(), offset: z.number().int().min(0).optional(), maxChars: z.number().int().min(200).max(60000).optional() },
    (a) => readGuidanceSection(a));
  platform('guided_workflows', 'List guided workflows (action list) or render one with your arguments filled in (action render). Returns a step plan of tool calls; it does not inspect targets or start analysis.',
    { action: z.enum(['list', 'render']).optional(), workflow: z.string().max(80).optional(), arguments: z.record(z.string(), z.union([z.string(), z.number(), z.boolean()])).optional() },
    async ({ action, workflow, arguments: args }) => {
      if (action !== 'render') return { workflows: WORKFLOWS.map((w) => ({ id: w.id, title: w.title, description: w.description, formats: w.formats, arguments: w.arguments, playbook: w.playbook ?? null })) };
      if (!workflow) throw new Error('workflow is required for action render');
      const r = renderWorkflow(workflow, args ?? {});
      if (!r.ok) return r;
      return { ...r.workflow, steps: r.workflow.steps.map((s) => ({ ...s, listed: visible.has(s.tool), exists: registry.has(s.tool) })) };
    });

  // ---------- progressive catalog ----------
  const getCatalog = () => (catalog ??= buildCatalogIndex([...registry.values()].map((r) => r.entry)));
  platform('discover_tools', 'Find the right tools for a goal ("recover endpoints from a bundle"), a file format ("apk") or a keyword ("dex"). Returns a small ranked list with each input contract. load: true also lists them for this session when the client hides tools.',
    { goal: z.string().max(2000).optional(), format: z.string().max(40).optional(), keyword: z.string().max(200).optional(), group: z.string().max(40).optional(), limit: z.number().int().min(1).max(40).optional(), load: z.boolean().optional() },
    async (a) => {
      if (!a.goal && !a.format && !a.keyword && !a.group) return { groups: groupSummary(), hint: 'Give goal, format, keyword or group.' };
      const r = discover(getCatalog(), a, visible);
      const loaded: string[] = [];
      if (a.load) for (const t of r.tools) {
        const x = registry.get(t.name);
        if (x && !visible.has(t.name)) { visible.add(t.name); x.tool.enable(); loaded.push(t.name); }
      }
      return {
        query: r.query, unknownTerms: r.unknownTerms, profile,
        tools: r.tools.map((t) => ({ name: t.name, group: t.group, score: t.score, description: t.description.slice(0, 300), effects: t.effects, listed: t.listed || loaded.includes(t.name), contract: contractSummary(t.inputSchema), example: exampleFor(t.inputSchema) })),
        loaded,
        next: profile === 'full' ? 'Call a tool by name.' : 'Call a tool by name if listed, or through call_tool { name, arguments } in any case.',
      };
    });
  platform('inspect_input_contract', 'Full JSON schema of a tool input plus a working example and its effects (reads, writes, runs programs, network).',
    { name: z.string().min(1).max(80) },
    async ({ name }) => {
      const r = registry.get(name);
      if (!r) { const near = discover(getCatalog(), { keyword: name.slice(0, 20), limit: 5 }).tools.map((t) => t.name); return { found: false, name: name.slice(0, 80), suggestions: near }; }
      return { found: true, name, group: r.entry.group, aliasOf: r.entry.aliasOf ?? null, description: r.entry.description, effects: r.entry.effects, listed: visible.has(name), inputSchema: r.entry.inputSchema, example: exampleFor(r.entry.inputSchema), summary: contractSummary(r.entry.inputSchema) };
    });
  platform('call_tool', 'Call any RevLens tool by name with its arguments, including tools this session does not list. The arguments are checked against the tool input contract first.',
    { name: z.string().min(1).max(80), arguments: z.record(z.string(), z.unknown()).optional() },
    async ({ name, arguments: args }) => {
      if (name === 'call_tool') throw new Error('call_tool cannot call itself');
      const r = registry.get(name);
      if (!r) throw new Error(`unknown tool "${name.slice(0, 80)}". Use discover_tools to find one.`);
      const parsed = z.object(r.shape).safeParse(args ?? {});
      if (!parsed.success) throw new Error(`arguments do not match ${name}: ${parsed.error.issues.slice(0, 8).map((i) => `${i.path.join('.') || '(root)'} ${i.message}`).join('; ')}. See inspect_input_contract { name: "${name}" }.`);
      return r.handler(parsed.data as Record<string, unknown>);
    });
  function groupSummary() {
    const by = new Map<string, number>();
    for (const r of registry.values()) by.set(r.entry.group, (by.get(r.entry.group) ?? 0) + 1);
    return [...by].map(([id, n]) => ({ id, tools: n, title: TOOL_MANIFEST.groups.find((g) => g.id === id)?.title ?? (id === 'core' ? 'Core triage and evidence' : id === 'platform' ? 'Guidance, catalog and settings' : id) }));
  }
  platform('capabilities', 'What this RevLens server can do: formats with playbooks, tool groups with counts, effects, profiles, settings and transports. Reads nothing from disk.', {},
    async () => {
      const list = [...registry.values()];
      return {
        version: SERVER_VERSION, profile, profiles: TOOL_PROFILES, listedTools: visible.size, totalTools: list.length,
        groups: groupSummary(),
        effects: { readOnly: list.filter((r) => !r.entry.effects.writes && !r.entry.effects.executes && !r.entry.effects.network).length, writes: list.filter((r) => r.entry.effects.writes).length, executes: list.filter((r) => r.entry.effects.executes).length, network: list.filter((r) => r.entry.effects.network).length },
        formats: [...new Set(TOOL_MANIFEST.analyzers.map((a) => a.package))].map((p) => ({ package: p, analyzers: TOOL_MANIFEST.analyzers.filter((a) => a.package === p).length })),
        playbookFormats: Object.keys(FORMAT_PLAYBOOKS), workflows: WORKFLOWS.map((w) => w.id),
        settings: SETTING_DEFS.map((d) => d.id), transports: ['stdio', 'streamable-http'], engineLoaded: engineLoaded(),
      };
    });
  platform('providers', 'Analysis providers: the built in RevLens packages (always present, no install) and the external tools RevLens can bridge to (radare2, rizin, Cutter, Ghidra, jadx, JEB, IDA and more) with versions, paths and install hints.',
    { includeBridges: z.boolean().optional().describe('probe external tools (default true)'), refresh: z.boolean().optional() },
    async ({ includeBridges, refresh }) => {
      const internal = TOOL_MANIFEST.packages.map((p) => ({ id: p.id, npm: p.npm, title: p.title, summary: p.summary, analyzers: p.analyzers.length, tools: TOOL_MANIFEST.tools.filter((t) => t.group === p.id).length, available: true }));
      if (includeBridges === false) return { internal };
      const eng = await loadEngine();
      const bridges = await import('@revlens/bridges/node');
      const inv = await bridges.inventory({ refresh: refresh === true });
      const jeb = 'detectJeb' in bridges ? await (bridges as unknown as { detectJeb: () => Promise<unknown> }).detectJeb() : undefined;
      void eng;
      return { internal, external: inv, ...(jeb ? { jeb } : {}) };
    });

  // ---------- settings ----------
  platform('inspect_analysis_settings', 'This session\'s analysis settings: file and output caps, time budgets, which analyzers run, execution and network policy. Shows value, launch value, default, bounds and where each came from.',
    { settings: z.array(z.string().max(40)).max(40).optional() },
    async (a) => settings.inspect(a));
  platform('update_analysis_settings', 'Change this session\'s analysis settings atomically (set or reset each). Applies to new calls only. expectedRevision guards against races; persist: true also saves to the settings file.',
    { changes: z.array(z.object({ setting: z.string().max(40), action: z.enum(['set', 'reset']).optional(), value: z.union([z.number(), z.boolean(), z.string(), z.array(z.string())]).optional() })).min(1).max(40), expectedRevision: z.number().int().min(0).optional(), persist: z.boolean().optional() },
    async (a) => { try { return settings.update(a); } catch (e) { if (e instanceof SettingsError) return { ok: false, inputError: true, error: e.message }; throw e; } });

  // ---------- resources ----------
  server.registerResource('analyzers', 'revlens://analyzers', { title: 'RevLens analyzers', description: 'Every analyzer across core and the packages, with what it reads.', mimeType: 'application/json' },
    async (uri) => ({ contents: [{ uri: uri.href, mimeType: 'application/json', text: toJson(TOOL_MANIFEST.analyzers) }] }));
  server.registerResource('tools', 'revlens://tools', { title: 'RevLens tools by area', description: 'Tool names grouped by area, with whether each one only reads.', mimeType: 'application/json' },
    async (uri) => ({ contents: [{ uri: uri.href, mimeType: 'application/json', text: toJson(tools.map((t) => ({ name: t.name, group: t.group, readOnly: t.annotations.readOnlyHint, listed: visible.has(t.name) }))) }] }));
  server.registerResource('guidance', 'revlens://guidance', { title: 'RevLens guidance overview', description: 'How to work, playbooks per format, guided workflows and docs pages.', mimeType: 'application/json' },
    async (uri) => ({ contents: [{ uri: uri.href, mimeType: 'application/json', text: toJson(await guidance({})) }] }));

  // ---------- prompts ----------
  server.registerPrompt('triage_file', {
    title: 'Triage a file',
    description: 'Walk through a first look at an unknown file: format, risk, behavior, then the right deep tools, with evidence for every claim.',
    argsSchema: { path: z.string().describe('Path to the file') },
  }, ({ path }) => ({ messages: [{ role: 'user', content: { type: 'text', text: [
    `Reverse engineer the file at ${path} with the RevLens tools.`,
    '1. Call analyze_file. Note the format, hashes, hardening, components and the top findings.',
    '2. Follow the "next" hint for the format: disasm_* for native code, managed_* for .NET, Python, Lua, BEAM and EVM, mobile_* for APK, DEX, class and IPA, web_* for JavaScript, Electron, PCAP, SQLite and HAR. guidance { format } has the playbook and discover_tools { format } the short tool list.',
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

  server.registerPrompt('guided_workflow', {
    title: 'Follow a guided workflow',
    description: 'Render one of the guided workflows (see guided_workflows) as instructions for the agent.',
    argsSchema: { workflow: z.string().describe(`one of ${WORKFLOWS.map((w) => w.id).join(', ')}`), path: z.string().optional().describe('path to the target, when the workflow takes one') },
  }, ({ workflow, path }) => {
    const r = renderWorkflow(workflow, path ? { path } : {});
    const body = r.ok ? [`${r.workflow.title}: ${r.workflow.description}`, ...r.workflow.steps.map((s, i) => `${i + 1}. ${s.tool} ${s.input ? JSON.stringify(s.input) : ''} (${s.why})`), `Deliver: ${r.workflow.deliverable}`].join('\n') : `${r.error}. Known workflows: ${r.known.join(', ')}`;
    return { messages: [{ role: 'user', content: { type: 'text', text: body } }] };
  });

  if (process.env.REVLENS_MCP_PRELOAD === '1') void loadEngine().then(reconcile, () => undefined);
  return { server, tools, settings, profile };
}

/** Tool names and groups without starting a server. */
export function toolCatalog(opts: ServerOptions = {}): ToolInfo[] { return createServer(opts).tools; }
