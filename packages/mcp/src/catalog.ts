// Progressive tool catalog: rank tools by goal, format or keyword with a small BM25 index over tool
// names and descriptions, describe each tool's input contract as JSON schema with an example, and
// define the minimal, standard and full tool profiles.
import { buildIndex, searchIndex, tokenize, type Bm25Index, type GuidanceSection } from './guidance/bm25.js';

export type ToolProfile = 'minimal' | 'standard' | 'full';
export const TOOL_PROFILES: ToolProfile[] = ['minimal', 'standard', 'full'];

/** Tools every profile lists: triage, evidence, and the way to reach everything else. */
export const MINIMAL_TOOLS = [
  'analyze_file', 'list_findings', 'get_strings', 'get_imports', 'hexdump', 'verify_claim',
  'discover_tools', 'inspect_input_contract', 'call_tool', 'guidance', 'search_guidance', 'inspect_analysis_settings',
];

/** The standard profile adds the rest of the core and platform tools and the most used tool of each area. */
export const STANDARD_EXTRA = [
  'get_sections', 'sbom', 'check_vulns', 'scan_rules', 'diff_files', 'report_markdown', 'list_analyzers',
  'read_guidance_section', 'guided_workflows', 'capabilities', 'providers', 'update_analysis_settings',
  'disasm_info', 'disasm_list_functions', 'disasm_function', 'disasm_pseudocode', 'disasm_xrefs', 'disasm_call_paths',
  'mobile_apk_report', 'mobile_manifest', 'mobile_dex_classes', 'mobile_dex_method', 'mobile_dex_search', 'mobile_ipa_info',
  'managed_dotnet_info', 'managed_dotnet_types', 'managed_dotnet_method_il', 'managed_pyc_disasm', 'managed_pyinstaller_list',
  'web_js_endpoints', 'web_bundle_modules', 'web_js_deobfuscate', 'web_electron_audit', 'web_asar_list', 'web_pcap_summary', 'web_pcap_flows', 'web_sqlite_query',
  'x_checksec', 'x_pe_inspect', 'x_elf_inspect', 'x_macho_inspect', 'x_firmware_scan', 'x_demangle',
  'bridge_doctor', 'bridge_r2_decompile', 'bridge_ghidra_decompile', 'list_cutter_sessions',
];

/** Names visible at startup for a profile. Unknown names are ignored. */
export function profileTools(profile: ToolProfile, all: string[]): Set<string> {
  if (profile === 'full') return new Set(all);
  const want = profile === 'minimal' ? MINIMAL_TOOLS : [...MINIMAL_TOOLS, ...STANDARD_EXTRA];
  const have = new Set(all);
  return new Set(want.filter((n) => have.has(n)));
}

export function parseProfile(v: unknown): ToolProfile {
  const s = typeof v === 'string' ? v.trim().toLowerCase() : '';
  if (!s) return 'full';
  if ((TOOL_PROFILES as string[]).includes(s)) return s as ToolProfile;
  throw new Error(`unknown tool profile "${s.slice(0, 40)}". Use minimal, standard or full.`);
}

/** Read --tool-profile <p> or --tool-profile=<p> from argv, then REVLENS_TOOL_PROFILE. */
export function profileFromArgv(argv: string[], env: NodeJS.ProcessEnv = process.env): ToolProfile {
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (a === '--tool-profile') return parseProfile(argv[i + 1]);
    if (a.startsWith('--tool-profile=')) return parseProfile(a.slice('--tool-profile='.length));
  }
  return parseProfile(env.REVLENS_TOOL_PROFILE);
}

export interface CatalogEntry {
  name: string;
  group: string;
  description: string;
  /** JSON schema of the input object */
  inputSchema: JsonSchema;
  effects: { writes?: boolean; network?: boolean; executes?: boolean };
  /** alias of another tool, for compatibility names */
  aliasOf?: string;
}

export interface JsonSchema { type: 'object'; properties: Record<string, Record<string, unknown>>; required: string[]; additionalProperties?: boolean; [k: string]: unknown }

/** Words that tie formats to the tools that read them, so a format query finds the right area. */
const FORMAT_WORDS: Record<string, string> = {
  elf: 'elf linux native disasm x_elf x_checksec bridge_r2 ghidra', pe: 'pe windows exe dll native disasm x_pe authenticode resources', macho: 'macho mach apple macos native disasm x_macho swift',
  'macho-fat': 'macho fat universal disasm x_macho', apk: 'apk android dex manifest mobile jadx apktool adb', dex: 'dex android mobile smali', aab: 'apk android mobile', jar: 'jar java class mobile',
  class: 'java class mobile', ipa: 'ipa ios iphone mobile plist entitlement', dotnet: 'dotnet net assembly cil il managed ilspy pinvoke', pyc: 'python pyc bytecode pyinstaller managed',
  python: 'python pyc pyinstaller managed', js: 'javascript js bundle web endpoint deobfuscate sourcemap', sourcemap: 'sourcemap source map web', asar: 'asar electron web',
  electron: 'electron asar web', firmware: 'firmware uimage squashfs container x_firmware binwalk', pcap: 'pcap capture network flow web_pcap', pcapng: 'pcap capture network flow web_pcap',
  sqlite: 'sqlite database web_sqlite', har: 'har browser web_har', wasm: 'wasm webassembly', lua: 'lua managed', beam: 'beam erlang managed', evm: 'evm ethereum solidity managed',
};

export interface CatalogIndex { entries: CatalogEntry[]; index: Bm25Index }

/** Index tool names, groups and descriptions. */
export function buildCatalogIndex(entries: CatalogEntry[]): CatalogIndex {
  const docs: GuidanceSection[] = entries.map((e) => ({
    id: e.name, file: e.group, title: `${e.name} ${e.name.replace(/_/g, ' ')}`, path: [e.group], level: 2, hash: '',
    text: `${e.description} ${Object.keys(e.inputSchema.properties).join(' ')}`,
  }));
  return { entries, index: buildIndex(docs) };
}

export interface DiscoverInput { goal?: string; format?: string; keyword?: string; group?: string; limit?: number; includeHidden?: boolean }

/**
 * Rank tools for a goal, a format, a keyword, or any mix. A keyword that is a tool name (or its prefix)
 * matches by name first. Returns at most `limit` tools (default 8, max 40) with their input contracts.
 */
export function discover(cat: CatalogIndex, input: DiscoverInput, visible?: Set<string>): { query: string; tools: (CatalogEntry & { score: number; matched: string[]; listed: boolean })[]; unknownTerms: string[] } {
  const limit = Math.max(1, Math.min(Math.floor(Number(input.limit) || 8), 40));
  const fmt = typeof input.format === 'string' ? input.format.trim().toLowerCase().replace(/^\./, '') : '';
  const kw = typeof input.keyword === 'string' ? input.keyword.trim().toLowerCase().slice(0, 200) : '';
  const goal = typeof input.goal === 'string' ? input.goal.slice(0, 2000) : '';
  const query = [goal, kw, fmt ? (FORMAT_WORDS[fmt] ?? fmt) : ''].filter(Boolean).join(' ');
  const groupOk = (e: CatalogEntry) => !input.group || e.group === input.group;
  const exact = kw ? cat.entries.filter((e) => groupOk(e) && (e.name === kw || e.name.startsWith(kw))) : [];
  const scored = new Map<string, { score: number; matched: string[] }>();
  for (const e of exact) scored.set(e.name, { score: e.name === kw ? 1000 : 500, matched: [kw] });
  let unknown: string[] = [];
  if (query.trim()) {
    const r = searchIndex(cat.index, query, { limit: 200, filter: (i) => groupOk(cat.entries[i]!) });
    unknown = r.unknown;
    for (const h of r.hits) {
      const e = cat.entries[h.index]!;
      const prev = scored.get(e.name);
      // format words name areas; a tool whose own name holds a format word gets a lift
      const fmtLift = fmt && tokenize(e.name).some((t) => (FORMAT_WORDS[fmt] ?? fmt).includes(t)) ? 2 : 0;
      scored.set(e.name, { score: (prev?.score ?? 0) + h.score + fmtLift + h.matched.length, matched: [...new Set([...(prev?.matched ?? []), ...h.matched])] });
    }
  } else if (!exact.length && input.group) {
    for (const e of cat.entries.filter(groupOk)) scored.set(e.name, { score: 1, matched: [] });
  }
  const byName = new Map(cat.entries.map((e) => [e.name, e]));
  const tools = [...scored]
    .map(([name, s]) => ({ ...byName.get(name)!, score: Math.round(s.score * 1000) / 1000, matched: s.matched, listed: visible ? visible.has(name) : true }))
    .filter((t) => !t.aliasOf || input.includeHidden)
    .sort((a, b) => b.score - a.score || a.name.localeCompare(b.name))
    .slice(0, limit);
  return { query: query.slice(0, 300), tools, unknownTerms: unknown };
}

/** JSON schema for a package tool input spec. */
export function specToJsonSchema(spec: Record<string, { type: string; description: string; optional?: boolean }>): JsonSchema {
  const properties: Record<string, Record<string, unknown>> = {};
  const required: string[] = [];
  for (const [k, p] of Object.entries(spec)) {
    const s: Record<string, unknown> = { description: p.description };
    if (p.type === 'array') { s.type = 'array'; s.items = { type: ['string', 'number', 'boolean'] }; }
    else if (p.type === 'object') { s.type = 'object'; s.additionalProperties = true; }
    else s.type = p.type;
    properties[k] = s;
    if (!p.optional) required.push(k);
  }
  return { type: 'object', properties, required, additionalProperties: false };
}

/** A short contract summary: required and optional fields with types. */
export function contractSummary(schema: JsonSchema): { required: string[]; optional: string[] } {
  const fmt = (k: string) => {
    const p = schema.properties[k] ?? {};
    const t = Array.isArray(p.type) ? p.type.join('|') : (p.type as string | undefined) ?? (p.enum ? 'enum' : p.anyOf || p.oneOf ? 'union' : 'any');
    return `${k}: ${t}`;
  };
  const req = new Set(schema.required ?? []);
  return { required: [...req].map(fmt), optional: Object.keys(schema.properties).filter((k) => !req.has(k)).map(fmt) };
}

const SAMPLE: Record<string, unknown> = {
  path: '/path/to/target.bin', before: '/path/to/old.bin', after: '/path/to/new.bin', a: '/path/to/old.bin', b: '/path/to/new.bin',
  function: 'main', target: 'main', address: '0x401000', query: 'password', contains: 'http', filter: 'main', pattern: 'secret',
  limit: 20, offset: 0, length: 256, minSeverity: 'medium', format: 'list', engine: 'auto', analysis: 'aa', outDir: '/tmp/revlens-out',
  namespace: 'App', className: 'com.example.MainActivity', class: 'com.example.MainActivity', method: 'onCreate', sql: 'select name from sqlite_master',
  sessionId: 's1', session: '1234', command: 'afl', allowExecution: true, timeoutMs: 60000, settings: ['maxFileMB'], name: 'analyze_file',
  goal: 'find network endpoints', keyword: 'disasm', topic: 'getting-started', id: 'playbooks/elf.md#first-pass', action: 'list', workflow: 'triage_unknown_file',
};

/** A plausible example value for one JSON schema node. */
function exampleValue(key: string, p: Record<string, unknown>, depth: number): unknown {
  if (depth > 6) return null;
  if (p.const !== undefined) return p.const;
  if (Array.isArray(p.enum)) return p.enum[0];
  const alt = (p.oneOf ?? p.anyOf) as Record<string, unknown>[] | undefined;
  if (Array.isArray(alt) && alt.length) return exampleValue(key, alt.find((x) => x.type !== 'null') ?? alt[0]!, depth + 1);
  const t = Array.isArray(p.type) ? p.type[0] : p.type;
  const sample = SAMPLE[key];
  if (t === 'array') {
    if (Array.isArray(sample)) return sample;
    const items = (p.items ?? {}) as Record<string, unknown>;
    if (items.type === 'object' || items.oneOf || items.anyOf || items.properties) return [exampleValue(key, items, depth + 1)];
    return [typeof sample === 'string' ? sample : 'main'];
  }
  if (t === 'number' || t === 'integer') return typeof sample === 'number' ? sample : typeof p.minimum === 'number' ? p.minimum : 1;
  if (t === 'boolean') return typeof sample === 'boolean' ? sample : false;
  if (t === 'object' || p.properties) {
    const props = (p.properties ?? {}) as Record<string, Record<string, unknown>>;
    const out: Record<string, unknown> = {};
    for (const k of (p.required as string[] | undefined) ?? []) if (props[k]) out[k] = exampleValue(k, props[k]!, depth + 1);
    return out;
  }
  return sample ?? `<${key}>`;
}

/** A plausible example input for a schema: required fields only, typed from the schema. */
export function exampleFor(schema: JsonSchema): Record<string, unknown> {
  return exampleValue('', schema as unknown as Record<string, unknown>, 0) as Record<string, unknown>;
}
