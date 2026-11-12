// Guidance access for the MCP server: overview, per-format playbooks, BM25 search and section reads over
// the bundle that scripts/build-guidance.mjs generates from docs/. The bundle is parsed on first use only.
import { searchIndex, type GuidanceBundle, type GuidanceSection } from './bm25.js';
import { WORKFLOWS } from './workflows.js';

let bundle: GuidanceBundle | undefined;

/** The generated guidance bundle, parsed once. */
export async function loadGuidance(): Promise<GuidanceBundle> {
  if (bundle) return bundle;
  const { GUIDANCE_JSON } = await import('../generated/guidance-data.js');
  bundle = JSON.parse(GUIDANCE_JSON) as GuidanceBundle;
  return bundle;
}

/** Format id (as analyze_file reports it, or a common name) to playbook file. */
export const FORMAT_PLAYBOOKS: Record<string, string> = {
  elf: 'playbooks/elf.md', so: 'playbooks/elf.md', linux: 'playbooks/elf.md',
  pe: 'playbooks/pe.md', exe: 'playbooks/pe.md', dll: 'playbooks/pe.md', windows: 'playbooks/pe.md',
  macho: 'playbooks/macho.md', 'macho-fat': 'playbooks/macho.md', 'mach-o': 'playbooks/macho.md', dylib: 'playbooks/macho.md', macos: 'playbooks/macho.md',
  apk: 'playbooks/apk.md', aab: 'playbooks/apk.md', dex: 'playbooks/apk.md', android: 'playbooks/apk.md', jar: 'playbooks/apk.md', class: 'playbooks/apk.md',
  ipa: 'playbooks/ipa.md', ios: 'playbooks/ipa.md',
  dotnet: 'playbooks/dotnet.md', '.net': 'playbooks/dotnet.md', net: 'playbooks/dotnet.md', csharp: 'playbooks/dotnet.md',
  pyc: 'playbooks/python.md', python: 'playbooks/python.md', pyinstaller: 'playbooks/python.md',
  js: 'playbooks/js-bundle.md', javascript: 'playbooks/js-bundle.md', sourcemap: 'playbooks/js-bundle.md', 'js-bundle': 'playbooks/js-bundle.md', bundle: 'playbooks/js-bundle.md',
  asar: 'playbooks/electron.md', electron: 'playbooks/electron.md',
  firmware: 'playbooks/firmware.md', ihex: 'playbooks/firmware.md', srec: 'playbooks/firmware.md', uf2: 'playbooks/firmware.md', uimage: 'playbooks/firmware.md',
  pcap: 'playbooks/pcap.md', pcapng: 'playbooks/pcap.md', capture: 'playbooks/pcap.md',
};

const clip = (s: string, max: number) => (s.length > max ? `${s.slice(0, max)}\n[cut at ${max} of ${s.length} characters, read again with offset ${max}]` : s);

/** Whole page text from its sections, in order. */
function pageText(b: GuidanceBundle, file: string): string {
  return b.sections.filter((s) => s.file === file).map((s) => `${'#'.repeat(Math.max(1, s.level))} ${s.title}\n\n${s.text}`).join('\n\n');
}

/**
 * guidance tool: with no input an overview (how to work, playbooks, workflows, docs); with format a
 * playbook; with topic the best matching page.
 */
export async function guidance(input: { format?: string; topic?: string; maxChars?: number } = {}): Promise<unknown> {
  const b = await loadGuidance();
  const max = Math.max(500, Math.min(Number(input.maxChars) || 12_000, 60_000));
  if (typeof input.format === 'string' && input.format.trim()) {
    const key = input.format.trim().toLowerCase();
    const file = FORMAT_PLAYBOOKS[key] ?? FORMAT_PLAYBOOKS[key.replace(/^\./, '')];
    if (!file) return { found: false, format: key.slice(0, 40), known: Object.keys(FORMAT_PLAYBOOKS), hint: 'Try search_guidance with a few words about the file.' };
    return { found: true, format: key, playbook: file, workflows: WORKFLOWS.filter((w) => w.playbook === file).map((w) => w.id), text: clip(pageText(b, file), max) };
  }
  if (typeof input.topic === 'string' && input.topic.trim()) {
    const direct = b.files.find((f) => f.file === input.topic || f.file === `${input.topic}.md`);
    const file = direct?.file ?? (() => { const r = searchIndex(b.index, input.topic!, { limit: 1 }); return r.hits[0] ? b.sections[r.hits[0].index]!.file : undefined; })();
    if (!file) return { found: false, topic: input.topic.slice(0, 80), hint: 'No page matched. Call guidance with no input for the list of pages.' };
    return { found: true, page: file, text: clip(pageText(b, file), max) };
  }
  return {
    howToWork: [
      'Start with analyze_file on the target. It names the format and gives a "next" hint.',
      'Call discover_tools with that format (or a goal in plain words) to get a short ranked list of tools and their input contracts.',
      'Read the playbook for the format with guidance { format }. guided_workflows renders a step list with your arguments.',
      'Tools only read unless their annotations say otherwise. Tools that run programs need allowExecution: true and the session setting allowExecution.',
      'Check every claim with verify_claim or cite the offset, address or path that shows it.',
    ],
    playbooks: b.files.filter((f) => f.kind === 'playbook' && !f.file.endsWith('README.md')).map((f) => ({ file: f.file, title: f.title })),
    formats: [...new Set(Object.values(FORMAT_PLAYBOOKS))].map((file) => ({ file, formats: Object.entries(FORMAT_PLAYBOOKS).filter(([, v]) => v === file).map(([k]) => k) })),
    workflows: WORKFLOWS.map((w) => ({ id: w.id, title: w.title, formats: w.formats })),
    docs: b.files.filter((f) => f.kind === 'doc').map((f) => ({ file: f.file, title: f.title })),
  };
}

/** search_guidance: ranked sections with short snippets and locators for read_guidance_section. */
export async function searchGuidance(input: { query?: string; limit?: number; kind?: 'doc' | 'playbook'; requireAll?: boolean }): Promise<unknown> {
  const b = await loadGuidance();
  const query = typeof input.query === 'string' ? input.query : '';
  if (!query.trim()) return { ok: false, inputError: true, error: 'query is required' };
  const kinds = new Map(b.files.map((f) => [f.file, f.kind]));
  const filter = input.kind ? (i: number) => kinds.get(b.sections[i]!.file) === input.kind : undefined;
  const r = searchIndex(b.index, query, { limit: input.limit ?? 8, require: input.requireAll ? 'all' : 'any', filter });
  return {
    query: query.slice(0, 200), terms: r.terms, unknownTerms: r.unknown,
    results: r.hits.map((h) => {
      const s = b.sections[h.index]!;
      return { id: s.id, file: s.file, title: s.title, path: s.path, score: h.score, matched: h.matched, hash: s.hash, snippet: snippet(s, r.terms) };
    }),
    next: 'Read a result with read_guidance_section { id } (pass hash too to detect a changed section).',
  };
}

function snippet(s: GuidanceSection, terms: string[]): string {
  const lower = s.text.toLowerCase();
  let at = -1;
  for (const t of terms) { const i = lower.indexOf(t); if (i >= 0 && (at < 0 || i < at)) at = i; }
  const start = Math.max(0, at - 80);
  return (start ? '...' : '') + s.text.slice(start, start + 240).replace(/\s+/g, ' ').trim() + (s.text.length > start + 240 ? '...' : '');
}

/** read_guidance_section: one section (optionally with its sub sections), paged by characters. */
export async function readGuidanceSection(input: { id?: string; hash?: string; includeChildren?: boolean; offset?: number; maxChars?: number }): Promise<unknown> {
  const b = await loadGuidance();
  const id = typeof input.id === 'string' ? input.id : '';
  const i = b.sections.findIndex((s) => s.id === id);
  if (i < 0) {
    const file = id.split('#')[0];
    const near = b.sections.filter((s) => s.file === file).map((s) => s.id).slice(0, 40);
    return { ok: false, found: false, id: id.slice(0, 200), error: 'unknown section id', sectionsInFile: near, hint: 'Search again with search_guidance to get a current id.' };
  }
  const s = b.sections[i]!;
  const parts = [`${'#'.repeat(Math.max(1, s.level))} ${s.title}\n\n${s.text}`];
  const children: string[] = [];
  for (let j = i + 1; j < b.sections.length; j++) {
    const c = b.sections[j]!;
    if (c.file !== s.file || c.level <= s.level) break;
    children.push(c.id);
    if (input.includeChildren) parts.push(`${'#'.repeat(c.level)} ${c.title}\n\n${c.text}`);
  }
  const full = parts.join('\n\n');
  const offset = Math.max(0, Math.min(Number(input.offset) || 0, full.length));
  const max = Math.max(200, Math.min(Number(input.maxChars) || 8000, 60_000));
  const text = full.slice(offset, offset + max);
  return {
    ok: true, id: s.id, file: s.file, title: s.title, path: s.path, hash: s.hash,
    stale: typeof input.hash === 'string' && input.hash !== '' && input.hash !== s.hash,
    children, offset, totalChars: full.length, nextOffset: offset + text.length < full.length ? offset + text.length : null, text,
  };
}

/** Server instructions: a short guide every MCP client shows the model at connect time. */
export function serverInstructions(opts: { profile?: string; toolCount?: number; hidden?: number } = {}): string {
  const formats = 'ELF, PE, Mach-O, APK, IPA, .NET, Python, JavaScript bundles, Electron, firmware and pcap';
  const lines = [
    'RevLens reverse engineers local files and apps. Every answer cites offsets, addresses or paths you can check.',
    '1. Start with analyze_file on the target; it names the format and suggests next tools.',
    '2. Call discover_tools with a goal ("find network endpoints"), a format ("apk") or a keyword to get a short ranked tool list with input contracts. inspect_input_contract shows the full JSON schema and an example for any tool.',
    `3. Read the playbook for the format with guidance { format } (playbooks exist for ${formats}). search_guidance and read_guidance_section search all docs. guided_workflows renders a step plan.`,
    '4. inspect_analysis_settings shows this session\'s limits; update_analysis_settings changes them. allowExecution is off by default; tools that start programs need it on.',
    '5. Before you report a fact, check it with verify_claim or quote the evidence.',
  ];
  if (opts.profile && opts.profile !== 'full') lines.push(`This server runs the "${opts.profile}" tool profile${opts.toolCount ? ` with ${opts.toolCount} tools listed` : ''}${opts.hidden ? `; ${opts.hidden} more are reachable through discover_tools and call_tool` : ''}.`);
  return lines.join('\n');
}
