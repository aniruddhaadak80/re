#!/usr/bin/env node
// RevLens MCP server. Small, focused tool set with compact outputs so agents keep
// their context window for thinking. Every answer cites offsets you can verify.
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { readFileSync, openSync, fstatSync, closeSync } from 'node:fs';
import { basename, resolve } from 'node:path';
import {
  analyze, diff, verifyClaim, scanRules, STARTER_RULES, toCycloneDX, toMarkdown, lookupOSV, ANALYZERS, REVLENS_VERSION,
  type Report, type Claim,
} from '@revlens/core';

const MAX_FILE = Number(process.env.REVLENS_MAX_FILE_MB ?? 256) * 1024 * 1024;
const cache = new Map<string, { mtime: number; bytes: Uint8Array; report: Report }>();

/** Opens the file once and checks and reads that same descriptor, so it cannot be swapped in between. */
function readFile(path: string): { bytes: Uint8Array; abs: string; mtime: number } {
  const abs = resolve(path);
  const fd = openSync(abs, 'r');
  try {
    const st = fstatSync(fd);
    if (!st.isFile()) throw new Error(`${abs} is not a regular file`);
    if (st.size > MAX_FILE) throw new Error(`${abs} is larger than ${MAX_FILE} bytes. Raise REVLENS_MAX_FILE_MB to allow it.`);
    return { bytes: new Uint8Array(readFileSync(fd)), abs, mtime: st.mtimeMs };
  } finally { closeSync(fd); }
}

async function reportFor(path: string, rules?: string): Promise<{ report: Report; bytes: Uint8Array }> {
  const { bytes, abs, mtime } = readFile(path);
  const key = abs + (rules ? `#${rules.length}` : '');
  const hit = cache.get(key);
  if (hit && hit.mtime === mtime) return hit;
  const report = await analyze(bytes, { name: basename(abs), rules });
  const entry = { mtime, bytes, report };
  cache.set(key, entry);
  if (cache.size > 32) cache.delete(cache.keys().next().value as string);
  return entry;
}

const text = (v: unknown) => ({ content: [{ type: 'text' as const, text: typeof v === 'string' ? v : JSON.stringify(v, null, 1) }] });
const fail = (e: unknown) => ({ isError: true, content: [{ type: 'text' as const, text: `RevLens error: ${(e as Error).message}` }] });
const wrap = <A,>(fn: (a: A) => Promise<ReturnType<typeof text>>) => async (a: A) => { try { return await fn(a); } catch (e) { return fail(e); } };

function overview(r: Report) {
  return {
    file: r.file, hardening: r.hardening, sections: r.sections.length, importLibraries: r.imports.map((i) => `${i.library} (${i.symbols.length})`).slice(0, 30),
    exports: r.exports.length, components: r.components.slice(0, 40).map((c) => `${c.name}${c.version ? '@' + c.version : ''}`),
    capabilities: r.capabilities.map((c) => `${c.name}${c.attack ? ` [${c.attack}]` : ''}`),
    findings: r.findings.slice(0, 25).map((f) => ({ severity: f.severity, title: f.title, where: f.evidence[0] })),
    findingTotals: Object.fromEntries(['critical', 'high', 'medium', 'low', 'info'].map((s) => [s, r.findings.filter((f) => f.severity === s).length])),
    members: r.meta.memberCount, timingsMs: r.timings.total,
    next: 'Use list_findings, get_strings, get_imports, get_sections, sbom, check_vulns, scan_rules, hexdump or verify_claim to go deeper.',
  };
}

const server = new McpServer({ name: 'revlens', version: REVLENS_VERSION });
const P = { path: z.string().describe('Absolute or relative path to a local file') };

server.tool('analyze_file', 'Triage any local file (ELF, PE, Mach-O, WASM, JS bundle, source map, npm tgz, ZIP/JAR/APK, CRX/XPI/VSIX, ASAR). Returns format, hashes, hardening, components, capabilities and top findings with offsets.',
  { ...P, rules: z.string().optional().describe('Extra yara-lite rule text') },
  wrap(async ({ path, rules }) => text(overview((await reportFor(path, rules)).report))));

server.tool('list_findings', 'All findings for a file, optionally filtered by minimum severity or analyzer id.',
  { ...P, minSeverity: z.enum(['info', 'low', 'medium', 'high', 'critical']).optional(), analyzer: z.string().optional(), limit: z.number().int().min(1).max(500).optional() },
  wrap(async ({ path, minSeverity, analyzer, limit }) => {
    const order = ['info', 'low', 'medium', 'high', 'critical'];
    const min = order.indexOf(minSeverity ?? 'info');
    const list = (await reportFor(path)).report.findings.filter((f) => order.indexOf(f.severity) >= min && (!analyzer || f.analyzer === analyzer));
    return text(list.slice(0, limit ?? 100));
  }));

server.tool('get_strings', 'Interesting strings with offsets. Filter by tag (url, ip, email, path, registry, command, guid, version) or a substring.',
  { ...P, tag: z.string().optional(), contains: z.string().optional(), limit: z.number().int().min(1).max(2000).optional() },
  wrap(async ({ path, tag, contains, limit }) => {
    const s = (await reportFor(path)).report.strings.filter((x) => (!tag || x.tag === tag) && (!contains || x.value.toLowerCase().includes(contains.toLowerCase())));
    return text(s.slice(0, limit ?? 150).map((x) => `${x.offset}\t${x.kind}\t${x.tag ?? ''}\t${x.value.slice(0, 300)}`).join('\n') || 'no matching strings');
  }));

server.tool('get_sections', 'Sections or segments with file offsets, virtual addresses, sizes and entropy.', P,
  wrap(async ({ path }) => text((await reportFor(path)).report.sections)));

server.tool('get_imports', 'Imported libraries and symbols, plus exports. Optional substring filter.',
  { ...P, contains: z.string().optional() },
  wrap(async ({ path, contains }) => {
    const r = (await reportFor(path)).report;
    const q = contains?.toLowerCase();
    return text({
      imports: r.imports.map((i) => ({ library: i.library, symbols: q ? i.symbols.filter((s) => s.toLowerCase().includes(q)) : i.symbols.slice(0, 400) })).filter((i) => i.symbols.length),
      exports: (q ? r.exports.filter((e) => e.toLowerCase().includes(q)) : r.exports).slice(0, 400),
    });
  }));

server.tool('sbom', 'Software bill of materials. format "list" is compact, "cyclonedx" is a CycloneDX 1.5 document.',
  { ...P, format: z.enum(['list', 'cyclonedx']).optional() },
  wrap(async ({ path, format }) => {
    const r = (await reportFor(path)).report;
    if (format === 'cyclonedx') return text(toCycloneDX(r));
    return text(r.components.map((c) => `${c.name}\t${c.version ?? '?'}\t${c.ecosystem}\t${Math.round(c.confidence * 100)}%\t${c.purl ?? ''}`).join('\n') || 'no components detected');
  }));

server.tool('check_vulns', 'Look up known vulnerabilities (CVE, GHSA) for detected components on OSV.dev. This makes a network request.', P,
  wrap(async ({ path }) => {
    const r = (await reportFor(path)).report;
    const v = await lookupOSV([r, ...(r.children ?? [])].flatMap((x) => x.components));
    return text(v.length ? v.map((f) => ({ severity: f.severity, title: f.title, detail: f.detail })) : 'No known vulnerabilities for components with a detected version.');
  }));

server.tool('scan_rules', 'Run yara-lite rules (a YARA subset) against a file. The starter pack runs unless includeStarter is false.',
  { ...P, rules: z.string().optional(), includeStarter: z.boolean().optional() },
  wrap(async ({ path, rules, includeStarter }) => {
    const { bytes } = readFile(path);
    return text(scanRules(bytes, (includeStarter === false ? '' : STARTER_RULES) + '\n' + (rules ?? '')));
  }));

server.tool('diff_files', 'Compare two versions of a file or package: dependencies, endpoints, imports, exports, capabilities, sections and findings.',
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
server.tool('verify_claim', 'Check claims about a file against its bytes before you rely on them. Returns VERIFIED, REFUTED or UNKNOWN with evidence for each claim.',
  { ...P, claims: z.array(claimSchema).min(1).max(50) },
  wrap(async ({ path, claims }) => {
    const { report, bytes } = await reportFor(path);
    return text(claims.map((c) => verifyClaim(bytes, c as Claim, report)));
  }));

server.tool('hexdump', 'Hex and ASCII view of a byte range, to inspect evidence offsets.',
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

server.tool('report_markdown', 'The full report as Markdown, good for writing up results.', P,
  wrap(async ({ path }) => text(toMarkdown((await reportFor(path)).report))));

server.tool('list_analyzers', 'What RevLens can analyze, one line per analyzer.', {},
  wrap(async () => text(ANALYZERS.map((a) => `${a.id}: ${a.description}`).join('\n'))));

await server.connect(new StdioServerTransport());
