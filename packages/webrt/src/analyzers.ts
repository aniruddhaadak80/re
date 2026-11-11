// RevLens Analyzer objects for the formats this package owns. Structured output goes under report.meta.webrt.
import type { Analyzer, AnalyzerContext, Finding } from '@revlens/core';
import { findEndpoints } from './js/endpoints.js';
import { unpackBundle } from './js/bundle.js';
import { deobfuscate } from './js/deobfuscate.js';
import { recoverSources } from './sourcemap.js';
import { auditAsar } from './electron.js';
import { isAsar } from './asar.js';
import { analyzePcap, isPcap, linkTypeName } from './pcap.js';
import { SqliteFile, isSqlite } from './sqlite.js';
import { analyzeHar, looksLikeHar } from './har.js';
import { decodeUtf8 } from './util.js';

const MAX_JS = 8 * 1024 * 1024;

function meta(ctx: AnalyzerContext): Record<string, unknown> {
  const m = (ctx.report.meta.webrt ??= {}) as Record<string, unknown>;
  return m;
}
function textOf(ctx: AnalyzerContext): string { return ctx.text ?? decodeUtf8(ctx.bytes); }
function err(ctx: AnalyzerContext, key: string, e: unknown) { meta(ctx)[`${key}Error`] = (e as Error).message?.slice(0, 300) ?? String(e); }

/** Heuristic: share of identifiers that look like javascript-obfuscator names. */
export function obfuscationScore(code: string): number {
  const sample = code.slice(0, 500_000);
  const hex = sample.match(/\b_0x[0-9a-f]{4,6}\b/g)?.length ?? 0;
  const idents = sample.match(/\b[A-Za-z_$][\w$]*\b/g)?.length ?? 1;
  return Math.min(1, hex / Math.max(1, idents) * 3);
}

export const webJsAnalyzer: Analyzer = {
  id: 'webrt-js',
  title: 'JavaScript endpoints, bundles and obfuscation',
  description: 'Finds network endpoints, eval and Function use, env names and feature flags; splits webpack, browserify and esbuild bundles into modules; detects and statically decodes javascript-obfuscator string arrays.',
  applies: (ctx) => ctx.format === 'js' && ctx.bytes.length <= MAX_JS,
  run(ctx) {
    const code = textOf(ctx);
    const out: Record<string, unknown> = {};
    try {
      const ep = findEndpoints(code, { maxItems: 1000 });
      out.endpoints = { calls: ep.calls.slice(0, 300), urls: ep.urls.slice(0, 300), hosts: ep.hosts, envNames: ep.envNames, featureFlags: ep.featureFlags.slice(0, 200), dynamicCode: ep.dynamicCode.slice(0, 100), storageKeys: ep.storageKeys.slice(0, 100), counts: ep.counts };
      if (ep.dynamicCode.length) ctx.report.findings.push({ id: 'webrt.js.dynamic-code', analyzer: 'webrt-js', title: `Dynamic code execution (${[...new Set(ep.dynamicCode.map((d) => d.api))].join(', ')})`, severity: 'medium', detail: 'The script builds code from strings at run time. This defeats static review and is a common way to hide payloads or open injection bugs.', evidence: ep.dynamicCode.slice(0, 10).map((d) => ({ offset: d.offset, snippet: `line ${d.line}: ${d.api}${d.argument ? `(${d.argument.slice(0, 80)})` : ''}` })), tags: ['javascript'], attack: ['T1059.007'] });
      if (ep.hosts.length) ctx.report.findings.push({ id: 'webrt.js.hosts', analyzer: 'webrt-js', title: `Contacts ${ep.hosts.length} host${ep.hosts.length === 1 ? '' : 's'}`, severity: 'info', detail: `Hosts referenced by network calls or URL literals: ${ep.hosts.slice(0, 30).join(', ')}.`, evidence: ep.urls.slice(0, 10).map((u) => ({ offset: u.offset, snippet: u.value.slice(0, 120) })), tags: ['network'] });
    } catch (e) { err(ctx, 'endpoints', e); }
    try {
      const b = unpackBundle(code);
      if (b.bundler !== 'unknown') out.bundle = { bundler: b.bundler, confidence: b.confidence, moduleCount: b.modules.length, chunkIds: b.chunkIds, entryIds: b.entryIds, modules: b.modules.slice(0, 500).map(({ code: _c, ...m }) => m), imports: b.imports.slice(0, 200), runtime: b.runtime };
    } catch (e) { err(ctx, 'bundle', e); }
    const score = obfuscationScore(code);
    out.obfuscationScore = Math.round(score * 100) / 100;
    if (score > 0.2 && code.length <= 2 * 1024 * 1024) {
      try {
        const d = deobfuscate(code);
        out.deobfuscation = { stringArray: d.stringArray, stats: d.stats, decodedStrings: d.decodedStrings.slice(0, 200), notes: d.notes };
        const f: Finding = { id: 'webrt.js.obfuscated', analyzer: 'webrt-js', title: d.stringArray ? `Obfuscated with a string array (${d.stringArray.encoding}, ${d.stringArray.length} strings)` : 'Code looks obfuscated', severity: 'medium', detail: d.stringArray ? `Strings are hidden in array ${d.stringArray.arrayName} and decoded through ${d.stringArray.decoderName} (${d.stringArray.wrappers} wrappers, array rotated ${d.stringArray.rotated} times). RevLens decoded ${d.stats.stringsDecoded} call sites statically; run web_js_deobfuscate for the readable code.` : 'Identifier names follow the javascript-obfuscator _0x pattern.', evidence: d.decodedStrings.slice(0, 10).map((s) => ({ snippet: s.slice(0, 120) })), tags: ['javascript', 'obfuscation'], attack: ['T1027'] };
        ctx.report.findings.push(f);
      } catch (e) { err(ctx, 'deobfuscate', e); }
    }
    meta(ctx).js = out;
  },
};

export const webSourcemapAnalyzer: Analyzer = {
  id: 'webrt-sourcemap',
  title: 'Source map recovery',
  description: 'Lists the original source tree a source map can rebuild, grouped by top level folder and package.',
  applies: (ctx) => ctx.format === 'sourcemap',
  run(ctx) {
    try {
      const r = recoverSources(textOf(ctx));
      meta(ctx).sourcemap = { sources: r.sources, withContent: r.withContent, coverage: r.coverage, mappings: r.mappings, tree: r.tree, files: r.files.slice(0, 1000).map((f) => ({ path: f.path, size: f.size })), missing: r.missing.slice(0, 200) };
    } catch (e) { err(ctx, 'sourcemap', e); }
  },
};

export const webElectronAnalyzer: Analyzer = {
  id: 'webrt-electron',
  title: 'Electron app audit',
  description: 'Reads an ASAR archive and reviews main and preload code for unsafe webPreferences, exposed bridges, IPC channels, openExternal, protocols and update feeds.',
  applies: (ctx) => ctx.format === 'asar' || isAsar(ctx.bytes),
  run(ctx) {
    try {
      const a = auditAsar(ctx.bytes);
      ctx.report.findings.push(...a.findings);
      const { findings: _f, ...rest } = a;
      meta(ctx).electron = rest;
    } catch (e) { err(ctx, 'electron', e); }
  },
};

export const webPcapAnalyzer: Analyzer = {
  id: 'webrt-pcap',
  title: 'Packet capture',
  description: 'Parses PCAP and PCAPNG: flows, DNS, HTTP/1.x, TLS SNI and JA3.',
  applies: (ctx) => isPcap(ctx.bytes),
  run(ctx) {
    try {
      const r = analyzePcap(ctx.bytes, { maxRecords: 2000 });
      meta(ctx).pcap = { format: r.format, linkTypes: r.linkTypes.map(linkTypeName), packetCount: r.packetCount, totalBytes: r.totalBytes, durationSeconds: r.durationSeconds, protocols: r.protocols, topTalkers: r.topTalkers, topPorts: r.topPorts, flowCount: r.flows.length, flows: r.flows.slice(0, 200), dns: r.dns.slice(0, 200), http: r.http.slice(0, 200), tls: r.tls.slice(0, 200), tlsServer: r.tlsServer.slice(0, 200), warnings: r.warnings };
      const plain = r.http.filter((h) => h.kind === 'request' && /authorization|cookie/i.test(Object.keys(h.headers).join(' ')));
      if (plain.length) ctx.report.findings.push({ id: 'webrt.pcap.cleartext-auth', analyzer: 'webrt-pcap', title: 'Credentials or cookies sent over cleartext HTTP', severity: 'high', detail: `${plain.length} HTTP requests carry Authorization or Cookie headers without TLS.`, evidence: plain.slice(0, 10).map((h) => ({ snippet: `packet ${h.packet}: ${h.method} ${h.host ?? ''}${h.target}` })), tags: ['network'] });
      const names = [...new Set([...r.dns.flatMap((d) => d.questions.map((q) => q.name)), ...r.tls.map((t) => t.sni).filter((x): x is string => !!x)])];
      if (names.length) ctx.report.findings.push({ id: 'webrt.pcap.names', analyzer: 'webrt-pcap', title: `${names.length} domain names in DNS and TLS SNI`, severity: 'info', detail: names.slice(0, 50).join(', '), evidence: [], tags: ['network'] });
    } catch (e) { err(ctx, 'pcap', e); }
  },
};

export const webSqliteAnalyzer: Analyzer = {
  id: 'webrt-sqlite',
  title: 'SQLite database',
  description: 'Reads the schema, row counts and column names of a SQLite 3 file without running SQLite.',
  applies: (ctx) => isSqlite(ctx.bytes),
  run(ctx) {
    try {
      const db = new SqliteFile(ctx.bytes);
      const tables = db.tables();
      meta(ctx).sqlite = { header: db.header, tables: tables.map((t) => ({ name: t.name, rows: t.rowCount, columns: t.columns, withoutRowid: t.withoutRowid, indexes: t.indexes, error: t.error })), objects: db.schema().map((o) => ({ type: o.type, name: o.name, table: o.tblName })) };
      const sensitive = tables.flatMap((t) => t.columns.filter((c) => /pass(word)?|secret|token|api_?key|session|cookie|credit|card|ssn/i.test(c.name)).map((c) => `${t.name}.${c.name}`));
      if (sensitive.length) ctx.report.findings.push({ id: 'webrt.sqlite.sensitive-columns', analyzer: 'webrt-sqlite', title: 'Database has columns that may hold secrets', severity: 'low', detail: sensitive.slice(0, 50).join(', '), evidence: [], tags: ['data'] });
    } catch (e) { err(ctx, 'sqlite', e); }
  },
};

export const webHarAnalyzer: Analyzer = {
  id: 'webrt-har',
  title: 'HAR traffic log',
  description: 'Summarizes hosts, API endpoints, redirects, auth schemes, cookies and missing security headers in a HAR file.',
  applies: (ctx) => (ctx.format === 'har' || ctx.format === 'json' || ctx.format === 'text' || ctx.name.toLowerCase().endsWith('.har')) && looksLikeHar(textOf(ctx).slice(0, 4096)),
  run(ctx) {
    try {
      const s = analyzeHar(textOf(ctx), { maxScripts: 20 });
      meta(ctx).har = s;
      if (s.mixedContent.length) ctx.report.findings.push({ id: 'webrt.har.mixed-content', analyzer: 'webrt-har', title: `${s.mixedContent.length} requests over HTTP from an HTTPS page`, severity: 'medium', detail: 'Mixed content can be modified by a network attacker.', evidence: s.mixedContent.slice(0, 10).map((m) => ({ snippet: m.url })), tags: ['network'] });
    } catch (e) { err(ctx, 'har', e); }
  },
};

export const ANALYZERS: Analyzer[] = [webJsAnalyzer, webSourcemapAnalyzer, webElectronAnalyzer, webPcapAnalyzer, webSqliteAnalyzer, webHarAnalyzer];
