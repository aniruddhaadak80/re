// Map what ran (a semantic trace, a Node inspector report, or scenario coverage) back to static bundle
// modules and original sources: each runtime script is matched to a local bundle by SHA-256, then by
// file name, then by length; each traced location or covered function offset is placed in the bundle
// module that contains it and, through the source map, in the original file and line. Modules that
// never ran are listed as cold. Browser safe.
import { unpackBundle, type BundleModule } from './js/bundle.js';
import { SourceMapIndex, parseSourceMap, inlineSourceMap, type RawSourceMap } from './sourcemap.js';
import { sourceKey } from './js/imports.js';
import { lineIndex, sha256Hex, InputError } from './util.js';

export interface LocalBundle { name: string; code: string; sourceMap?: string | RawSourceMap }
interface RuntimeScript { url: string; sha256?: string; length?: number; scriptId?: string }
interface RuntimeLocation { url: string; line: number; column: number; label: string; event?: number; count?: number }

export interface ReconciledModule { id: string; path?: string; size: number; enter: number; exit: number; requests: number; timers: number; covered: number; functions: string[] }
export interface ReconciledScript {
  url: string;
  bundle?: string;
  matchedBy?: 'sha256' | 'name' | 'length';
  bundler?: string;
  modules: ReconciledModule[];
  coldModules: { id: string; path?: string }[];
  locations: { label: string; line: number; column: number; module?: string; original?: { source: string; line: number; column: number; name?: string } }[];
}
export interface Reconciliation { scripts: ReconciledScript[]; unmatchedScripts: string[]; unusedBundles: string[]; summary: { scripts: number; matched: number; locations: number; placed: number; mappedToSource: number }; warnings: string[] }

const STACK_TAIL = /^(.*?) (\S*):(\d{1,9}):(\d{1,9})$/;

function baseName(u: string): string { try { return new URL(u).pathname.split('/').pop() ?? u; } catch { return u.split(/[\\/]/).pop() ?? u; } }

/** Pull scripts and code locations out of a trace, an inspector report or a scenario capture. */
function collect(runtime: any): { scripts: RuntimeScript[]; locations: RuntimeLocation[]; offsets: { url: string; offset: number; label: string; count: number }[] } {
  const scripts: RuntimeScript[] = [];
  const locations: RuntimeLocation[] = [];
  const offsets: { url: string; offset: number; label: string; count: number }[] = [];
  for (const s of (Array.isArray(runtime?.scripts) ? runtime.scripts : []).slice(0, 10_000)) if (s && typeof s.url === 'string') scripts.push({ url: s.url, sha256: s.sha256, length: typeof s.length === 'number' ? s.length : typeof s.size === 'number' ? s.size : undefined, scriptId: s.scriptId });
  for (const e of (Array.isArray(runtime?.events) ? runtime.events : []).slice(0, 200_000)) {
    if ((e.kind === 'enter' || e.kind === 'exit') && e.location?.url) locations.push({ url: e.location.url, line: e.location.line, column: e.location.column, label: `${e.kind} ${e.fn}`, event: e.seq });
    else if ((e.kind === 'request' || e.kind === 'timer') && Array.isArray(e.stack) && e.stack[0]) {
      const m = STACK_TAIL.exec(String(e.stack[0]));
      if (m) locations.push({ url: m[2]!, line: Number(m[3]), column: Math.max(0, Number(m[4]) - 1), label: e.kind === 'request' ? `request ${e.request?.url ?? ''}` : `timer ${e.timer}`, event: e.seq });
    }
  }
  // Node inspector report: calls with offsets; scenario capture: coverage per script
  for (const c of (Array.isArray(runtime?.calls) ? runtime.calls : []).slice(0, 100_000)) if (typeof c.url === 'string' && typeof c.offset === 'number') offsets.push({ url: c.url, offset: c.offset, label: `call ${c.name}`, count: Number(c.count ?? 1) });
  for (const s of (Array.isArray(runtime?.coverage?.scripts) ? runtime.coverage.scripts : []).slice(0, 5000)) {
    if (!scripts.some((x) => x.url === s.url)) scripts.push({ url: s.url });
    for (const f of (s.top ?? []).slice(0, 10_000)) offsets.push({ url: s.url, offset: f.offset, label: `call ${f.name}`, count: f.count });
  }
  for (const u of new Set([...locations.map((l) => l.url), ...offsets.map((o) => o.url)])) if (!scripts.some((s) => s.url === u)) scripts.push({ url: u });
  return { scripts, locations, offsets };
}

/** Reconcile runtime observations with local bundles (and their source maps). */
export function reconcileJavaScriptRuntime(runtime: unknown, bundles: LocalBundle[], opts: { limit?: number } = {}): Reconciliation {
  if (!bundles.length) throw new InputError('give at least one local bundle');
  const { scripts, locations, offsets } = collect(runtime);
  const warnings: string[] = [];
  const prepared = bundles.slice(0, 200).map((b) => ({ ...b, sha: sha256Hex(b.code), base: baseName(b.name) }));
  const used = new Set<string>();
  const out: ReconciledScript[] = [];
  const unmatched: string[] = [];
  let placed = 0, mapped = 0;
  const lim = Math.max(1, Math.min(opts.limit ?? 2000, 50_000));
  for (const s of scripts) {
    let hit = s.sha256 ? prepared.find((b) => b.sha === s.sha256) : undefined;
    let by: ReconciledScript['matchedBy'] = hit ? 'sha256' : undefined;
    if (!hit) { hit = prepared.find((b) => b.base === baseName(s.url)); if (hit) by = 'name'; }
    if (!hit && s.length) { hit = prepared.find((b) => b.code.length === s.length); if (hit) by = 'length'; }
    const locs = locations.filter((l) => l.url === s.url);
    const offs = offsets.filter((o) => o.url === s.url);
    if (!hit) { if (locs.length || offs.length) unmatched.push(s.url); continue; }
    if (by === 'name' && s.sha256 && s.sha256 !== hit.sha) warnings.push(`${s.url}: matched ${hit.name} by name but the content differs (sha256)`);
    used.add(hit.name);
    let modules: BundleModule[] = [];
    let bundler: string | undefined;
    let map: RawSourceMap | undefined;
    try { map = hit.sourceMap ? parseSourceMap(hit.sourceMap) : inlineSourceMap(hit.code); } catch { warnings.push(`${hit.name}: source map not usable`); }
    try { const u = unpackBundle(hit.code, { sourceMap: map }); modules = u.modules; bundler = u.bundler; } catch (e) { warnings.push(`${hit.name}: ${(e as Error).message.slice(0, 120)}`); }
    // a plain script or an ESM chunk without a registry is one module
    if (!modules.length) modules = [{ id: '<file>', path: hit.name, start: 0, end: hit.code.length, line: 1, size: hit.code.length, deps: [], exports: [] }];
    let idx: SourceMapIndex | undefined;
    try { if (map) idx = new SourceMapIndex(map); } catch { idx = undefined; }
    const pos = lineIndex(hit.code);
    // line starts for line/column to offset
    const starts: number[] = [0];
    for (let i = 0; i < hit.code.length; i++) if (hit.code.charCodeAt(i) === 10) starts.push(i + 1);
    const offsetOf = (line: number, col: number) => (starts[line - 1] ?? hit.code.length) + col;
    const stats = new Map<string, ReconciledModule>(modules.map((m) => [m.id, { id: m.id, path: m.path, size: m.size, enter: 0, exit: 0, requests: 0, timers: 0, covered: 0, functions: [] }]));
    const moduleAt = (off: number) => { let best: BundleModule | undefined; for (const m of modules) if (off >= m.start && off < m.end && (!best || m.size < best.size)) best = m; return best; };
    const rs: ReconciledScript = { url: s.url, bundle: hit.name, matchedBy: by, bundler, modules: [], coldModules: [], locations: [] };
    for (const l of locs) {
      const m = moduleAt(offsetOf(l.line, l.column));
      const o = idx?.originalPositionFor(l.line, l.column);
      if (m) {
        placed++;
        const st = stats.get(m.id)!;
        const kind = l.label.split(' ')[0];
        if (kind === 'enter') { st.enter++; const fn = l.label.slice(6); if (!st.functions.includes(fn) && st.functions.length < 100) st.functions.push(fn); }
        else if (kind === 'exit') st.exit++;
        else if (kind === 'request') st.requests++;
        else if (kind === 'timer') st.timers++;
      }
      if (o?.source) mapped++;
      if (rs.locations.length < lim) rs.locations.push({ label: l.label, line: l.line, column: l.column, module: m ? (m.path ?? m.id) : undefined, original: o?.source && o.line !== undefined ? { source: sourceKey(o.source, map?.sourceRoot), line: o.line, column: o.column ?? 0, name: o.name } : undefined });
    }
    for (const o of offs) {
      const m = moduleAt(o.offset);
      const p = pos(o.offset);
      const orig = idx?.originalPositionFor(p.line, p.column);
      if (m) { placed++; const st = stats.get(m.id)!; st.covered += o.count; const fn = o.label.slice(5); if (fn && !st.functions.includes(fn) && st.functions.length < 100) st.functions.push(fn); }
      if (orig?.source) mapped++;
      if (rs.locations.length < lim) rs.locations.push({ label: o.label, line: p.line, column: p.column, module: m ? (m.path ?? m.id) : undefined, original: orig?.source && orig.line !== undefined ? { source: sourceKey(orig.source, map?.sourceRoot), line: orig.line, column: orig.column ?? 0, name: orig.name } : undefined });
    }
    rs.modules = [...stats.values()].filter((m) => m.enter || m.exit || m.requests || m.timers || m.covered).sort((a, b) => (b.enter + b.covered + b.requests) - (a.enter + a.covered + a.requests));
    rs.coldModules = [...stats.values()].filter((m) => !(m.enter || m.exit || m.requests || m.timers || m.covered)).map((m) => ({ id: m.id, path: m.path })).slice(0, lim);
    out.push(rs);
  }
  const total = locations.length + offsets.length;
  return { scripts: out, unmatchedScripts: unmatched.slice(0, 1000), unusedBundles: prepared.filter((b) => !used.has(b.name)).map((b) => b.name), summary: { scripts: scripts.length, matched: out.length, locations: total, placed, mappedToSource: mapped }, warnings };
}
