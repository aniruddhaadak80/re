import type { ChangeSet, Component, DiffReport, Finding, Report, Section } from './types.js';

function setDiff<T>(a: T[], b: T[], key: (x: T) => string): ChangeSet<T> {
  const ka = new Map(a.map((x) => [key(x), x])), kb = new Map(b.map((x) => [key(x), x]));
  return { added: [...kb].filter(([k]) => !ka.has(k)).map(([, v]) => v), removed: [...ka].filter(([k]) => !kb.has(k)).map(([, v]) => v) };
}

function flat(r: Report): Report[] { return [r, ...(r.children ?? []).flatMap(flat)]; }

interface Surface { urls?: string[]; apiPaths?: string[]; graphql?: string[]; ipc?: string[] }

/** Compare two reports, for example two releases of the same app, and say what changed. */
export function diff(a: Report, b: Report): DiffReport {
  const all = (r: Report) => flat(r);
  const comps = (r: Report) => all(r).flatMap((x) => x.components);
  const imports = (r: Report) => [...new Set(all(r).flatMap((x) => x.imports.flatMap((i) => i.symbols.map((s) => `${i.library}!${s}`))))];
  const exports = (r: Report) => [...new Set(all(r).flatMap((x) => x.exports))];
  const endpoints = (r: Report) => [...new Set(all(r).flatMap((x) => {
    const s = (x.meta.surface ?? {}) as Surface;
    return [...(s.urls ?? []), ...(s.apiPaths ?? []), ...(s.graphql ?? []), ...(s.ipc ?? []).map((c) => `ipc:${c}`)];
  }))];
  const tagged = (r: Report) => [...new Set(all(r).flatMap((x) => x.strings.filter((s) => s.tag && s.tag !== 'version').map((s) => s.value)))];
  const caps = (r: Report) => [...new Set(all(r).flatMap((x) => x.capabilities.map((c) => c.name)))];

  // Components: same name with a different version counts as changed.
  const ca = comps(a), cb = comps(b);
  const byName = (l: Component[]) => new Map(l.map((c) => [c.name, c]));
  const na = byName(ca), nb = byName(cb);
  const components: ChangeSet<Component> = { added: [], removed: [], changed: [] };
  for (const [n, c] of nb) { const old = na.get(n); if (!old) components.added.push(c); else if (old.version !== c.version) components.changed!.push({ before: old, after: c }); }
  for (const [n, c] of na) if (!nb.has(n)) components.removed.push(c);

  const sections: ChangeSet<Section> = setDiff(a.sections, b.sections, (s) => s.name);
  sections.changed = a.sections.flatMap((s) => {
    const t = b.sections.find((x) => x.name === s.name);
    return t && (Math.abs(t.size - s.size) > 0 || Math.abs(t.entropy - s.entropy) > 0.5) ? [{ before: s, after: t }] : [];
  });
  const findings: ChangeSet<Finding> = setDiff(all(a).flatMap((x) => x.findings), all(b).flatMap((x) => x.findings), (f) => f.id.replace(/\.\d+(@|$)/, '$1'));

  const d: DiffReport = {
    schema: 'revlens/diff@1',
    a: { name: a.file.name, sha256: a.file.hashes.sha256, format: a.file.format },
    b: { name: b.file.name, sha256: b.file.hashes.sha256, format: b.file.format },
    components,
    imports: setDiff(imports(a), imports(b), (x) => x),
    exports: setDiff(exports(a), exports(b), (x) => x),
    endpoints: setDiff(endpoints(a), endpoints(b), (x) => x),
    strings: setDiff(tagged(a), tagged(b), (x) => x),
    sections, findings,
    capabilities: setDiff(caps(a), caps(b), (x) => x),
    summary: '',
  };
  const parts: string[] = [];
  const n = (c: ChangeSet<unknown>, label: string) => { const k = c.added.length + c.removed.length + (c.changed?.length ?? 0); if (k) parts.push(`${k} ${k === 1 ? label.replace('changes', 'change') : label}`); };
  n(d.components, 'dependency changes'); n(d.endpoints, 'endpoint changes'); n(d.imports, 'import changes'); n(d.exports, 'export changes');
  n(d.capabilities, 'capability changes'); n(d.findings, 'finding changes'); n(d.sections, 'section changes');
  d.summary = a.file.hashes.sha256 === b.file.hashes.sha256 ? 'The two files are byte for byte identical.' :
    parts.length ? `Between ${a.file.name} and ${b.file.name}: ${parts.join(', ')}.` : 'The files differ in bytes but not in anything RevLens tracks.';
  return d;
}
