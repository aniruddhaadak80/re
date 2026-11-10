import type { Analyzer } from '../types.js';

interface SourceMap { version?: number; sources?: string[]; sourcesContent?: (string | null)[]; mappings?: string; file?: string }

export const sourcemapAnalyzer: Analyzer = {
  id: 'sourcemap',
  title: 'Source maps',
  description: 'Detects source map references and inline maps, and reports how much original source can be rebuilt from sourcesContent.',
  applies: (ctx) => ctx.format === 'js' || ctx.format === 'sourcemap',
  run(ctx) {
    const { report } = ctx;
    const text = ctx.text ?? '';

    const parseMap = (json: string, origin: string) => {
      let map: SourceMap;
      try { map = JSON.parse(json) as SourceMap; } catch { return; }
      if (!map.sources) return;
      const sources = map.sources;
      const withContent = (map.sourcesContent ?? []).filter((c) => typeof c === 'string' && c.length > 0).length;
      const coverage = sources.length ? Math.round((withContent / sources.length) * 100) : 0;
      report.meta.sourcemap = { origin, sources: sources.length, withContent, coverage, file: map.file, tree: sources.slice(0, 500) };
      report.findings.push({
        id: 'sourcemap.present', analyzer: 'sourcemap', title: `Source map recovers ${coverage}% of original sources`, severity: coverage > 0 ? 'medium' : 'info',
        detail: `A source map lists ${sources.length} original files${withContent ? `, and ${withContent} of them include full original code in sourcesContent` : ', but without embedded original code'}. ${coverage > 0 ? 'The original project tree can be rebuilt from this map.' : ''} Shipping maps to production exposes source and structure.`,
        evidence: [{ snippet: origin }], tags: ['sourcemap'],
      });
    };

    if (ctx.format === 'sourcemap') { parseMap(text, ctx.name); return; }

    const m = /[#@]\s*sourceMappingURL=([^\s'"]+)/.exec(text);
    if (!m) return;
    const url = m[1] as string;
    if (url.startsWith('data:')) {
      const b64 = url.slice(url.indexOf(',') + 1);
      try {
        const bin = atob(b64);
        const json = new TextDecoder().decode(Uint8Array.from(bin, (c) => c.charCodeAt(0)));
        parseMap(json, 'inline data URI');
      } catch { /* bad base64 */ }
    } else {
      report.findings.push({
        id: 'sourcemap.ref', analyzer: 'sourcemap', title: 'References an external source map', severity: 'low',
        detail: `The bundle points to a source map at "${url}". If that file is published, the original source can be rebuilt. Fetch it alongside the bundle to recover the tree.`,
        evidence: [{ offset: m.index, snippet: url }], tags: ['sourcemap'],
      });
      report.meta.sourcemapUrl = url;
    }
  },
};
