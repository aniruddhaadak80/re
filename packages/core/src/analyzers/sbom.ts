import type { Analyzer, Component, Evidence } from '../types.js';

/**
 * Identify open source packages inside minified bundles. Sources of truth, best first:
 * 1. package.json files (in archives)
 * 2. license and banner comments like "/*! react-dom v18.3.1 | MIT *\/" or "@license React v18.3.1"
 * 3. webpack / vite / rollup module paths "node_modules/<name>/"
 * 4. well known runtime version constants (React.version, jQuery.fn.jquery, Vue.version, lodash VERSION)
 */
const BANNERS: RegExp[] = [
  /\/\*[!*]\s*(?:@license\s+)?([@a-z0-9][\w.\/-]{1,60}?)\s+v?(\d+\.\d+\.\d+(?:-[\w.]+)?)\b/gi,
  /@license\s+([A-Za-z][\w.\/ -]{1,40}?)\s+v?(\d+\.\d+\.\d+(?:-[\w.]+)?)/g,
  /\*\s+([@a-z0-9][\w.\/-]{1,60})\s+-\s+v?(\d+\.\d+\.\d+)\b/gi,
];
const KNOWN: { name: string; re: RegExp }[] = [
  { name: 'react', re: /\.version\s*=\s*["'](1[6-9]\.\d+\.\d+)["'][^;]{0,60}(?:ReactCurrentOwner|__SECRET_INTERNALS|react)/ },
  { name: 'react-dom', re: /reconcilerVersion\s*:\s*["'](\d+\.\d+\.\d+)["']/ },
  { name: 'jquery', re: /jquery\s*[:=]\s*["'](\d+\.\d+\.\d+)["']/ },
  { name: 'lodash', re: /var\s+VERSION\s*=\s*["'](4\.\d+\.\d+)["']/ },
  { name: 'vue', re: /version\s*:\s*["'](\d\.\d+\.\d+)["'][^;]{0,80}(?:compile|createApp|nextTick)/ },
  { name: 'angular', re: /new\s+\w+\(["'](1[0-9]\.\d+\.\d+)["']\)[^;]{0,40}VERSION|full:\s*["'](\d+\.\d+\.\d+)["']/ },
  { name: 'moment', re: /hooks\.version\s*=\s*["'](2\.\d+\.\d+)["']/ },
  { name: 'axios', re: /VERSION\s*=\s*["'](\d+\.\d+\.\d+)["'][^;]{0,200}axios/ },
  { name: 'core-js', re: /core-js[^"']{0,40}["']?version["']?\s*:\s*["'](3\.\d+\.\d+)["']/ },
];
const NM_PATH = /node_modules\/((?:@[\w.-]+\/)?[\w.-]+)\//g;

export function purl(name: string, version?: string): string {
  const n = name.startsWith('@') ? `%40${name.slice(1)}` : name;
  return `pkg:npm/${n}${version ? `@${version}` : ''}`;
}

function add(list: Component[], name: string, version: string | undefined, confidence: number, ev: Evidence) {
  name = name.trim().toLowerCase().replace(/\.js$/, '').replace(/\s+/g, '-');
  if (!/^(@[\w.-]+\/)?[\w.-]{1,214}$/.test(name) || /^\d/.test(name) || ['v', 'version', 'license', 'copyright'].includes(name)) return;
  const existing = list.find((c) => c.name === name && (c.version === version || !c.version || !version));
  if (existing) {
    if (!existing.version && version) { existing.version = version; existing.purl = purl(name, version); }
    existing.confidence = Math.max(existing.confidence, confidence);
    if (existing.evidence.length < 3) existing.evidence.push(ev);
    return;
  }
  list.push({ name, version, ecosystem: 'npm', purl: purl(name, version), confidence, evidence: [ev] });
}

export const bundleSbomAnalyzer: Analyzer = {
  id: 'sbom',
  title: 'Bundle SBOM',
  description: 'Finds npm packages and versions inside minified JavaScript bundles and package.json files, with purl ids for CycloneDX.',
  applies: (ctx) => ctx.format === 'js' || ctx.format === 'json',
  run(ctx) {
    const text = ctx.text ?? '';
    const comps = ctx.report.components;
    if (ctx.format === 'json') {
      if (!/package\.json$/.test(ctx.name)) return;
      try {
        const p = JSON.parse(text) as { name?: string; version?: string; dependencies?: Record<string, string> };
        if (p.name) add(comps, p.name, p.version, 1, { path: ctx.name, snippet: `${p.name}@${p.version}` });
        for (const [d, v] of Object.entries(p.dependencies ?? {})) {
          comps.push({ name: d, version: v.replace(/^[\^~>=<\s]+/, '') || undefined, ecosystem: 'npm', purl: purl(d), confidence: 0.5,
            evidence: [{ path: ctx.name, snippet: `dependency ${d}: ${v}` }] });
        }
      } catch { /* not a package.json */ }
      return;
    }
    const head = text.length > 8_000_000 ? text.slice(0, 8_000_000) : text;
    for (const re of BANNERS) {
      re.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = re.exec(head)) && comps.length < 500) add(comps, m[1] as string, m[2], 0.9, { offset: m.index, length: m[0].length, snippet: m[0].slice(0, 100) });
    }
    for (const k of KNOWN) {
      const m = k.re.exec(head);
      if (m) add(comps, k.name, (m[1] ?? m[2]) as string, 0.75, { offset: m.index, length: Math.min(m[0].length, 100), snippet: m[0].slice(0, 100) });
    }
    NM_PATH.lastIndex = 0;
    let m: RegExpExecArray | null;
    let n = 0;
    while ((m = NM_PATH.exec(head)) && n++ < 5000) add(comps, m[1] as string, undefined, 0.6, { offset: m.index, snippet: m[0] });

    const bundler = /__webpack_require__|webpackChunk/.test(head) ? 'webpack' : /import\.meta\.env|__vite__|vite\/preload/.test(head) ? 'vite' :
      /__esbuild|esbuild/.test(head.slice(0, 5000)) ? 'esbuild' : /System\.register/.test(head) ? 'systemjs' : /define\.amd/.test(head) && /typeof exports/.test(head) ? 'umd' : /define\.amd/.test(head) ? 'amd' : /parcelRequire/.test(head) ? 'parcel' : undefined;
    if (bundler) ctx.report.meta.bundler = bundler;
  },
};
