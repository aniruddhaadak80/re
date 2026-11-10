#!/usr/bin/env node
// RevLens self scan: analyze the code this repo ships (the built CLI, MCP server and web app
// bundles) and write one SARIF 2.1.0 file for GitHub code scanning. Only findings at or above
// the minimum severity are kept, so the Security tab shows real issues and not triage notes.
//
// Known self matches (RevLens ships its own signatures and a suspicious demo) are listed with
// a reason in .github/revlens-baseline.json and left out of the upload. The log shows them.
//
// Usage: node scripts/self-scan.mjs [--out revlens.sarif] [--min medium] [--baseline file] [dir ...]
import { readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const repo = resolve(fileURLToPath(new URL('..', import.meta.url)));
const core = await import(new URL('../packages/core/dist/index.js', import.meta.url).href);

const args = process.argv.slice(2);
const opt = (name, def) => { const i = args.indexOf(name); if (i < 0) return def; const v = args[i + 1]; args.splice(i, 2); return v; };
const out = opt('--out', 'revlens.sarif');
const min = opt('--min', 'medium');
const baselinePath = opt('--baseline', join(repo, '.github', 'revlens-baseline.json'));
const glob = (g) => new RegExp('^' + g.split('*').map((x) => x.replace(/[.+?^${}()|[\]\\]/g, '\\$&')).join('[^/]*') + '$');
const baseline = (baselinePath === 'none' ? [] : JSON.parse(readFileSync(baselinePath, 'utf8')).entries)
  .map((e) => ({ files: e.files.map(glob), rules: new Set(e.rules), reason: e.reason }));
const baselined = (uri, ruleId) => baseline.find((e) => e.rules.has(ruleId) && e.files.some((re) => re.test(uri)));
const ORDER = ['info', 'low', 'medium', 'high', 'critical'];
if (!ORDER.includes(min)) throw new Error(`--min must be one of ${ORDER.join(', ')}`);
const dirs = args.length ? args : ['packages/cli/dist', 'packages/mcp/dist', 'apps/web/dist'];
const SCAN = /\.(?:m?js|cjs|wasm|json|webmanifest)$/i;

function* walk(dir) {
  for (const name of readdirSync(dir).sort()) {
    const p = join(dir, name);
    const st = statSync(p);
    if (st.isDirectory()) yield* walk(p);
    else if (st.isFile() && SCAN.test(name)) yield p;
  }
}

const rules = new Map();
const results = [];
const artifacts = [];
let files = 0;
let kept = 0;
let dropped = 0;
const suppressed = [];
for (const d of dirs) {
  const abs = resolve(repo, d);
  try { statSync(abs); } catch { throw new Error(`${d} does not exist. Run the builds first.`); }
  for (const file of walk(abs)) {
    const uri = relative(repo, file).split(sep).join('/');
    const report = await core.analyze(new Uint8Array(readFileSync(file)), { name: uri });
    const run = core.toSARIF(report).runs[0];
    files++;
    for (const r of run.results) {
      const sev = r.properties?.severity ?? 'info';
      if (ORDER.indexOf(sev) < ORDER.indexOf(min)) { dropped++; continue; }
      const loc = r.locations?.[0]?.physicalLocation?.artifactLocation;
      if (loc && !loc.uri.includes('/')) loc.uri = uri;
      const b = baselined(loc?.uri ?? uri, r.ruleId);
      if (b) { suppressed.push(`${sev}\t${r.ruleId}\t${loc?.uri ?? uri}\t${b.reason}`); continue; }
      results.push(r);
      kept++;
      const rule = run.tool.driver.rules.find((x) => x.id === r.ruleId);
      if (rule && !rules.has(rule.id)) rules.set(rule.id, rule);
    }
    artifacts.push(...run.artifacts);
  }
}

const sarif = {
  $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
  version: '2.1.0',
  runs: [{
    tool: { driver: { name: 'RevLens', version: core.REVLENS_VERSION, informationUri: 'https://github.com/aniruddhaadak80/re', rules: [...rules.values()] } },
    results,
    artifacts,
  }],
};
writeFileSync(out, JSON.stringify(sarif, null, 2));
console.log(`[self-scan] ${files} files, ${kept + suppressed.length} findings at ${min} or higher, ${suppressed.length} of them known self matches, ${dropped} below ${min}. Uploading ${results.length}. Wrote ${out}`);
for (const line of suppressed) console.log(`  baseline\t${line}`);
for (const r of results) console.log(`  report\t${r.properties?.severity}\t${r.ruleId}\t${r.locations?.[0]?.physicalLocation?.artifactLocation?.uri}\t${r.message.text.slice(0, 140)}`);
