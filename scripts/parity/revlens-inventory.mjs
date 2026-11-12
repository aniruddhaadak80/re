#!/usr/bin/env node
// Build an exact inventory of RevLens from a built checkout (run `npm ci && npx tsc -b` first).
// Usage: node scripts/parity/revlens-inventory.mjs [--root .] [--out docs/parity/data/revlens-inventory.json]
//
// Live pass: starts the real MCP server in memory and calls tools/list through an MCP client, so the
// list is exactly what an agent sees (names, descriptions, JSON input schemas, annotations). It also
// reads TOOL_GROUPS (package TOOLS with their group), TOP_LEVEL_COMMANDS and every package CLI_COMMANDS,
// ALL_ANALYZERS_NODE and the core format ids.
// Static pass: core FormatId union from packages/core/src/types.ts, CLI options from
// packages/cli/src/index.ts, and every REVLENS_* environment variable used outside tests.
import { execFileSync } from 'node:child_process';
import { mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const args = process.argv.slice(2);
const opt = (name, dflt) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : dflt; };
const ROOT = resolve(opt('--root', '.'));
const OUT = resolve(opt('--out', 'docs/parity/data/revlens-inventory.json'));
const imp = (p) => import(pathToFileURL(join(ROOT, p)).href);

async function livePass() {
  const { createServer } = await imp('packages/mcp/dist/server.js');
  const { Client } = await imp('node_modules/@modelcontextprotocol/sdk/dist/esm/client/index.js');
  const { InMemoryTransport } = await imp('node_modules/@modelcontextprotocol/sdk/dist/esm/inMemory.js');
  const engine = await imp('packages/engine/dist/node.js');
  const { server, tools: infos } = createServer();
  const [a, b] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: 'parity-inventory', version: '1.0.0' });
  await Promise.all([server.connect(a), client.connect(b)]);
  const listed = [];
  let cursor;
  do {
    const page = await client.listTools(cursor ? { cursor } : {});
    listed.push(...page.tools);
    cursor = page.nextCursor;
  } while (cursor);
  const prompts = (await client.listPrompts().catch(() => ({ prompts: [] }))).prompts.map((p) => p.name);
  const resources = (await client.listResources().catch(() => ({ resources: [] }))).resources.map((r) => r.uri);
  const groupOf = new Map(infos.map((t) => [t.name, t.group]));
  const npmOf = new Map(engine.TOOL_GROUPS.map((g) => [g.id, g.npm]));
  npmOf.set('core', '@revlens/core');
  const tools = listed.map((t) => {
    const props = t.inputSchema?.properties ?? {};
    const req = new Set(t.inputSchema?.required ?? []);
    const group = groupOf.get(t.name) ?? null;
    return {
      name: t.name, group, package: npmOf.get(group) ?? null,
      description: t.description ?? '',
      annotations: t.annotations ?? null,
      inputs: Object.entries(props).map(([name, p]) => ({ name, type: p.type ?? (p.enum ? 'enum' : 'any'), enum: p.enum, required: req.has(name), description: p.description?.slice(0, 300) })),
    };
  });
  await client.close();
  const commands = [
    ...engine.TOP_LEVEL_COMMANDS.map((c) => ({ path: c.name, group: 'top', usage: c.usage, summary: c.summary })),
    ...engine.TOOL_GROUPS.flatMap((g) => g.commands.map((c) => ({ path: `${g.id} ${c.name}`, group: g.id, usage: c.usage, summary: c.summary }))),
  ];
  const analyzers = engine.ALL_ANALYZERS_NODE.map((x) => ({ id: x.id, package: x.package, title: x.title, description: x.description }));
  return { tools, prompts, resources, commands, analyzers, toolEffects: engine.TOOL_EFFECTS };
}

const isTest = (p) => /\.test\.ts$|\/test\/|\/dist\//.test(p);
function walk(dir, acc = [], depth = 0) {
  if (depth > 10) return acc;
  for (const name of readdirSync(dir)) {
    if (name === 'node_modules' || name === 'dist' || name.startsWith('.')) continue;
    const p = join(dir, name);
    const st = statSync(p);
    if (st.isDirectory()) walk(p, acc, depth + 1);
    else if (/\.(ts|tsx|mjs|js)$/.test(p)) acc.push(p);
  }
  return acc;
}

function staticPass() {
  const types = readFileSync(join(ROOT, 'packages/core/src/types.ts'), 'utf8');
  const fm = /export type FormatId\s*=([^;]+);/.exec(types);
  const formatIds = fm ? [...fm[1].matchAll(/'([^']+)'/g)].map((m) => m[1]) : [];
  const cli = readFileSync(join(ROOT, 'packages/cli/src/index.ts'), 'utf8');
  const oh = /const OPTIONS_HELP = `([\s\S]*?)`;/.exec(cli);
  const cliOptions = oh ? [...oh[1].matchAll(/(--[a-z][a-z-]*|-[a-z])\b/g)].map((m) => m[1]) : [];
  const coreCommands = (/const CORE_COMMANDS = new Set\(\[([^\]]*)\]/.exec(cli)?.[1] ?? '').match(/'[^']+'/g)?.map((s) => s.slice(1, -1)) ?? [];
  const env = new Map();
  for (const base of ['packages', 'apps']) {
    for (const p of walk(join(ROOT, base))) {
      if (isTest(p)) continue;
      const text = readFileSync(p, 'utf8');
      for (const m of text.matchAll(/\bREVLENS_[A-Z0-9_]{2,}\b/g)) {
        if (!env.has(m[0])) env.set(m[0], new Set());
        env.get(m[0]).add(p.slice(ROOT.length + 1));
      }
    }
  }
  const envNames = [...env.entries()].map(([name, files]) => ({ name, files: [...files].slice(0, 5), fileCount: files.size })).sort((a, b) => a.name.localeCompare(b.name));
  const outputs = readFileSync(join(ROOT, 'packages/core/src/output/index.ts'), 'utf8');
  const outputFunctions = [...outputs.matchAll(/export function (to[A-Z][A-Za-z]+)/g)].map((m) => m[1]);
  const packages = readdirSync(join(ROOT, 'packages')).filter((n) => statSync(join(ROOT, 'packages', n)).isDirectory());
  return { formatIds, cliOptions, coreCommands, envNames, outputFunctions, packages };
}

const live = await livePass().then((v) => ({ ok: true, ...v }), (e) => ({ ok: false, error: String(e?.stack ?? e).slice(0, 2000) }));
const stat = staticPass();
let head = '';
try { head = execFileSync('git', ['-C', ROOT, 'rev-parse', 'HEAD']).toString().trim(); } catch { /* not git */ }
const result = {
  generatedFrom: { path: ROOT, commit: head, live: live.ok, liveError: live.ok ? undefined : live.error },
  counts: live.ok ? { tools: live.tools.length, commands: live.commands.length + stat.coreCommands.length, analyzers: live.analyzers.length, formatIds: stat.formatIds.length, envNames: stat.envNames.length } : undefined,
  ...(live.ok ? { tools: live.tools, prompts: live.prompts, resources: live.resources, commands: live.commands, analyzers: live.analyzers, toolEffects: live.toolEffects } : {}),
  ...stat,
};
mkdirSync(dirname(OUT), { recursive: true });
writeFileSync(OUT, JSON.stringify(result, null, 1) + '\n');
console.log(JSON.stringify({ out: OUT, live: live.ok, counts: result.counts, error: live.ok ? undefined : live.error?.slice(0, 600) }));
process.exit(0);
