#!/usr/bin/env node
// Build an exact inventory of morluto/rea (scope reference only, MIT) from a source checkout.
// Usage: node scripts/parity/rea-inventory.mjs [--src /workspace/work/rea-src] [--out docs/parity/data/rea-inventory.json]
//
// Two passes:
// 1. A live pass that loads rea's own registries through its tsx (needs `npm ci` in the rea checkout):
//    TOOL_CONTRACTS (every MCP tool with its input JSON schema and declared effects), the incur CLI tree
//    from createCli() (every command path with its args and options), CLI_OUTPUT_FORMATS,
//    ARTIFACT_FORMAT_IDS, TOOL_FAMILY_IDS and the debugger session limit settings.
// 2. A static pass over the sources: top level folders under src/, the environment schema in
//    src/config/environment.ts, every REA_* name used outside tests, and the tool names mentioned in
//    docs/reference/mcp-contracts.md.
// The live pass is the authority. If it fails, the static pass still runs and the output says so.
import { execFileSync } from 'node:child_process';
import { mkdirSync, readFileSync, readdirSync, statSync, writeFileSync, unlinkSync, existsSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';

const args = process.argv.slice(2);
const opt = (name, dflt) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : dflt; };
const SRC = resolve(opt('--src', '/workspace/work/rea-src'));
const OUT = resolve(opt('--out', 'docs/parity/data/rea-inventory.json'));

const HELPER = `
import { TOOL_CONTRACTS } from "./src/contracts/toolContracts.ts";
import { toolFamilyId } from "./src/contracts/toolFamilies.ts";
import { TOOL_FAMILY_IDS } from "./src/contracts/toolFamilyIds.ts";
import { ARTIFACT_FORMAT_IDS } from "./src/domain/artifactGraph.ts";
import { CLI_OUTPUT_FORMATS } from "./src/cliOutput.ts";
import { CLI_COMMAND_NAMES } from "./src/cliCommandNames.ts";
import { debuggerSessionLimitEnvironmentShape } from "./src/config/debuggerSessionLimits.ts";
import { createCli } from "./src/cli.ts";
import { visitRegisteredCommands } from "./src/cli/visitRegisteredCommands.ts";
import { z } from "zod";
import { writeFileSync } from "node:fs";

const jsonSchema = (s: any) => {
  try { return z.toJSONSchema(s, { io: "input", unrepresentable: "any" }) as any; }
  catch (e) { return { error: String(e).slice(0, 200) }; }
};
const fields = (s: any) => {
  const js = jsonSchema(s);
  const req = new Set(js.required ?? []);
  const props = js.properties ?? {};
  // discriminated unions and other top level unions: merge the branch properties
  const branches = js.anyOf ?? js.oneOf ?? [];
  for (const b of branches) for (const [k, v] of Object.entries(b.properties ?? {})) if (!(k in props)) props[k] = v;
  return Object.entries(props).map(([name, p]: [string, any]) => ({
    name,
    type: p.type ?? (p.enum ? "enum" : p.anyOf ? "union" : p.const !== undefined ? "const" : "any"),
    enum: p.enum ?? (p.const !== undefined ? [p.const] : undefined),
    required: req.has(name),
    description: typeof p.description === "string" ? p.description.slice(0, 300) : undefined,
  }));
};
const tools = TOOL_CONTRACTS.map((c: any) => ({
  name: c.name,
  family: toolFamilyId(c.name) ?? null,
  kind: c.kind ?? null,
  description: c.description,
  effects: c.effects ?? null,
  requiresActiveTarget: c.requiresActiveTarget ?? null,
  inputs: c.inputSchema ? fields(c.inputSchema) : [],
}));
const cli = createCli({});
const commands: any[] = [];
const shapeFields = (s: any) => {
  if (!s) return [];
  const shape = s.shape ?? (typeof s === "object" ? s : {});
  return Object.entries(shape).map(([name, f]: [string, any]) => ({
    name,
    description: f?.description ?? f?._zod?.def?.description,
    optional: typeof f?.isOptional === "function" ? f.isOptional() : undefined,
  }));
};
visitRegisteredCommands(cli as any, (c: any, path: string, outputPolicy: any) => {
  commands.push({ path, description: c.description ?? "", args: shapeFields(c.args), options: shapeFields(c.options), outputPolicy: outputPolicy ?? null });
});
writeFileSync(process.env.PARITY_OUT as string, JSON.stringify({
  tools, commands,
  cliCommandNames: CLI_COMMAND_NAMES,
  cliOutputFormats: CLI_OUTPUT_FORMATS,
  artifactFormats: ARTIFACT_FORMAT_IDS,
  toolFamilies: TOOL_FAMILY_IDS,
  debuggerSettings: Object.keys(debuggerSessionLimitEnvironmentShape),
}));
process.exit(0);
`;

function livePass() {
  const helper = join(SRC, `.parity-inventory-${process.pid}.ts`);
  writeFileSync(helper, HELPER);
  try {
    const tmpOut = join(SRC, `.parity-inventory-${process.pid}.json`);
    execFileSync(process.execPath, ['--import', 'tsx', helper], {
      cwd: SRC, maxBuffer: 64 * 1024 * 1024, timeout: 300_000, env: { ...process.env, REA_LOG_LEVEL: 'silent', PARITY_OUT: tmpOut },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    const data = JSON.parse(readFileSync(tmpOut, 'utf8'));
    try { unlinkSync(tmpOut); } catch { /* flaky mount */ }
    return { ok: true, ...data };
  } catch (e) {
    return { ok: false, error: String(e.stderr ?? e.message ?? e).slice(0, 2000) };
  } finally {
    try { unlinkSync(helper); } catch { /* the reference checkout may sit on a flaky mount */ }
  }
}

const isTest = (p) => /\.test\.ts$|\/test(s)?\/|fixtures?\//.test(p);
function walk(dir, acc = [], depth = 0) {
  if (depth > 12) return acc;
  for (const name of readdirSync(dir)) {
    if (name === 'node_modules' || name.startsWith('.')) continue;
    const p = join(dir, name);
    const st = statSync(p);
    if (st.isDirectory()) walk(p, acc, depth + 1);
    else if (p.endsWith('.ts')) acc.push(p);
  }
  return acc;
}

function staticPass() {
  const srcDir = join(SRC, 'src');
  const folders = readdirSync(srcDir).filter((n) => statSync(join(srcDir, n)).isDirectory()).map((n) => {
    const files = walk(join(srcDir, n)).filter((p) => !isTest(p));
    return { folder: n, files: files.length };
  });
  const envText = readFileSync(join(srcDir, 'config/environment.ts'), 'utf8');
  const start = envText.indexOf('const environmentSchema = z.object({');
  const end = envText.indexOf('\n});', start);
  const block = envText.slice(start, end);
  const envSchemaKeys = [...block.matchAll(/^\s{2}([A-Z][A-Z0-9_]+):/gm)].map((m) => m[1]);
  const envDefaults = {};
  for (const k of envSchemaKeys) {
    const i = block.indexOf(`${k}:`);
    const seg = block.slice(i, block.indexOf('\n  ', i + k.length + 3) > 0 ? block.indexOf('\n  ', i + k.length + 3) + 200 : i + 400);
    const d = /\.default\(\s*([^)]*)\)/.exec(seg.split(/\n {2}[A-Z]/)[0]);
    if (d) envDefaults[k] = d[1].trim();
  }
  const reaNames = new Map();
  for (const p of walk(srcDir)) {
    if (isTest(p)) continue;
    const text = readFileSync(p, 'utf8');
    for (const m of text.matchAll(/\bREA_[A-Z0-9_]{2,}\b/g)) {
      const rel = p.slice(SRC.length + 1);
      if (!reaNames.has(m[0])) reaNames.set(m[0], new Set());
      reaNames.get(m[0]).add(rel);
    }
  }
  const envNames = [...reaNames.entries()].map(([name, files]) => ({ name, files: [...files].slice(0, 5), fileCount: files.size }))
    .sort((a, b) => a.name.localeCompare(b.name));
  const contracts = readFileSync(join(SRC, 'docs/reference/mcp-contracts.md'), 'utf8');
  const sections = [...contracts.matchAll(/^(#{2,4}) (.+)$/gm)].map((m) => ({ level: m[1].length, title: m[2] }));
  const mentioned = [...new Set([...contracts.matchAll(/`([a-z][a-z0-9]*(?:_[a-z0-9]+)+)`/g)].map((m) => m[1]))].sort();
  const pkg = JSON.parse(readFileSync(join(SRC, 'package.json'), 'utf8'));
  return { folders, envSchemaKeys, envDefaults, envNames, contractsDoc: { sections, mentionedIdentifiers: mentioned }, version: pkg.version };
}

const live = livePass();
const stat = staticPass();
let head = '';
try { head = execFileSync('git', ['-C', SRC, 'rev-parse', 'HEAD']).toString().trim(); } catch { /* not a git checkout */ }
const result = {
  generatedFrom: { path: SRC, commit: head, version: stat.version, live: live.ok, liveError: live.ok ? undefined : live.error },
  counts: live.ok ? { tools: live.tools.length, commands: live.commands.length, cliCommandNames: live.cliCommandNames.length, artifactFormats: live.artifactFormats.length, outputFormats: live.cliOutputFormats.length, envSchemaKeys: stat.envSchemaKeys.length, envNames: stat.envNames.length, folders: stat.folders.length } : undefined,
  ...(live.ok ? { tools: live.tools, commands: live.commands, cliCommandNames: live.cliCommandNames, cliOutputFormats: live.cliOutputFormats, artifactFormats: live.artifactFormats, toolFamilies: live.toolFamilies, debuggerSettings: live.debuggerSettings } : {}),
  ...stat,
};
// tool names mentioned in the contracts doc that are real tools
if (live.ok) {
  const names = new Set(live.tools.map((t) => t.name));
  result.contractsDoc.mentionedTools = result.contractsDoc.mentionedIdentifiers.filter((n) => names.has(n));
  delete result.contractsDoc.mentionedIdentifiers;
}
mkdirSync(dirname(OUT), { recursive: true });
writeFileSync(OUT, JSON.stringify(result, null, 1) + '\n');
console.log(JSON.stringify({ out: OUT, live: live.ok, counts: result.counts, error: live.ok ? undefined : live.error?.slice(0, 400) }));
if (!existsSync(OUT)) process.exit(1);
