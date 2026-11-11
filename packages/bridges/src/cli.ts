// CLI commands for the revlens binary: `doctor`, `setup` and `bridge <tool>`. Human text by
// default, JSON with --json. Node only.
import { formatInventory, inventory } from './doctor.js';
import { MCP_CLIENTS, setupClient, type McpClient } from './setup.js';
import { TOOLS } from './tools.js';
import type { BridgeTool, CliCommand } from './types.js';

export interface ParsedArgs { flags: Record<string, string | boolean | string[]>; positional: string[] }

/** Minimal argv parser: --key value, --key=value, --flag, repeated keys become arrays. */
export function parseArgv(argv: string[]): ParsedArgs {
  const flags: ParsedArgs['flags'] = {};
  const positional: string[] = [];
  const BOOL = new Set(['json', 'write', 'verbose', 'refresh', 'allow-execution', 'help', 'applications', 'case-sensitive', 'third-party-only', 'no-sources',
    'all', 'replace', 'downgrade', 'allow-test', 'grant-permissions', 'keep-data', 'overwrite', 'include-raw', 'force-stop', 'include-apk', 'allow-any-remote-path', 'resume']);
  for (let i = 0; i < argv.length && i < 10_000; i++) {
    const a = argv[i]!;
    if (a === '--') { positional.push(...argv.slice(i + 1)); break; }
    if (a.startsWith('--')) {
      const eq = a.indexOf('=');
      const key = eq > 0 ? a.slice(2, eq) : a.slice(2);
      let val: string | boolean;
      if (eq > 0) val = a.slice(eq + 1);
      else if (BOOL.has(key) || i + 1 >= argv.length || argv[i + 1]!.startsWith('--')) val = true;
      else val = argv[++i]!;
      const prev = flags[key];
      if (prev === undefined) flags[key] = val;
      else flags[key] = [...(Array.isArray(prev) ? prev : [String(prev)]), String(val)];
    } else positional.push(a);
  }
  return { flags, positional };
}

function camel(k: string): string {
  return k.replace(/-([a-z])/g, (_, c: string) => c.toUpperCase());
}

/** Turn CLI flags into a tool input using the tool's schema for types. */
export function toolInput(tool: BridgeTool, p: ParsedArgs): Record<string, unknown> {
  const input: Record<string, unknown> = {};
  for (const [rawKey, v] of Object.entries(p.flags)) {
    if (rawKey === 'json' || rawKey === 'help') continue;
    const key = rawKey === 'allow-execution' ? 'allowExecution' : camel(rawKey);
    const field = tool.inputSchema[key];
    if (!field) continue;
    const vals = Array.isArray(v) ? v : [v];
    switch (field.type) {
      case 'number': input[key] = Number(vals[vals.length - 1]); break;
      case 'boolean': input[key] = vals[vals.length - 1] === true || vals[vals.length - 1] === 'true'; break;
      case 'array': input[key] = vals.flatMap((x) => String(x).split(',')).filter((x) => x !== ''); break;
      case 'object': {
        const s = String(vals[vals.length - 1]);
        try { input[key] = JSON.parse(s); } catch { input[key] = s; }
        break;
      }
      default: input[key] = String(vals[vals.length - 1]);
    }
  }
  if (tool.inputSchema.path && input.path === undefined && p.positional[0]) input.path = p.positional[0];
  if (tool.inputSchema.args && input.args === undefined && p.positional.length > 1) input.args = p.positional.slice(1);
  return input;
}

/** Short human rendering of a bridge result. */
export function renderResult(r: unknown): string {
  if (!r || typeof r !== 'object') return String(r);
  const o = r as Record<string, any>;
  if (o.available === false) {
    const inst = o.install ?? {};
    const cmd = inst.brew ?? inst.apt ?? inst.winget ?? inst.scoop ?? inst.choco ?? inst.pip ?? inst.dotnet ?? inst.cargo ?? inst.script ?? inst.url;
    return `${o.tool} is not available: ${o.reason}\n${cmd ? `install: ${cmd}\n` : ''}homepage: ${inst.homepage ?? ''}`;
  }
  if (o.ok === false) return `error: ${o.error}${o.hint ? `\nhint: ${o.hint}` : ''}`;
  const out: string[] = [];
  if (o.tool) out.push(`[${o.tool}${o.toolVersion ? ' ' + o.toolVersion : ''}]`);
  if (Array.isArray(o.functions) && Array.isArray(o.functions[0]?.instructions)) {
    for (const f of o.functions) { out.push(`${f.address} <${f.name}>:`); for (const i of f.instructions) out.push(`  ${i.address}  ${(i.bytes ?? '').padEnd(10)}  ${i.text}`); }
  } else if (Array.isArray(o.functions)) {
    for (const f of o.functions) out.push(`${f.address}  ${String(f.size ?? '').padStart(7)}  ${f.name}`);
    if (o.more) out.push(`... more, use --offset ${(o.offset ?? 0) + o.functions.length}`);
  } else if (Array.isArray(o.instructions)) {
    for (const i of o.instructions) out.push(`${i.address}  ${(i.bytes ?? '').padEnd(10)}  ${i.text}`);
  } else if (typeof o.code === 'string') out.push(o.code);
  else if (typeof o.source === 'string') out.push(o.source);
  else if (Array.isArray(o.results)) {
    for (const d of o.results) out.push(`// ${d.function?.name} @ ${d.function?.address}${d.ok ? '' : ` failed: ${d.error}`}`, d.c ?? '');
  } else if (Array.isArray(o.hits)) {
    for (const h of o.hits) out.push(h.offsetHex ? `${h.offsetHex.padEnd(10)} ${h.description}` : `${h.className}:${h.line}  ${h.text}`);
  } else if (Array.isArray(o.stops)) {
    for (const s of o.stops) {
      out.push(`stop ${s.index}: ${s.reason ?? ''} ${s.function ?? ''} pc=${s.pc ?? '?'}`);
      out.push('  ' + Object.entries(s.registers).map(([k, v]) => `${k}=${v}`).join(' '));
      for (const f of s.backtrace) out.push(`  #${f.index} ${f.address ?? ''} ${f.function}`);
    }
    if (o.exitCode !== null && o.exitCode !== undefined) out.push(`exit code ${o.exitCode}`);
  } else if (Array.isArray(o.events)) {
    for (const e of o.events) out.push(JSON.stringify(e));
    for (const e of o.errors ?? []) out.push(`error: ${e}`);
  } else if (Array.isArray(o.processes)) {
    for (const p of o.processes) out.push(`${String(p.pid).padStart(7)}  ${p.name}${p.identifier ? '  ' + p.identifier : ''}`);
  } else if (Array.isArray(o.devices)) {
    for (const d of o.devices) out.push(`${d.id ?? d.serial}  ${d.type ?? d.state}  ${d.name ?? d.model ?? ''}`);
  } else if (Array.isArray(o.classes)) {
    for (const c of o.classes) out.push(c.className);
  } else if (Array.isArray(o.types)) {
    for (const t of o.types) out.push(`${t.kind.padEnd(9)} ${t.name}`);
  } else if (Array.isArray(o.xrefs)) {
    for (const x of o.xrefs) out.push(`${x.from}  ${x.type ?? ''}  ${x.function ?? ''}  ${x.opcode ?? ''}`);
  } else if (Array.isArray(o.strings)) {
    for (const s of o.strings) out.push(`${s.vaddr ?? ''}  ${JSON.stringify(s.value)}`);
  } else if (Array.isArray(o.sections)) {
    for (const s of o.sections) out.push(`${s.name.padEnd(24)} ${s.vma}  size ${s.size}`);
  } else if (Array.isArray(o.symbols)) {
    for (const s of o.symbols) out.push(`${s.address}  ${s.section.padEnd(12)} ${s.name}`);
  } else out.push(JSON.stringify(o, null, 2));
  return out.join('\n');
}

const json = (v: unknown) => process.stdout.write(JSON.stringify(v, null, 2) + '\n');

const doctor: CliCommand = {
  name: 'doctor',
  usage: 'revlens doctor [--json] [--verbose] [--refresh]',
  summary: 'Show which external RE tools are installed and how to install the rest',
  async run(argv) {
    const p = parseArgv(argv);
    const inv = await inventory({ refresh: p.flags.refresh === true });
    if (p.flags.json) json(inv);
    else process.stdout.write(formatInventory(inv, { verbose: p.flags.verbose === true }) + '\n');
    return 0;
  },
};

const setup: CliCommand = {
  name: 'setup',
  usage: `revlens setup <${MCP_CLIENTS.join('|')}> [--scope user|project] [--write] [--json]`,
  summary: 'Add the RevLens MCP server to an agent client config (dry run unless --write)',
  async run(argv) {
    const p = parseArgv(argv);
    const client = p.positional[0] as McpClient | undefined;
    if (!client || !MCP_CLIENTS.includes(client)) {
      process.stderr.write(`usage: ${setup.usage}\n`);
      return 2;
    }
    const scope = p.flags.scope === 'project' ? 'project' : 'user';
    try {
      const r = await setupClient({ client, scope, write: p.flags.write === true });
      if (p.flags.json) { json(r); return 0; }
      if (!r.changed) { process.stdout.write(`${r.path} already has the ${r.name} server. Nothing to do.\n`); return 0; }
      if (r.dryRun) {
        process.stdout.write(`Dry run. This would ${r.exists ? 'update' : 'create'} ${r.path}:\n\n${r.after}\nRun again with --write to save it${r.exists ? ' (a backup is made first)' : ''}.\n`);
      } else {
        const w = r as typeof r & { backup?: string | null };
        process.stdout.write(`Wrote ${r.path}${w.backup ? `, backup at ${w.backup}` : ''}. Restart ${client} to load RevLens.\n`);
      }
      return 0;
    } catch (e) {
      process.stderr.write(`setup failed: ${(e as Error).message}\n`);
      return 1;
    }
  },
};

const bridge: CliCommand = {
  name: 'bridge',
  usage: 'revlens bridge <tool> [file] [--key value ...] [--json]   (revlens bridge list shows tools)',
  summary: 'Run one external tool bridge, for example: revlens bridge r2_functions app.elf',
  async run(argv) {
    const p = parseArgv(argv);
    const name = p.positional.shift();
    if (!name || name === 'list') {
      for (const t of TOOLS) process.stdout.write(`${t.name.replace(/^bridge_/, '').padEnd(18)} ${t.description}\n`);
      return name ? 0 : 2;
    }
    const tool = TOOLS.find((t) => t.name === name || t.name === `bridge_${name}`);
    if (!tool) { process.stderr.write(`unknown bridge tool ${name}. Try: revlens bridge list\n`); return 2; }
    if (p.flags.help) {
      process.stdout.write(`${tool.name}: ${tool.description}\n`);
      for (const [k, v] of Object.entries(tool.inputSchema)) process.stdout.write(`  --${k.replace(/[A-Z]/g, (c) => '-' + c.toLowerCase())}  (${v.type}${v.optional ? '' : ', required'}) ${v.description}\n`);
      return 0;
    }
    const r = await tool.run(toolInput(tool, p));
    if (p.flags.json) json(r);
    else process.stdout.write(renderResult(r) + '\n');
    const o = r as Record<string, unknown>;
    return o && (o.available === false || o.ok === false) ? 1 : 0;
  },
};

export const CLI_COMMANDS: CliCommand[] = [doctor, setup, bridge];
