// Round 3 CLI commands: each maps to a tool in tools-r3.ts. Human text is a short rendering;
// --json prints the tool result.
import type { CliCommand } from './cli.js';
import { R3_TOOLS } from './tools-r3.js';

const out = (s: string) => { (globalThis as { process?: { stdout: { write(s: string): void } } }).process?.stdout.write(s + '\n'); };
const err = (s: string) => { (globalThis as { process?: { stderr: { write(s: string): void } } }).process?.stderr.write(s + '\n'); };

const BOOL = new Set(['json', 'include-anonymous', 'all', 'debug-info', 'no-debug-info', 'regex', 'case-sensitive', 'clear', 'with-pseudocode']);

function parse(argv: string[]) {
  const pos: string[] = [];
  const flags: Record<string, string | boolean> = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (a.startsWith('--')) {
      const eq = a.indexOf('=');
      if (eq > 0) flags[a.slice(2, eq)] = a.slice(eq + 1);
      else if (BOOL.has(a.slice(2))) flags[a.slice(2)] = true;
      else flags[a.slice(2)] = argv[++i] ?? '';
    } else pos.push(a);
  }
  return { pos, flags };
}

const camel = (s: string) => s.replace(/-([a-z])/g, (_m, c: string) => c.toUpperCase());

/** text rendering: compact JSON lines for arrays, key: value for scalars */
export function renderPlain(v: unknown, indent = ''): string {
  if (v === null || v === undefined) return indent + '-';
  if (typeof v !== 'object') return indent + String(v);
  const lines: string[] = [];
  for (const [k, x] of Object.entries(v as Record<string, unknown>)) {
    if (x === undefined) continue;
    if (typeof x === 'string' && x.includes('\n')) { lines.push(`${indent}${k}:`); lines.push(...x.split('\n').map((l) => indent + '  ' + l)); }
    else if (Array.isArray(x)) { lines.push(`${indent}${k}: (${x.length})`); for (const e of x.slice(0, 500)) lines.push(indent + '  ' + (typeof e === 'object' ? JSON.stringify(e) : String(e))); }
    else if (typeof x === 'object' && x) { lines.push(`${indent}${k}:`); lines.push(renderPlain(x, indent + '  ')); }
    else lines.push(`${indent}${k}: ${String(x)}`);
  }
  return lines.join('\n');
}

/** A CLI command backed by a tool: positional arguments fill the named params in order, --flags fill the rest. */
function toolCommand(name: string, tool: string, positional: string[], summary: string): CliCommand {
  const t = R3_TOOLS.find((x) => x.name === tool);
  if (!t) throw new Error('missing tool ' + tool);
  const opt = Object.keys(t.inputSchema).filter((k) => !positional.includes(k)).map((k) => `[--${k.replace(/[A-Z]/g, (c) => '-' + c.toLowerCase())} v]`).join(' ');
  return {
    name, summary,
    usage: `${name} ${positional.map((x) => `<${x}>`).join(' ')} ${opt} [--json]`,
    async run(argv) {
      const p = parse(argv);
      const required = positional.filter((k) => !t.inputSchema[k]?.optional);
      if (p.pos.length < required.length || p.flags.help) { err(`usage: revlens ${this.usage}`); return 2; }
      const input: Record<string, unknown> = {};
      positional.forEach((k, i) => { if (p.pos[i] !== undefined) input[k] = p.pos[i]; });
      for (const [k, v] of Object.entries(p.flags)) {
        if (k === 'json') continue;
        const key = camel(k);
        const spec = t.inputSchema[key];
        if (!spec) continue;
        input[key] = spec.type === 'number' && typeof v === 'string' ? Number(v) : spec.type === 'boolean' ? v === true || v === 'true' : spec.type === 'array' && typeof v === 'string' ? v.split(',') : v;
      }
      try {
        const r = await t.run(input);
        out(p.flags.json ? JSON.stringify(r, null, 2) : renderPlain(r));
        return 0;
      } catch (e) {
        err(`${name}: ${(e as Error).message}`);
        return 1;
      }
    },
  };
}

export const R3_COMMANDS: CliCommand[] = [
  toolCommand('disasm-debug-info', 'disasm_debug_info', ['path', 'view', 'name'], 'DWARF types, prototypes, parameters, locals and globals'),
];
