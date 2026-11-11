// CLI commands for @revlens/extras. Each wraps one agent tool: the first bare argument is
// the file path, --key value pairs become tool inputs, and --json prints raw JSON.

import type { CliCommand, ToolDef } from './util.js';
import { TOOLS } from './tools.js';

function parseArgs(argv: string[], tool: ToolDef): { input: Record<string, unknown>; json: boolean } {
  const input: Record<string, unknown> = {};
  let json = false;
  const rest: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i] as string;
    if (a === '--json') { json = true; continue; }
    if (a.startsWith('--')) {
      const eq = a.indexOf('=');
      const key = eq > 0 ? a.slice(2, eq) : a.slice(2);
      let val: string | undefined = eq > 0 ? a.slice(eq + 1) : undefined;
      const spec = tool.inputSchema[key];
      if (val === undefined) {
        if (spec?.type === 'boolean') { input[key] = true; continue; }
        val = argv[++i];
      }
      if (val === undefined) continue;
      if (spec?.type === 'number') input[key] = Number(val);
      else if (spec?.type === 'array' || spec?.type === 'object') { try { input[key] = JSON.parse(val); } catch { input[key] = spec.type === 'array' ? val.split(',') : val; } }
      else if (spec?.type === 'boolean') input[key] = val !== 'false';
      else input[key] = val;
    } else rest.push(a);
  }
  if (rest.length && tool.inputSchema.path && input.path === undefined) input.path = rest.shift();
  if (rest.length && tool.inputSchema.symbols) input.symbols = rest;
  return { input, json };
}

/** Plain text rendering of a JSON result: indented keys, short arrays inline, long arrays capped. */
export function renderText(x: unknown, indent = '', depth = 0): string {
  if (x === null || x === undefined) return 'null';
  if (typeof x !== 'object') return String(x);
  if (depth > 6) return JSON.stringify(x).slice(0, 200);
  if (Array.isArray(x)) {
    if (!x.length) return '[]';
    if (x.every((v) => v === null || typeof v !== 'object') && JSON.stringify(x).length < 100) return x.join(', ');
    const shown = x.slice(0, 50).map((v) => `${indent}- ${renderText(v, indent + '  ', depth + 1).replace(/^\s+/, '')}`);
    if (x.length > 50) shown.push(`${indent}... ${x.length - 50} more`);
    return '\n' + shown.join('\n');
  }
  const lines: string[] = [];
  for (const [k, v] of Object.entries(x as Record<string, unknown>)) {
    const r = renderText(v, indent + '  ', depth + 1);
    lines.push(`${indent}${k}: ${r.startsWith('\n') ? r : r.split('\n').join('\n' + indent + '  ')}`);
  }
  return (depth ? '\n' : '') + lines.join('\n');
}

function command(cmd: string, toolName: string, summary: string): CliCommand {
  const tool = TOOLS.find((t) => t.name === toolName);
  if (!tool) throw new Error(`missing tool ${toolName}`);
  const opts = Object.entries(tool.inputSchema).filter(([k]) => k !== 'path' && k !== 'bytes').map(([k, s]) => `[--${k} ${s.type === 'boolean' ? '' : '<' + s.type + '>'}]`.replace(' ]', ']')).join(' ');
  return {
    name: cmd,
    usage: `revlens ${cmd} ${tool.inputSchema.path ? '<file> ' : ''}${opts} [--json]`,
    summary,
    async run(argv) {
      if (argv.includes('--help') || argv.includes('-h')) { console.log(`${this.usage}\n${tool.description}`); return 0; }
      const { input, json } = parseArgs(argv, tool);
      try {
        const out = await tool.run(input);
        console.log(json ? JSON.stringify(out, null, 2) : renderText(out));
        return 0;
      } catch (e) {
        console.error(`${cmd}: ${(e as Error).message}`);
        return 1;
      }
    },
  };
}

export const CLI_COMMANDS: CliCommand[] = [
  command('x-demangle', 'x_demangle', 'Demangle C++, Rust and MSVC names, or a binary symbol table'),
  command('x-container', 'x_container', 'Sections and segments of ELF, PE or Mach-O'),
  command('x-read-bytes', 'x_read_bytes', 'Hex dump at a file offset or virtual address'),
  command('x-search-bytes', 'x_search_bytes', 'Search a hex pattern with wildcards or a string'),
  command('x-address-map', 'x_address_map', 'Virtual address to file offset and back'),
  command('x-checksec', 'x_checksec', 'Hardening checks for ELF, PE and Mach-O'),
  command('x-go', 'x_go_symbols', 'Go functions, files and packages from pclntab'),
  command('x-rust', 'x_rust_info', 'Rust compiler version and crates'),
  command('x-pe', 'x_pe_inspect', 'Deep PE inspection'),
  command('x-pe-resources', 'x_pe_resources', 'PE resources, version info and manifest'),
  command('x-authenticode', 'x_pe_authenticode', 'Verify Authenticode signatures'),
  command('x-elf', 'x_elf_inspect', 'ELF notes, dynamic section and initializers'),
  command('x-unwind', 'x_elf_unwind', 'Function ranges from .eh_frame'),
  command('x-kmod', 'x_kernel_module', 'Linux kernel module facts or IKCONFIG'),
  command('x-macho', 'x_macho_inspect', 'Mach-O load commands and code signature'),
  command('x-firmware', 'x_firmware_scan', 'Find embedded images in a firmware blob'),
  command('x-firmware-parse', 'x_firmware_parse', 'Parse one firmware structure'),
  command('x-v8', 'x_v8_inspect', 'V8 code cache, snapshot or Hermes bytecode header'),
  command('x-gpu', 'x_gpu_inspect', 'CUDA, PTX, AMDGPU and SPIR-V code objects'),
  command('x-model', 'x_model_inspect', 'GGUF, safetensors and npy model files'),
  command('x-lnk', 'x_lnk_inspect', 'Windows shortcut files'),
  command('x-ips', 'x_apple_ips', 'Apple .ips crash reports'),
  command('x-claim', 'x_ledger_record', 'Record a claim with byte evidence in a ledger file'),
  command('x-unknown', 'x_ledger_unknown', 'Record or update an unknown in a ledger file'),
  command('x-verify', 'x_ledger_verify', 'Re-verify every claim in a ledger file'),
  command('x-ledger', 'x_ledger_list', 'Show the claims and unknowns in a ledger file'),
  command('x-ledger-export', 'x_ledger_export', 'Export a ledger as JSON or Markdown'),
  command('x-eval-tasks', 'x_eval_tasks', 'List eval tasks for agents'),
  command('x-eval-score', 'x_eval_score', 'Score agent answers to the eval tasks'),
];
