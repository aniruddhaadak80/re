// CLI commands. Human text by default, JSON with --json.
import {
  disasmAt, disasmCallgraph, disasmCallPaths, disasmFindReferences, disasmFunction, disasmInfo,
  disasmListFunctions, disasmPseudocode, disasmSearch, disasmXrefs,
} from './api.js';

export interface CliCommand { name: string; usage: string; summary: string; run(argv: string[]): Promise<number> }

interface Parsed { pos: string[]; flags: Record<string, string | boolean> }

function parse(argv: string[]): Parsed {
  const pos: string[] = [];
  const flags: Record<string, string | boolean> = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (a.startsWith('--')) {
      const eq = a.indexOf('=');
      if (eq > 0) flags[a.slice(2, eq)] = a.slice(eq + 1);
      else if (['json', 'imports', 'thumb', 'exact'].includes(a.slice(2))) flags[a.slice(2)] = true;
      else flags[a.slice(2)] = argv[++i] ?? '';
    } else pos.push(a);
  }
  return { pos, flags };
}

function num(v: string | boolean | undefined): number | undefined { return typeof v === 'string' && v !== '' ? Number(v) : undefined; }
function str(v: string | boolean | undefined): string | undefined { return typeof v === 'string' && v !== '' ? v : undefined; }

const out = (s: string) => { (globalThis as { process?: { stdout: { write(s: string): void } } }).process?.stdout.write(s + '\n'); };
const err = (s: string) => { (globalThis as { process?: { stderr: { write(s: string): void } } }).process?.stderr.write(s + '\n'); };

function wrap(name: string, usage: string, summary: string, minPos: number, body: (p: Parsed) => Promise<{ json: unknown; text: () => string }>): CliCommand {
  return {
    name, usage, summary,
    async run(argv) {
      const p = parse(argv);
      if (p.pos.length < minPos || p.flags.help) { err(`usage: revlens ${usage}`); return 2; }
      try {
        const r = await body(p);
        out(p.flags.json ? JSON.stringify(r.json, null, 2) : r.text());
        return 0;
      } catch (e) {
        err(`${name}: ${(e as Error).message}`);
        return 1;
      }
    },
  };
}

const common = (p: Parsed) => ({ path: p.pos[0]!, arch: str(p.flags.arch) as never });

export const CLI_COMMANDS: CliCommand[] = [
  wrap('disasm-info', 'disasm-info <file> [--arch x86_64|arm64] [--json]', 'Format, arch, entry, sections and function count of a native binary', 1, async (p) => {
    const r = await disasmInfo(common(p));
    return { json: r, text: () => [`${r.format} ${r.arch} ${r.bits}-bit  entry ${r.entry ?? '-'}  decoder ${r.decoder}`, `functions ${r.functions}  symbols ${r.symbols}  imports ${r.imports}${r.go ? '  go ' + r.go : ''}`, ...r.sections.map((s) => `  ${s.name.padEnd(20)} ${s.vaddr.padStart(12)} ${String(s.size).padStart(10)} ${s.exec ? 'x' : '-'}${s.write ? 'w' : '-'}`)].join('\n') };
  }),
  wrap('disasm-functions', 'disasm-functions <file> [--filter s] [--sort addr|name|size] [--limit n] [--offset n] [--imports] [--json]', 'List discovered functions', 1, async (p) => {
    const r = await disasmListFunctions({ ...common(p), filter: str(p.flags.filter), sort: str(p.flags.sort) as never, limit: num(p.flags.limit), offset: num(p.flags.offset), includeImports: !!p.flags.imports });
    return { json: r, text: () => [`${r.total} functions (showing ${r.functions.length} from ${r.offset})${r.discoveryComplete ? '' : ' discovery incomplete'}`, ...r.functions.map((f) => `${f.addr.padStart(12)}  ${String(f.size ?? '').padStart(7)}  ${f.source.padEnd(15)} ${f.name}`)].join('\n') };
  }),
  wrap('disasm', 'disasm <file> <function|address> [--limit n] [--offset n] [--json]', 'Disassemble a function with its basic blocks', 2, async (p) => {
    const r = await disasmFunction({ ...common(p), function: p.pos[1]!, limit: num(p.flags.limit), offset: num(p.flags.offset) });
    return {
      json: r,
      text: () => {
        const lines = [`${r.function.name} @ ${r.function.addr}  ${r.summary.instructions} insns, ${r.summary.blocks} blocks, complexity ${r.summary.cyclomaticComplexity}`];
        for (const b of r.blocks) {
          lines.push(`; block ${b.start}${b.succ.length ? ' -> ' + b.succ.map((e) => `${e.to}(${e.kind})`).join(' ') : ''}${b.exit ? ' [' + b.exit + ']' : ''}`);
          for (const i of b.insns) lines.push(`  ${String(i.addr).padStart(12)}  ${String(i.bytes).padEnd(20)} ${i.text}${i.ref ? '   ; ' + i.ref : ''}`);
        }
        if (r.paging.hasMore) lines.push(`... more instructions, use --offset ${r.paging.offset + r.paging.limit}`);
        return lines.join('\n');
      },
    };
  }),
  wrap('disasm-at', 'disasm-at <file> <address> [--count n] [--thumb] [--json]', 'Disassemble N instructions at an address', 2, async (p) => {
    const r = await disasmAt({ ...common(p), address: p.pos[1]!, count: num(p.flags.count), thumb: p.flags.thumb ? true : undefined });
    return { json: r, text: () => r.instructions.map((i) => `${String(i.addr).padStart(12)}  ${String(i.bytes).padEnd(20)} ${i.text}${i.ref ? '   ; ' + i.ref : ''}`).join('\n') };
  }),
  wrap('decompile', 'decompile <file> <function|address> [--max-lines n] [--json]', 'Light pseudo code and summary for a function', 2, async (p) => {
    const r = await disasmPseudocode({ ...common(p), function: p.pos[1]!, maxLines: num(p.flags['max-lines']) });
    return { json: r, text: () => r.pseudocode };
  }),
  wrap('xrefs', 'xrefs <file> <address|name> [--direction to|from] [--limit n] [--json]', 'Cross references to or from a target', 2, async (p) => {
    const r = await disasmXrefs({ ...common(p), target: p.pos[1]!, direction: (str(p.flags.direction) ?? 'to') as never, limit: num(p.flags.limit), offset: num(p.flags.offset) });
    return { json: r, text: () => (r.refs as Record<string, string>[]).map((x) => Object.values(x).filter(Boolean).join('  ')).join('\n') || 'no references' };
  }),
  wrap('callgraph', 'callgraph <file> [function] [--direction callees|callers|both] [--depth n] [--json]', 'Call graph around a function', 1, async (p) => {
    const r = await disasmCallgraph({ ...common(p), function: p.pos[1], direction: str(p.flags.direction) as never, depth: num(p.flags.depth), limit: num(p.flags.limit) });
    return { json: r, text: () => ('edges' in r && r.edges ? r.edges.map((e) => `${e.from} -> ${e.to}`).join('\n') : r.nodes.map((n) => `${n.addr}  ${n.name}  callers=${(n as { callers?: number }).callers ?? ''}`).join('\n')) };
  }),
  wrap('disasm-search', 'disasm-search <file> [--bytes "48 8b ?? ??"] [--insn "call *printf*"] [--text s] [--limit n] [--json]', 'Byte pattern, instruction or text search', 1, async (p) => {
    const r = await disasmSearch({ ...common(p), bytes_pattern: str(p.flags.bytes), insn: str(p.flags.insn), text: str(p.flags.text), limit: num(p.flags.limit), offset: num(p.flags.offset), scope: str(p.flags.scope) as never });
    return { json: r, text: () => r.matches.map((m) => Object.values(m).filter((v) => v !== undefined).join('  ')).join('\n') || 'no matches' };
  }),
  wrap('refs', 'refs <file> (--string s | --import name) [--exact] [--json]', 'Functions referencing a string or an import', 1, async (p) => {
    const r = await disasmFindReferences({ ...common(p), string: str(p.flags.string), import: str(p.flags.import), exact: !!p.flags.exact, limit: num(p.flags.limit) });
    return { json: r, text: () => r.matches.map((m) => `${m.kind} ${JSON.stringify(m.value)} @ ${m.target}\n` + m.refs.map((x) => `    ${x.from}  in ${x.function}`).join('\n')).join('\n') || 'no references' };
  }),
  wrap('call-paths', 'call-paths <file> <target> [--from f] [--max-depth n] [--json]', 'Call paths from entry to a function', 2, async (p) => {
    const r = await disasmCallPaths({ ...common(p), target: p.pos[1]!, from: str(p.flags.from), maxDepth: num(p.flags['max-depth']), maxPaths: num(p.flags['max-paths']) });
    return { json: r, text: () => (r.paths.length ? r.paths.map((x) => x.join(' -> ')).join('\n') : `no path from ${r.from.name} to ${r.target.name}`) };
  }),
];
