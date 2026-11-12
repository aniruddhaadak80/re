// CLI commands. Human text by default, JSON with --json.
import {
  disasmAt, disasmCallgraph, disasmCallPaths, disasmFindReferences, disasmFunction, disasmInfo,
  disasmListFunctions, disasmPseudocode, disasmSearch, disasmXrefs,
} from './api.js';
import { disasmTraceValues, disasmIndirectTargets } from './flowapi.js';
import { disasmMatchFunctions, disasmCompareFunctions } from './matchapi.js';
import { R3_COMMANDS } from './cli-r3.js';

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
      else if (['json', 'imports', 'thumb', 'exact', 'unresolved', 'no-names'].includes(a.slice(2))) flags[a.slice(2)] = true;
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

const common = (p: Parsed) => ({
  path: p.pos[0]!, arch: str(p.flags.arch) as never,
  ...(str(p.flags['load-mode']) ? { loadMode: str(p.flags['load-mode']) as never } : {}),
  ...(str(p.flags['raw-arch']) ? { rawArch: str(p.flags['raw-arch']) as never } : {}),
  ...(str(p.flags['raw-base']) ? { rawBase: str(p.flags['raw-base']) as never } : {}),
});

const BASE_COMMANDS: CliCommand[] = [
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
  wrap('trace-values', 'trace-values <file> [function] [--call addr|name] [--occurrence n] [--arg n] [--value text|0xaddr] [--param n] [--depth n] [--limit n] [--json]', 'Value flow: what reaches a call argument (backward) or where a value goes (forward)', 1, async (p) => {
    const r: any = await disasmTraceValues({
      ...common(p), function: p.pos[1], call: str(p.flags.call), occurrence: num(p.flags.occurrence), arg: num(p.flags.arg),
      value: str(p.flags.value), param: num(p.flags.param), depth: num(p.flags.depth), limit: num(p.flags.limit), budgetMs: num(p.flags['budget-ms']),
    });
    return {
      json: r,
      text: () => {
        const lines: string[] = [];
        if (r.mode === 'backward') {
          lines.push(`backward value flow in ${r.function?.name ?? '?'} @ ${r.function?.addr ?? '?'}  abi ${r.abi}${r.complete ? '' : '  (budget reached)'}`);
          for (const c of r.calls ?? []) {
            lines.push(`call ${c.callee ?? '(indirect)'} at ${c.at}`);
            for (const a of c.args ?? []) {
              lines.push(`  arg ${a.index}${a.reg ? ` (${a.reg})` : ''} = ${a.value?.text ?? '?'}${a.producedAt ? `   set at ${a.producedAt}` : ''}`);
              const walk = (list: any[] | undefined, pad: string) => { for (const up of list ?? []) { lines.push(`${pad}from ${up.function} call at ${up.callAt}: ${up.value?.text ?? '?'}`); walk(up.fromCallers, pad + '  '); } };
              walk(a.fromCallers, '    ');
            }
          }
        } else {
          lines.push(`forward value flow, depth ${r.depth}, ${r.functionsSearched ?? 0} functions searched${r.complete ? '' : '  (budget reached)'}`);
          for (const x of r.results ?? []) {
            lines.push(`value ${x.value?.text ?? '?'}`);
            const walk = (list: any[] | undefined, pad: string) => {
              for (const k of list ?? []) {
                lines.push(`${pad}${String(k.kind).padEnd(12)} ${k.at ?? ''}  in ${k.function ?? '?'}${k.callee ? `  -> ${k.callee}${k.argIndex !== undefined ? ` arg ${k.argIndex}` : ''}` : ''}`);
                if (k.into) walk(k.into.sinks, pad + '  ');
              }
            };
            walk(x.sinks, '  ');
          }
        }
        return lines.join('\n') || 'nothing found';
      },
    };
  }),
  wrap('indirect', 'indirect <file> [function] [--unresolved] [--limit n] [--offset n] [--json]', 'Indirect calls and jumps with resolved targets (jump tables, pointer tables, constants, vtables)', 1, async (p) => {
    const r: any = await disasmIndirectTargets({ ...common(p), function: p.pos[1], unresolved: p.flags.unresolved ? true : undefined, limit: num(p.flags.limit), offset: num(p.flags.offset), budgetMs: num(p.flags['budget-ms']) });
    return {
      json: r,
      text: () => [
        `${r.total} indirect sites, ${r.resolved} resolved, ${r.unresolved} unresolved (${r.functionsScanned} functions${r.complete ? '' : ', budget reached'})`,
        ...(r.sites ?? []).map((x: any) => `${String(x.at).padStart(12)}  ${String(x.kind).padEnd(8)} in ${x.function}  ${x.resolved ? `by ${x.resolvedBy}${x.table ? ` at ${x.table}` : ''}: ${(x.targets ?? []).slice(0, 12).map((t: any) => t.name ?? t.addr).join(' ')}${(x.targets ?? []).length > 12 ? ' ...' : ''}` : 'unresolved'}`),
        ...(r.hasMore ? [`... more, use --offset ${r.offset + (r.sites?.length ?? 0)}`] : []),
      ].join('\n'),
    };
  }),
  wrap('match-functions', 'match-functions <file> <file2> [--no-names] [--min-confidence n] [--filter s] [--limit n] [--offset n] [--json]', 'Map functions between two binaries (versions, stripped vs unstripped)', 2, async (p) => {
    const r: any = await disasmMatchFunctions({ ...common(p), path2: p.pos[1]!, arch2: str(p.flags.arch2), useNames: p.flags['no-names'] ? false : undefined, minConfidence: num(p.flags['min-confidence']), filter: str(p.flags.filter), limit: num(p.flags.limit), offset: num(p.flags.offset), budgetMs: num(p.flags['budget-ms']) });
    return {
      json: r,
      text: () => [
        `${r.matched} matched (${r.identical} identical, ${r.changed} changed), ${r.unmatchedA} only in first, ${r.unmatchedB} only in second`,
        `methods: ${Object.entries(r.byMethod ?? {}).map(([k, v]) => `${k} ${v}`).join(', ')}`,
        ...(r.matches ?? []).map((m: any) => `${m.a.addr.padStart(12)} ${m.a.name.padEnd(28)} ${m.b.addr.padStart(12)} ${m.b.name.padEnd(28)} ${m.method.padEnd(9)} ${m.confidence.toFixed(2)}${m.identical ? '' : '  changed'}`),
        ...(r.hasMore ? [`... more, use --offset ${r.offset + r.matches.length}`] : []),
      ].join('\n'),
    };
  }),
  wrap('compare-functions', 'compare-functions <file> <function> [file2] [function2] [--context n] [--limit n] [--json]', 'Side by side diff of two functions with addresses normalized', 2, async (p) => {
    const r: any = await disasmCompareFunctions({ ...common(p), function: p.pos[1]!, path2: p.pos[2], function2: p.pos[3], arch2: str(p.flags.arch2), context: num(p.flags.context), limit: num(p.flags.limit) });
    return {
      json: r,
      text: () => [
        `${r.a.name} @ ${r.a.addr} (${r.a.insns} insns) vs ${r.b.name} @ ${r.b.addr} (${r.b.insns} insns): ${r.identical ? 'identical' : `similarity ${Number(r.similarity).toFixed(2)}`}`,
        `blocks: ${r.blocks?.identical ?? 0} identical, ${r.blocks?.changed ?? 0} changed`,
        ...(r.diff ?? []).map((l: any) => (l.op === '@@' ? l.text : `${l.op} ${(l.a ?? '').padStart(12)} ${(l.b ?? '').padStart(12)}  ${l.text}`)),
      ].join('\n'),
    };
  }),
];

/** Every disasm CLI command. */
export const CLI_COMMANDS: CliCommand[] = [...BASE_COMMANDS, ...R3_COMMANDS];
