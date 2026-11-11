// CLI commands for the revlens binary. Human text by default, JSON with --json.
import * as api from './api.js';
import { errMsg } from './util.js';

export interface CliCommand { name: string; usage: string; summary: string; run(argv: string[]): Promise<number> }

interface Parsed { pos: string[]; flags: Record<string, string | boolean> }
function parse(argv: string[]): Parsed {
  const pos: string[] = [];
  const flags: Record<string, string | boolean> = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i] as string;
    if (a.startsWith('--')) {
      const [k, v] = a.slice(2).split('=', 2) as [string, string | undefined];
      if (v !== undefined) flags[k] = v;
      else if (k === 'json' || k === 'members' || k === 'binaries' || k === 'no-listing' || k === 'bodies' || k === 'public') flags[k] = true;
      else if (i + 1 < argv.length && !(argv[i + 1] as string).startsWith('--')) flags[k] = argv[++i] as string;
      else flags[k] = true;
    } else pos.push(a);
  }
  return { pos, flags };
}
const num = (v: unknown): number | undefined => (v === undefined || v === true ? undefined : Number(v));
const str = (v: unknown): string | undefined => (typeof v === 'string' ? v : undefined);
const out = (s: string) => console.log(s);

async function wrap(argv: string[], usage: string, fn: (p: Parsed) => Promise<{ json: unknown; text: () => string }>): Promise<number> {
  const p = parse(argv);
  if (p.flags.help || !p.pos.length) { out(`usage: ${usage}`); return p.flags.help ? 0 : 2; }
  try {
    const r = await fn(p);
    out(p.flags.json ? JSON.stringify(r.json, (_k, v) => (typeof v === 'bigint' ? v.toString() : v instanceof Uint8Array ? undefined : v), 2) : r.text());
    return 0;
  } catch (e) { console.error(`error: ${errMsg(e)}`); return 1; }
}

function input(file: string): { path?: string; hex?: string } {
  return /^0x[0-9a-fA-F]+$/.test(file) ? { hex: file } : { path: file };
}

const kv = (o: Record<string, unknown>) => Object.entries(o).filter(([, v]) => v !== undefined && v !== '').map(([k, v]) => `${k}: ${typeof v === 'object' ? JSON.stringify(v) : v}`).join('\n');

export const CLI_COMMANDS: CliCommand[] = [
  {
    name: 'dotnet',
    usage: 'revlens dotnet <assembly.dll> [info | types [--filter s] [--members] | il <Type::Method|0x06token> | search <query> [--kind k]] [--json] [--limit n] [--offset n]',
    summary: 'Inspect a .NET assembly: metadata summary, types, CIL of a method, search and xrefs',
    run: (argv) => wrap(argv, CLI_COMMANDS[0]!.usage, async ({ pos, flags }) => {
      const [file, sub = 'info', arg] = pos as [string, string?, string?];
      const base = { ...input(file), offset: num(flags.offset), limit: num(flags.limit) };
      if (sub === 'types') {
        const r = await api.dotnetTypesTool({ ...base, filter: str(flags.filter), namespace: str(flags.namespace), members: !!flags.members }) as { items: { token: string; kind: string; fullName: string; methods: { token: string; name: string; signature: string }[] }[]; total: number };
        return { json: r, text: () => [`${r.total} types`, ...r.items.flatMap((t) => [`${t.token} ${t.kind} ${t.fullName}`, ...t.methods.map((m) => `    ${m.token} ${m.name} ${m.signature}`)])].join('\n') };
      }
      if (sub === 'il') {
        if (!arg) throw new Error('il needs a method');
        const r = await api.dotnetMethodIlTool({ ...base, method: arg, index: num(flags.index), format: 'text' }) as { text: string; overloads: string[] };
        return { json: await api.dotnetMethodIlTool({ ...base, method: arg, index: num(flags.index) }), text: () => (r.overloads.length > 1 ? `// ${r.overloads.length} overloads, use --index\n` : '') + r.text };
      }
      if (sub === 'search') {
        if (!arg) throw new Error('search needs a query');
        const r = await api.dotnetSearchTool({ ...base, query: arg, kind: str(flags.kind) }) as { items: Record<string, unknown>[]; total: number };
        return { json: r, text: () => [`${r.total} hits`, ...r.items.map((h) => 'from' in h ? `${h.fromToken} ${h.from} ${h.label} ${h.opcode} ${h.to}` : `${h.kind} ${h.token ?? ''} ${h.text}`)].join('\n') };
      }
      const r = await api.dotnetInfoTool(base) as Record<string, any>;
      return {
        json: r,
        text: () => [
          kv({ assembly: r.assembly ? `${r.assembly.name} ${r.assembly.version}` : r.module?.name, targetFramework: r.targetFramework, runtime: r.runtimeVersion, machine: r.machine, flags: r.cliFlags?.join(' '), entryPoint: r.entryPoint }),
          r.counts ? `counts: ${Object.entries(r.counts).map(([k, v]) => `${k}=${v}`).join(' ')}` : '',
          ...(r.assemblyRefs ?? []).map((a: any) => `ref ${a.name} ${a.version} ${a.publicKeyToken}`),
          ...(r.pinvoke ?? []).slice(0, 50).map((p: any) => `pinvoke ${p.library}!${p.entry} -> ${p.member}`),
          ...(r.resources ?? []).map((x: any) => `resource ${x.name} ${x.size ?? ''} bytes at ${x.offset ?? '?'}`),
          ...(r.obfuscators ?? []).map((o: any) => `obfuscator ${o.name}: ${o.evidence}`),
          r.readyToRun ? `ReadyToRun ${r.readyToRun.majorVersion}.${r.readyToRun.minorVersion} ${r.readyToRun.compositeOrComponent ?? ''}` : '',
          r.singleFileBundle ? `single-file bundle ${r.singleFileBundle.version} with ${r.singleFileBundle.fileCount} files` : '',
        ].filter(Boolean).join('\n'),
      };
    }),
  },
  {
    name: 'pyc',
    usage: 'revlens pyc <file.pyc> [--code <path>] [--version 3.x] [--json]',
    summary: 'Disassemble Python 3.7 to 3.13 bytecode like dis',
    run: (argv) => wrap(argv, CLI_COMMANDS[1]!.usage, async ({ pos, flags }) => {
      const r = await api.pycDisasmTool({ path: pos[0], codePath: str(flags.code), version: str(flags.version), format: flags.json ? 'json' : 'text', limit: num(flags.limit), offset: num(flags.offset) }) as { text?: string; version: string };
      return { json: r, text: () => `# Python ${r.version}\n${r.text ?? ''}` };
    }),
  },
  {
    name: 'pyinstaller',
    usage: 'revlens pyinstaller <app> [list | extract --out <dir> [--filter s]] [--json]',
    summary: 'List or extract a PyInstaller executable with fixed .pyc headers',
    run: (argv) => wrap(argv, CLI_COMMANDS[2]!.usage, async ({ pos, flags }) => {
      const [file, sub = 'list'] = pos as [string, string?];
      if (sub === 'extract') {
        const outDir = str(flags.out);
        if (!outDir) throw new Error('extract needs --out <dir>');
        const r = await api.pyinstallerExtractTool({ path: file, outDir, filter: str(flags.filter), limit: num(flags.limit) ?? 5000 }) as { written: number; outDir: string; errors: string[] };
        return { json: r, text: () => [`wrote ${r.written} files to ${r.outDir}`, ...r.errors.map((e) => `warning: ${e}`)].join('\n') };
      }
      const r = await api.pyinstallerListTool({ path: file, limit: num(flags.limit) ?? 5000, offset: num(flags.offset) }) as Record<string, any>;
      return {
        json: r,
        text: () => [
          kv({ pythonVersion: r.pythonVersion, pylib: r.pylibName, cookieOffset: r.cookieOffset, entryPoints: r.entryPoints.join(', ') }),
          ...r.entries.items.map((e: any) => `${e.type} ${String(e.size).padStart(10)} @${e.offset} ${e.name}`),
          r.pyz?.entries ? `PYZ ${r.pyz.modules} modules` : '',
          ...(r.pyz?.entries?.items ?? []).map((e: any) => `  ${e.typeName.padEnd(7)} ${e.name}`),
        ].filter(Boolean).join('\n'),
      };
    }),
  },
  {
    name: 'lua',
    usage: 'revlens lua <file.luac> [--json] [--no-listing]',
    summary: 'List Lua 5.1 to 5.4 and LuaJIT bytecode',
    run: (argv) => wrap(argv, CLI_COMMANDS[3]!.usage, async ({ pos, flags }) => {
      const r = await api.luaInfoTool({ path: pos[0], listing: !flags['no-listing'], maxLines: num(flags.limit) }) as Record<string, any>;
      return { json: r, text: () => `${r.flavor} ${r.version}, ${r.functionCount} functions${r.stripped ? ', stripped' : ''}\n${r.listing ?? ''}` };
    }),
  },
  {
    name: 'beam',
    usage: 'revlens beam <file.beam> [--json]',
    summary: 'List an Erlang or Elixir BEAM module: chunks, exports, imports',
    run: (argv) => wrap(argv, CLI_COMMANDS[4]!.usage, async ({ pos }) => {
      const r = await api.beamInfoTool({ path: pos[0] }) as Record<string, any>;
      return {
        json: r,
        text: () => [
          `module ${r.module}${r.elixir ? ' (Elixir)' : ''}, ${r.atomCount} atoms`,
          `chunks: ${r.chunks.map((c: any) => `${c.id}@${c.offset}+${c.size}`).join(' ')}`,
          ...r.exports.map((e: any) => `export ${e.name}/${e.arity} label ${e.label}`),
          ...r.imports.map((e: any) => `import ${e.module}:${e.name}/${e.arity}`),
        ].join('\n'),
      };
    }),
  },
  {
    name: 'evm',
    usage: 'revlens evm <file | 0xhex> [selectors | disasm] [--json] [--limit n]',
    summary: 'EVM bytecode: selectors, proxy patterns, metadata, disassembly',
    run: (argv) => wrap(argv, CLI_COMMANDS[5]!.usage, async ({ pos, flags }) => {
      const [file, sub = 'selectors'] = pos as [string, string?];
      if (sub === 'disasm') {
        const r = await api.evmDisasmTool({ ...input(file), limit: num(flags.limit) ?? 5000, offset: num(flags.offset) }) as Record<string, any>;
        return { json: r, text: () => r.instructions.items.map((i: any) => `${i.pc.toString(16).padStart(5, '0')}: ${i.op}${i.push !== undefined ? ' 0x' + i.push : ''}`).join('\n') };
      }
      const r = await api.evmSelectorsTool(input(file)) as Record<string, any>;
      return {
        json: r,
        text: () => [
          `${r.codeSize} bytes of code${r.metadata?.solc ? `, solc ${r.metadata.solc}` : ''}${r.metadata?.ipfs ? `, ipfs ${r.metadata.ipfs}` : ''}`,
          ...r.selectors.map((s: any) => `0x${s.selector} ${s.signature ?? '?'}${s.target !== undefined ? ` -> 0x${s.target.toString(16)}` : ''}`),
          ...r.proxy.map((p: any) => `proxy ${p.kind}: ${p.evidence}`),
          ...r.events.map((e: any) => `event ${e.signature}`),
        ].join('\n'),
      };
    }),
  },
  {
    name: 'pinvoke-map',
    usage: 'revlens pinvoke-map <assembly.dll> <native lib>... [--status resolved|missing-export|library-not-shipped] [--json]',
    summary: 'Match .NET DllImports to exports of shipped native libraries',
    run: (argv) => wrap(argv, 'revlens pinvoke-map <assembly.dll> <native lib>... [--status s] [--json]', async ({ pos, flags }) => {
      const [file, ...libs] = pos as [string, ...string[]];
      const r = await api.pinvokeMapTool({ ...input(file), libraries: libs, status: str(flags.status), limit: 2000 }) as Record<string, any>;
      return {
        json: r,
        text: () => [
          `${r.summary.total} P/Invoke: ${r.summary.resolved} resolved, ${r.summary['missing-export']} missing export, ${r.summary['library-not-shipped']} library not shipped`,
          ...r.libraries.map((l: any) => `lib ${l.file} (${l.format} ${l.arch ?? ''}) ${l.exports} exports, ${l.referenced} referenced${l.error ? ' error: ' + l.error : ''}`),
          ...r.bindings.items.map((b: any) => `${b.status.padEnd(19)} ${b.library}!${b.entry} <- ${b.member}${b.matches.length ? '  ' + b.matches.map((m: any) => `${m.platform}:${m.address ?? m.forwarder}`).join(' ') : ''}`),
        ].join('\n'),
      };
    }),
  },
  {
    name: 'compare-members',
    usage: 'revlens compare-members <old.dll> <new.dll> [--bodies] [--public] [--filter s] [--json]',
    summary: 'Diff types, methods, fields and signatures between two .NET assemblies',
    run: (argv) => wrap(argv, 'revlens compare-members <old.dll> <new.dll> [--bodies] [--public] [--filter s] [--json]', async ({ pos, flags }) => {
      const [a, b] = pos as [string, string?];
      const r = await api.compareMembersTool({ path: a, otherPath: b, bodies: !!flags.bodies, publicOnly: !!flags.public, filter: str(flags.filter), limit: 2000 }) as Record<string, any>;
      return {
        json: r,
        text: () => {
          const out = [`types ${r.types.a} -> ${r.types.b}: +${r.types.added.length} -${r.types.removed.length} changed ${r.types.changed}; methods +${r.methods.added} -${r.methods.removed} ~${r.methods.changed}; fields +${r.fields.added} -${r.fields.removed}`];
          for (const t of r.types.added) out.push(`+ type ${t}`);
          for (const t of r.types.removed) out.push(`- type ${t}`);
          for (const c of r.changes.items) {
            out.push(`~ ${c.type}`);
            for (const m of c.methods.added) out.push(`  + ${m}`);
            for (const m of c.methods.removed) out.push(`  - ${m}`);
            for (const m of c.methods.changed) out.push(`  * ${m.from} -> ${m.to}`);
            for (const f of c.fields.added) out.push(`  + field ${f}`);
            for (const f of c.fields.removed) out.push(`  - field ${f}`);
          }
          return out.join('\n');
        },
      };
    }),
  },
];
