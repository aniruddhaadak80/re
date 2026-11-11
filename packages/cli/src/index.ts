#!/usr/bin/env node
// RevLens CLI. Core commands plus every package's commands, with plain argument parsing.
import { readFileSync, writeFileSync, openSync, fstatSync, closeSync } from 'node:fs';
import { basename } from 'node:path';
import {
  diff, verifyClaim, scanRules, STARTER_RULES, toSARIF, toMarkdown, toHTML, toCycloneDX, lookupOSV,
  REVLENS_VERSION, type Report, type Claim, type Severity, type FormatId,
} from '@revlens/core';
import { analyzeAllNode as analyzeAll, ALL_ANALYZERS_NODE as ALL_ANALYZERS, PACKAGES, TOOL_GROUPS, TOP_LEVEL_COMMANDS, packageViews, type PackageCommand } from '@revlens/engine/node';
import { toolCatalog } from '@revlens/mcp/server';

const C = process.stdout.isTTY && !process.env.NO_COLOR
  ? { gold: (s: string) => `\x1b[38;5;220m${s}\x1b[0m`, teal: (s: string) => `\x1b[38;5;37m${s}\x1b[0m`, dim: (s: string) => `\x1b[2m${s}\x1b[0m`,
      red: (s: string) => `\x1b[31m${s}\x1b[0m`, orange: (s: string) => `\x1b[38;5;208m${s}\x1b[0m`, bold: (s: string) => `\x1b[1m${s}\x1b[0m` }
  : { gold: String, teal: String, dim: String, red: String, orange: String, bold: String } as Record<string, (s: string) => string>;

const SEV_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
const sevColor = (s: Severity) => (s === 'critical' ? C.red! : s === 'high' ? C.orange! : s === 'medium' ? C.gold! : s === 'low' ? C.teal! : C.dim!)(s.toUpperCase().padEnd(8));

const OPTIONS_HELP = `Options
  --json  --md  --html  --sarif  --cyclonedx   Output format (default is a readable summary)
  --out <path>        Write output to a file
  --osv               Look up known vulnerabilities on OSV.dev (network, opt in)
  --rules <file>      Extra yara-lite rules
  --packages <list>   analyze: only these packages (comma list of ${PACKAGES.map((p) => p.id).join(', ')}); core always runs
  --fail-on <sev>     Exit with code 2 when a finding at or above this severity exists
  --claim <json>      verify: a claim (or array of claims) as JSON
  --strict            verify: exit with code 3 when any claim is REFUTED
  --fail-on-match     rules: exit with code 2 when any rule matches
  --max-strings <n>   Strings to keep in the report (default 400)
  --no-recurse        Do not analyze archive members
  -h, --help  -v, --version`;

const CORE_COMMANDS = new Set(['analyze', 'scan', 'diff', 'verify', 'rules', 'sbom', 'sarif', 'analyzers', 'tools', 'mcp', 'serve-mcp', 'help', ...TOP_LEVEL_COMMANDS.map((c) => c.name)]);

/** Argument text of a package usage line, without the leading "revlens" and command name. */
function usageArgs(c: PackageCommand): string {
  return c.usage.replace(/^usage:\s*/, '').replace(/^revlens\s+/, '').replace(new RegExp(`^${c.name.replace(/[-]/g, '\\-')}\\b\\s*`), '');
}

/** A package command can also be called without its area when its name is unique and not a core command. */
function flatAliases(): Map<string, { group: string; cmd: PackageCommand }> {
  const seen = new Map<string, number>();
  for (const g of TOOL_GROUPS) for (const c of g.commands) seen.set(c.name, (seen.get(c.name) ?? 0) + 1);
  const out = new Map<string, { group: string; cmd: PackageCommand }>();
  for (const g of TOOL_GROUPS) for (const c of g.commands) if (seen.get(c.name) === 1 && !CORE_COMMANDS.has(c.name)) out.set(c.name, { group: g.id, cmd: c });
  return out;
}

function areaHelp(id: string): string {
  const g = TOOL_GROUPS.find((x) => x.id === id);
  if (!g) return `unknown area "${id}". Areas: ${TOOL_GROUPS.map((x) => x.id).join(', ')}`;
  const L = [`${C.gold!('revlens ' + g.id)}  ${g.title} (${g.npm})`, ''];
  const w = Math.max(...g.commands.map((c) => c.name.length));
  for (const c of g.commands) {
    L.push(`  revlens ${g.id} ${c.name.padEnd(w)}  ${c.summary}`);
    const args = usageArgs(c);
    if (args) L.push(C.dim!(`  ${' '.repeat(9 + g.id.length + w)}  ${args}`));
  }
  L.push('', C.dim!('Every command takes --json for machine readable output and --help for details.'));
  return L.join('\n');
}

function fullHelp(): string {
  const L = [`${C.gold!('RevLens')} ${REVLENS_VERSION}  reverse engineer binaries, bundles, apps, bytecode, captures and databases`, '',
    'Core',
    '  revlens analyze <file...>        Analyze with every analyzer (core and all packages) and print a summary',
    '  revlens diff <old> <new>         Show what changed between two versions',
    '  revlens verify <file> <claim>    Check a claim against the bytes',
    '                                   claims: string=TEXT  import=SYMBOL  section=NAME',
    '                                           format=elf  sha256=HEX  at=OFFSET:HEX  uses=NAME[@VER]',
    '  revlens rules <file> [--rules r] Run the yara-lite rule pack (plus your rules)',
    '  revlens sbom <file>              Print a CycloneDX 1.5 SBOM',
    '  revlens sarif <file>             Print SARIF 2.1.0 for GitHub code scanning',
    '  revlens analyzers                List analyzers from every package',
    '  revlens tools [--json]           List every MCP tool the server offers',
    '  revlens mcp                      Start the MCP server on stdio',
    '',
    'Setup and external tools',
    ...TOP_LEVEL_COMMANDS.map((c) => `  ${c.usage.replace(/^revlens\s+/, 'revlens ').split('   ')[0]!.padEnd(32)} ${c.summary}`),
    ''];
  for (const g of TOOL_GROUPS) if (g.commands.length) L.push(`${g.title}  ${C.dim!(`revlens ${g.id} <command>, see revlens help ${g.id}`)}`, '  ' + g.commands.map((c) => c.name).join('  '), '');
  L.push(C.dim!('Commands with a unique name also work without the area, for example revlens smali app.apk.'), '', OPTIONS_HELP);
  return L.join('\n');
}

interface Args { _: string[]; flags: Record<string, string | boolean> }
function parse(argv: string[]): Args {
  const a: Args = { _: [], flags: {} };
  const valued = new Set(['out', 'rules', 'fail-on', 'max-strings', 'claim', 'packages', 'dir']);
  for (let i = 0; i < argv.length; i++) {
    const t = argv[i] as string;
    if (t === '-h') a.flags.help = true;
    else if (t === '-v') a.flags.version = true;
    else if (t.startsWith('--')) {
      const [k, v] = t.slice(2).split('=', 2) as [string, string | undefined];
      if (v !== undefined) a.flags[k] = v;
      else if (valued.has(k)) a.flags[k] = argv[++i] ?? '';
      else a.flags[k] = true;
    } else a._.push(t);
  }
  return a;
}

/** Opens the file once and checks and reads that same descriptor, so it cannot be swapped in between. */
function read(path: string): Uint8Array {
  const fd = openSync(path, 'r');
  try {
    if (!fstatSync(fd).isFile()) throw new Error(`${path} is not a file`);
    return new Uint8Array(readFileSync(fd));
  } finally { closeSync(fd); }
}

function emit(text: string, flags: Args['flags']) {
  if (typeof flags.out === 'string' && flags.out) { writeFileSync(flags.out, text); console.error(C.dim!(`wrote ${flags.out}`)); }
  else process.stdout.write(text.endsWith('\n') ? text : text + '\n');
}

function summary(r: Report): string {
  const L: string[] = [];
  const f = r.file;
  L.push(`${C.gold!(C.bold!(f.name))}  ${C.dim!(`${f.format}${f.arch ? ` ${f.arch}` : ''}${f.bits ? ` ${f.bits}-bit` : ''}  ${f.size.toLocaleString('en-US')} bytes  entropy ${f.entropy.toFixed(2)}  ${r.timings.total} ms`)}`);
  L.push(C.dim!(`sha256 ${f.hashes.sha256}`));
  if (r.hardening) L.push(C.dim!('hardening ') + Object.entries(r.hardening).map(([k, v]) => `${k}=${v}`).join('  '));
  if (r.sections.length) L.push(C.dim!(`sections  `) + r.sections.slice(0, 12).map((s) => `${s.name}(${s.entropy.toFixed(1)})`).join(' '));
  const imps = r.imports.reduce((n, i) => n + i.symbols.length, 0);
  if (imps) L.push(C.dim!(`imports   `) + `${imps} from ${r.imports.length} ${r.imports.length === 1 ? 'library' : 'libraries'}: ${r.imports.slice(0, 6).map((i) => i.library).join(', ')}`);
  if (r.components.length) L.push(C.dim!(`sbom      `) + r.components.slice(0, 10).map((c) => `${c.name}${c.version ? '@' + c.version : ''}`).join(', ') + (r.components.length > 10 ? ` and ${r.components.length - 10} more` : ''));
  if (r.capabilities.length) L.push(C.dim!(`abilities `) + r.capabilities.map((c) => c.name + (c.attack ? C.dim!(` ${c.attack}`) : '')).join(', '));
  const views = packageViews(r);
  if (views.length) L.push(C.dim!(`deep      `) + views.join('; '));
  if (r.meta.memberCount) L.push(C.dim!(`members   `) + `${r.meta.memberCount} files, ${r.children?.length ?? 0} analyzed`);
  L.push('');
  if (!r.findings.length) L.push(C.teal!('No findings.'));
  for (const x of r.findings.slice(0, 40)) {
    const ev = x.evidence[0];
    const where = ev ? C.dim!(` ${ev.path ? ev.path : ''}${ev.offset !== undefined ? `@${ev.offset}` : ''}`) : '';
    L.push(`${sevColor(x.severity)} ${x.title}${where}`);
  }
  if (r.findings.length > 40) L.push(C.dim!(`and ${r.findings.length - 40} more, use --json or --md for all`));
  return L.join('\n');
}

function parseClaim(s: string): Claim {
  const [k, ...rest] = s.split('=');
  const v = rest.join('=');
  switch (k) {
    case 'string': return { kind: 'contains-string', value: v };
    case 'import': return { kind: 'imports-symbol', symbol: v };
    case 'section': return { kind: 'has-section', name: v };
    case 'format': return { kind: 'format-is', format: v as FormatId };
    case 'sha256': return { kind: 'sha256-is', value: v };
    case 'at': { const [o, h] = v.split(':'); return { kind: 'bytes-at', offset: Number(o), hex: h ?? '' }; }
    case 'uses': { const [n, ver] = v.split(/@(?=[^@]*$)/); return { kind: 'uses-component', name: n ?? v, version: ver }; }
  }
  throw new Error(`unknown claim "${s}". Try string=, import=, section=, format=, sha256=, at=, uses=`);
}

async function run(file: string, flags: Args['flags']): Promise<Report> {
  const rules = typeof flags.rules === 'string' ? readFileSync(flags.rules, 'utf8') : undefined;
  const packages = typeof flags.packages === 'string' ? flags.packages.split(',').map((x) => x.trim()).filter(Boolean) : undefined;
  const r = await analyzeAll(read(file), { name: basename(file), rules, recurse: !flags['no-recurse'], packages,
    maxStrings: flags['max-strings'] ? Number(flags['max-strings']) : undefined });
  if (flags.osv) {
    const all = [r, ...(r.children ?? [])].flatMap((x) => x.components);
    try { r.findings.unshift(...await lookupOSV(all)); } catch (e) { console.error(C.orange!(`OSV lookup failed: ${(e as Error).message}`)); }
  }
  return r;
}

async function main(): Promise<number> {
  const a = parse(process.argv.slice(2));
  const [cmd, ...rest] = a._;
  if (a.flags.version && !cmd) { console.log(REVLENS_VERSION); return 0; }
  if (!cmd) { console.log(fullHelp()); return 0; }
  const f = a.flags;
  if (cmd === 'help') { console.log(rest[0] ? areaHelp(rest[0]) : fullHelp()); return 0; }
  const top = TOP_LEVEL_COMMANDS.find((c) => c.name === cmd);
  if (top) { const raw = process.argv.slice(2); return top.run(raw.slice(raw.indexOf(cmd) + 1)); }
  if (a.flags.help && CORE_COMMANDS.has(cmd)) { console.log(fullHelp()); return 0; }

  switch (cmd) {
    case 'analyzers':
      if (f.json) { emit(JSON.stringify(ALL_ANALYZERS, null, 2), f); return 0; }
      for (const x of ALL_ANALYZERS) console.log(`${C.gold!(x.id.padEnd(16))} ${C.teal!(x.package.padEnd(8))} ${x.title.padEnd(30)} ${C.dim!(x.description)}`);
      return 0;
    case 'tools': {
      const all = toolCatalog().map((t) => ({ name: t.name, group: t.group, description: t.description, readOnly: t.annotations.readOnlyHint }));
      if (f.json) { emit(JSON.stringify(all, null, 2), f); return 0; }
      for (const g of ['core', ...TOOL_GROUPS.map((x) => x.id)]) {
        const list = all.filter((t) => t.group === g);
        console.log(C.gold!(`${g} (${list.length})`));
        for (const t of list) console.log(`  ${t.name.padEnd(28)} ${C.dim!(t.description.split('. ')[0]!.slice(0, 100))}`);
      }
      console.log(C.dim!(`${all.length} MCP tools in total`));
      return 0;
    }

    case 'analyze': case 'scan': {
      if (!rest.length) throw new Error('give at least one file');
      const reports: Report[] = [];
      for (const file of rest) reports.push(await run(file, f));
      if (f.json) emit(JSON.stringify(reports.length === 1 ? reports[0] : reports, null, 2), f);
      else if (f.md) emit(reports.map(toMarkdown).join('\n\n---\n\n'), f);
      else if (f.html) emit(toHTML(reports[0] as Report), f);
      else if (f.sarif) emit(JSON.stringify(toSARIF(reports[0] as Report), null, 2), f);
      else if (f.cyclonedx) emit(JSON.stringify(toCycloneDX(reports[0] as Report), null, 2), f);
      else emit(reports.map(summary).join('\n\n'), f);
      return failCode(reports, f);
    }
    case 'sarif': { const r = await run(need(rest[0]), f); emit(JSON.stringify(toSARIF(r), null, 2), f); return failCode([r], f); }
    case 'sbom': { const r = await run(need(rest[0]), f); emit(JSON.stringify(toCycloneDX(r), null, 2), f); return 0; }
    case 'diff': {
      const [x, y] = [need(rest[0]), need(rest[1])];
      const d = diff(await run(x, f), await run(y, f));
      if (f.json) { emit(JSON.stringify(d, null, 2), f); return 0; }
      const L = [C.gold!(d.summary), ''];
      const show = (label: string, cs: { added: unknown[]; removed: unknown[]; changed?: { before: unknown; after: unknown }[] }, fmt: (v: never) => string) => {
        if (!cs.added.length && !cs.removed.length && !cs.changed?.length) return;
        L.push(C.bold!(label));
        for (const v of cs.added.slice(0, 30)) L.push(C.teal!(`  + ${fmt(v as never)}`));
        for (const v of cs.removed.slice(0, 30)) L.push(C.red!(`  - ${fmt(v as never)}`));
        for (const v of cs.changed?.slice(0, 30) ?? []) L.push(C.gold!(`  ~ ${fmt(v.before as never)} -> ${fmt(v.after as never)}`));
      };
      show('Dependencies', d.components, (c: { name: string; version?: string }) => `${c.name}@${c.version ?? '?'}`);
      show('Endpoints', d.endpoints, (s: string) => s);
      show('Imports', d.imports, (s: string) => s);
      show('Exports', d.exports, (s: string) => s);
      show('Capabilities', d.capabilities, (s: string) => s);
      show('Findings', d.findings, (x: { title: string; severity: string }) => `${x.severity} ${x.title}`);
      show('Sections', d.sections, (s: { name: string; size: number }) => `${s.name} ${s.size}`);
      emit(L.join('\n'), f);
      return 0;
    }
    case 'verify': {
      const file = need(rest[0]);
      const bytes = read(file);
      const r = await analyzeAll(bytes, { name: basename(file) });
      let worst = 0;
      const claims: [string, Claim][] = rest.slice(1).map((c) => [c, parseClaim(c)]);
      if (typeof f.claim === 'string') {
        const parsed = JSON.parse(f.claim) as Claim | Claim[];
        for (const c of Array.isArray(parsed) ? parsed : [parsed]) claims.push([JSON.stringify(c), c]);
      }
      if (!claims.length) throw new Error('give a claim, for example section=.text or --claim \'{"kind":"has-section","name":".text"}\'');
      for (const [c, claim] of claims) {
        const res = verifyClaim(bytes, claim, r);
        if (f.json) console.log(JSON.stringify(res));
        else console.log(`${res.verdict === 'VERIFIED' ? C.teal!('VERIFIED') : res.verdict === 'REFUTED' ? C.red!('REFUTED ') : C.gold!('UNKNOWN ')} ${c}  ${C.dim!(res.reason)}`);
        if (res.verdict === 'REFUTED') worst = 3;
      }
      return f.strict ? worst : 0;
    }
    case 'rules': {
      const file = need(rest[0]);
      const extra = typeof f.rules === 'string' ? readFileSync(f.rules, 'utf8') : '';
      const matches = scanRules(read(file), (f['no-starter'] ? '' : STARTER_RULES) + '\n' + extra);
      if (f.json) emit(JSON.stringify(matches, null, 2), f);
      else if (!matches.length) console.log(C.teal!('No rules matched.'));
      else for (const m of matches) console.log(`${C.gold!(m.rule)} ${C.dim!(m.tags.join(' '))}  ${m.meta.description ?? ''}\n${m.strings.slice(0, 4).map((s) => C.dim!(`    ${s.id} @${s.offset} ${s.snippet}`)).join('\n')}`);
      return f['fail-on-match'] && matches.length ? 2 : 0;
    }
    case 'mcp': case 'serve-mcp': {
      const { StdioServerTransport } = await import('@modelcontextprotocol/sdk/server/stdio.js');
      const { server } = (await import('@revlens/mcp/server')).createServer();
      await server.connect(new StdioServerTransport());
      return -1;
    }
  }
  const group = TOOL_GROUPS.find((g) => g.id === cmd);
  const raw = process.argv.slice(2);
  const after = raw.slice(raw.indexOf(cmd) + 1);
  if (group) {
    const sub = group.commands.find((c) => c.name === after[0]);
    if (sub) return sub.run(after.slice(1));
    if (!after.length || after[0] === '--help' || after[0] === '-h') { console.log(areaHelp(group.id)); return 0; }
    // "revlens disasm <file>" keeps working: the area id is also a disasm command name
    const same = group.commands.find((c) => c.name === cmd);
    if (same) return same.run(after);
    throw new Error(`unknown ${group.id} command "${after[0]}". Run revlens help ${group.id}`);
  }
  const alias = flatAliases().get(cmd);
  if (alias) return alias.cmd.run(after);
  throw new Error(`unknown command "${cmd}". Run revlens --help`);
}

function need(v: string | undefined): string { if (!v) throw new Error('missing file argument'); return v; }

function failCode(reports: Report[], f: Args['flags']): number {
  if (typeof f['fail-on'] !== 'string') return 0;
  const limit = SEV_ORDER.indexOf(f['fail-on'] as Severity);
  if (limit < 0) throw new Error(`--fail-on takes one of ${SEV_ORDER.join(', ')}`);
  return reports.some((r) => r.findings.some((x) => SEV_ORDER.indexOf(x.severity) <= limit)) ? 2 : 0;
}

main().then((code) => { if (code >= 0) process.exitCode = code; }, (e: Error) => { console.error(C.red!('error: ') + e.message); process.exitCode = 1; });
