#!/usr/bin/env node
// Generate docs/parity/*.md from the two inventories and the reviewed decisions in mapping.mjs.
// Usage: node scripts/parity/generate.mjs [--check]
//   --check  fail (exit 1) when a rea tool, command, format or setting has no reviewed row, or a row
//            names a RevLens tool or command that does not exist. Writes nothing.
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import * as M from './mapping.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, '..', '..');
const DOCS = join(ROOT, 'docs', 'parity');
const rea = JSON.parse(readFileSync(join(DOCS, 'data', 'rea-inventory.json'), 'utf8'));
const rl = JSON.parse(readFileSync(join(DOCS, 'data', 'revlens-inventory.json'), 'utf8'));
const bench = existsSync(join(DOCS, 'data', 'bench.json')) ? JSON.parse(readFileSync(join(DOCS, 'data', 'bench.json'), 'utf8')) : undefined;
const CHECK = process.argv.includes('--check');

const rlTools = new Map(rl.tools.map((t) => [t.name, t]));
const rlCommands = new Set([...rl.commands.map((c) => c.path), ...rl.coreCommands]);
const problems = [];

// ---------- validation ----------
const reaToolNames = rea.tools.map((t) => t.name);
for (const n of reaToolNames) if (!M.TOOLS[n]) problems.push(`rea tool without a row: ${n}`);
for (const n of Object.keys(M.TOOLS)) if (!reaToolNames.includes(n)) problems.push(`row for unknown rea tool: ${n}`);
for (const [n, r] of Object.entries(M.TOOLS)) for (const t of r.rl) if (!rlTools.has(t)) problems.push(`${n}: unknown RevLens tool ${t}`);
for (const [cmd, tools] of Object.entries(M.RL_CLI_TOOLS)) {
  const base = cmd.replace(/ --.*$/, '');
  if (!rlCommands.has(base)) problems.push(`RL_CLI_TOOLS names unknown RevLens command ${cmd}`);
  for (const t of tools) if (!rlTools.has(t)) problems.push(`RL_CLI_TOOLS ${cmd}: unknown tool ${t}`);
}
const reaCmdNames = rea.commands.map((c) => c.path);
for (const c of reaCmdNames) if (!rlToolForCommand(c) && !M.CLI_EXTRA[c]) problems.push(`rea command without a row: ${c}`);
for (const [c, r] of Object.entries(M.CLI_EXTRA)) {
  if (!reaCmdNames.includes(c)) problems.push(`CLI_EXTRA row for unknown rea command ${c}`);
  for (const x of r.rl) if (!rlCommands.has(x) && !/^bridge \S+$/.test(x) && !/^disasm |^extras /.test(x)) problems.push(`CLI_EXTRA ${c}: unknown RevLens command ${x}`);
  for (const x of r.rl) if (/^(disasm|extras) /.test(x) && !rlCommands.has(x)) problems.push(`CLI_EXTRA ${c}: unknown RevLens command ${x}`);
  for (const x of r.rl) if (/^bridge /.test(x) && !rlTools.has('bridge_' + x.slice(7))) problems.push(`CLI_EXTRA ${c}: unknown bridge tool ${x}`);
}
for (const f of rea.artifactFormats) if (!M.FORMATS[f]) problems.push(`rea artifact format without a row: ${f}`);
for (const f of rea.cliOutputFormats) if (!M.OUTPUT_FORMATS[f]) problems.push(`rea output format without a row: ${f}`);
const reaConfig = [...new Set([...rea.envSchemaKeys, ...rea.debuggerSettings, ...rea.envNames.map((e) => e.name)])];
for (const k of reaConfig) if (!M.CONFIG[k] && !M.CONFIG_INTERNAL.includes(k)) problems.push(`rea setting without a row: ${k}`);
for (const k of Object.keys(M.CONFIG)) if (!reaConfig.includes(k)) problems.push(`row for unknown rea setting: ${k}`);
for (const k of Object.keys(M.FORMATS)) if (!k.includes('(') && !rea.artifactFormats.includes(k)) problems.push(`row for unknown rea format: ${k}`);

if (problems.length) {
  console.error(problems.join('\n'));
  if (CHECK) process.exit(1);
}
if (CHECK) { console.log('parity rows complete'); process.exit(0); }

function rlToolForCommand(c) {
  const t = c.replace(/-/g, '_');
  return M.TOOLS[t] ? t : undefined;
}

// ---------- helpers ----------
const esc = (s) => String(s ?? '').replace(/\|/g, '\\|').replace(/\r?\n/g, ' ');
const firstSentence = (s, max = 170) => {
  const t = String(s ?? '').replace(/\s+/g, ' ').trim();
  const i = t.search(/\.\s/);
  const one = i > 20 && i < max ? t.slice(0, i + 1) : t;
  return one.length > max ? one.slice(0, max - 3).replace(/\s+\S*$/, '') + '...' : one;
};
const STATUS_ORDER = ['equal', 'better', 'partial', 'missing'];
const statusCell = (r) => {
  if (!r.wip) return r.status;
  const w = M.IN_PROGRESS[r.wip];
  return `${r.status}, in progress (${w.branch})`;
};
const code = (xs) => xs.length ? xs.map((x) => '`' + x + '`').join(', ') : '-';
const totals = (rows) => {
  const t = { rows: rows.length, equal: 0, better: 0, partial: 0, missing: 0, inProgress: 0 };
  for (const r of rows) { t[r.status]++; if (r.wip && (r.status === 'missing' || r.status === 'partial')) t.inProgress++; }
  t.covered = t.equal + t.better;
  return t;
};
const totalsLine = (t) => `${t.rows} rows: ${t.equal} equal, ${t.better} better, ${t.partial} partial, ${t.missing} missing (${t.inProgress} of the partial or missing rows are in progress on a round-3 branch). Covered (equal or better): ${t.covered} of ${t.rows}.`;
const header = (title, intro) => [
  `# ${title}`,
  '',
  'Generated by `node scripts/parity/generate.mjs` from `docs/parity/data/rea-inventory.json` (morluto/rea ' +
    `${rea.generatedFrom.version}, commit ${rea.generatedFrom.commit.slice(0, 10)}) and \`docs/parity/data/revlens-inventory.json\` ` +
    `(RevLens main ${(rl.generatedFrom.mainCommit ?? rl.generatedFrom.commit).slice(0, 10)}). Decisions live in \`scripts/parity/mapping.mjs\`; edit them there and regenerate.`,
  '',
  'rea is used for scope only. RevLens is not REA and is not affiliated with it.',
  '',
  intro,
  '',
  'Status: equal means a RevLens tool does the same job; better means the same job and more; partial means part of the job, with the gap in the note; missing means no RevLens tool does it. "in progress" names the round-3 branch adding it.',
  '',
].join('\n');

// ---------- rea-tools.md ----------
const toolRows = rea.tools.map((t) => ({ ...M.TOOLS[t.name], name: t.name, family: t.family ?? 'none', desc: t.description, inputs: t.inputs }));
const famOrder = rea.toolFamilies;
let md = header('rea MCP tools against RevLens', `Every MCP tool in rea's TOOL_CONTRACTS (${rea.tools.length} tools), grouped by rea tool family.\n\n**Totals.** ${totalsLine(totals(toolRows))}`);
for (const fam of [...famOrder, 'none']) {
  const rows = toolRows.filter((r) => r.family === fam);
  if (!rows.length) continue;
  md += `\n## ${fam} (${rows.length})\n\n${totalsLine(totals(rows))}\n\n| rea tool | what it does | inputs | RevLens tool(s) | status | note |\n|---|---|---|---|---|---|\n`;
  for (const r of rows) md += `| \`${r.name}\` | ${esc(firstSentence(r.desc))} | ${esc(r.inputs.map((i) => i.name + (i.required ? '*' : '')).join(', ') || '-')} | ${code(r.rl)} | ${statusCell(r)} | ${esc(r.note)} |\n`;
}
const usedRl = new Set(Object.values(M.TOOLS).flatMap((r) => r.rl));
const rlOnly = rl.tools.filter((t) => !usedRl.has(t.name));
md += `\n## RevLens tools with no rea counterpart (${rlOnly.length})\n\nThese go beyond rea's catalog.\n\n| RevLens tool | package | what it does |\n|---|---|---|\n`;
for (const t of rlOnly) md += `| \`${t.name}\` | ${t.package ?? t.group} | ${esc(firstSentence(t.description))} |\n`;
writeFileSync(join(DOCS, 'rea-tools.md'), md);

// ---------- rea-cli.md ----------
const rlCmdsForTools = (tools) => {
  const out = new Set();
  for (const t of tools) {
    if (t.startsWith('bridge_')) out.add(`bridge ${t.slice(7)}`);
    for (const [cmd, ts] of Object.entries(M.RL_CLI_TOOLS)) if (ts.includes(t)) out.add(cmd);
  }
  return [...out];
};
const cliRows = rea.commands.map((c) => {
  const toolName = rlToolForCommand(c.path);
  const flags = c.options.map((o) => '--' + o.name.replace(/[A-Z]/g, (x) => '-' + x.toLowerCase()));
  const args = c.args.map((a) => `<${a.name}>`);
  if (!toolName) return { ...M.CLI_EXTRA[c.path], name: c.path, desc: c.description, args, flags, via: '' };
  const tr = M.TOOLS[toolName];
  const cmds = rlCmdsForTools(tr.rl);
  if (tr.status === 'missing' || !tr.rl.length) return { ...tr, rl: [], name: c.path, desc: c.description, args, flags, via: toolName };
  if (!cmds.length) return { status: 'partial', wip: tr.wip, owner: tr.owner ?? 'cli', rl: [], name: c.path, desc: c.description, args, flags, via: toolName, note: `MCP only: ${tr.rl.join(', ')} (${tr.status}) have no CLI command. ${tr.note}`.trim() };
  return { ...tr, rl: cmds, name: c.path, desc: c.description, args, flags, via: toolName };
});
md = header('rea CLI commands against RevLens', `Every command in rea's incur CLI tree (${rea.commands.length} commands; rea has no nested subcommands). For a command that wraps an MCP tool the status follows the tool row in rea-tools.md, and drops to partial when the RevLens tool has no CLI command (\`revlens bridge <tool>\` runs any bridge tool).\n\n**Totals.** ${totalsLine(totals(cliRows))}`);
md += '\n| rea command | what it does | args and flags | RevLens command(s) | status | note |\n|---|---|---|---|---|---|\n';
for (const r of cliRows) md += `| \`rea ${r.name}\` | ${esc(firstSentence(r.desc, 140))} | ${esc([...r.args, ...r.flags].join(' ') || '-')} | ${r.rl.length ? r.rl.map((x) => '`revlens ' + x + '`').join(', ') : '-'} | ${statusCell(r)} | ${esc(r.note)} |\n`;
md += `\n## RevLens CLI commands\n\n${rl.coreCommands.length} core commands (${rl.coreCommands.join(', ')}), ${rl.commands.length} package and top level commands. Global options: ${rl.cliOptions.filter((o) => o.startsWith('--')).join(', ')}.\n`;
writeFileSync(join(DOCS, 'rea-cli.md'), md);

// ---------- formats.md ----------
const fmtRows = Object.entries(M.FORMATS).map(([k, r]) => ({ ...r, name: k }));
const artRows = fmtRows.filter((r) => rea.artifactFormats.includes(r.name));
const toolFmtRows = fmtRows.filter((r) => !rea.artifactFormats.includes(r.name));
const outRows = rea.cliOutputFormats.map((f) => ({ ...M.OUTPUT_FORMATS[f], name: f }));
md = header('File formats and output formats', `Input formats: rea's ARTIFACT_FORMAT_IDS (${rea.artifactFormats.length}) plus the formats its dedicated inspect tools read (${toolFmtRows.length}). RevLens core detects ${rl.formatIds.length} format ids (${rl.formatIds.join(', ')}); package tools read more.\n\n**Totals, input formats.** ${totalsLine(totals(fmtRows))}\n\n**Totals, output formats.** ${totalsLine(totals(outRows))}`);
const fmtTable = (rows) => '| rea format | RevLens | status | note |\n|---|---|---|---|\n' + rows.map((r) => `| \`${r.name}\` | ${code(r.rl)} | ${statusCell(r)} | ${esc(r.note)} |`).join('\n') + '\n';
md += `\n## rea artifact formats (${artRows.length})\n\n${fmtTable(artRows)}\n## Formats read by dedicated rea tools (${toolFmtRows.length})\n\n${fmtTable(toolFmtRows)}\n## Formats RevLens reads that rea does not list (${M.RL_ONLY_FORMATS.length})\n\n${M.RL_ONLY_FORMATS.map((x) => `- ${x}`).join('\n')}\n\n## CLI output formats (${outRows.length})\n\n${fmtTable(outRows)}\nRevLens only: ${M.RL_ONLY_OUTPUTS.join(', ')}. Library output functions: ${rl.outputFunctions.join(', ')}.\n`;
writeFileSync(join(DOCS, 'formats.md'), md);

// ---------- config.md ----------
const envSchema = new Set([...rea.envSchemaKeys, ...rea.debuggerSettings]);
const cfgRows = Object.entries(M.CONFIG).map(([k, r]) => ({ ...r, name: k, schema: envSchema.has(k), def: rea.envDefaults[k] }));
const flagRows = Object.entries(M.CLI_FLAGS).map(([k, r]) => ({ ...r, name: k }));
md = header('Configuration options and environment variables', `rea settings: the ${rea.envSchemaKeys.length} keys of its environment schema (src/config/environment.ts), the ${rea.debuggerSettings.length} debugger session limits, and every other REA_* variable its sources read outside tests. ${M.CONFIG_INTERNAL.length} internal plumbing names are listed but not counted. RevLens reads ${rl.envNames.length} REVLENS_* variables and takes most limits as per call inputs (timeoutMs, budgetMs, limit, maxChars).\n\n**Totals, settings.** ${totalsLine(totals(cfgRows))}\n\n**Totals, CLI flags.** ${totalsLine(totals(flagRows))}`);
const cfgTable = (rows) => '| rea setting | default | RevLens | status | note |\n|---|---|---|---|---|\n' + rows.map((r) => `| \`${r.name}\` | ${esc(r.def ?? '-')} | ${code(r.rl)} | ${statusCell(r)} | ${esc(r.note)} |`).join('\n') + '\n';
md += `\n## Environment schema and debugger limits (${cfgRows.filter((r) => r.schema).length})\n\n${cfgTable(cfgRows.filter((r) => r.schema))}\n## Other REA_* variables (${cfgRows.filter((r) => !r.schema).length})\n\n${cfgTable(cfgRows.filter((r) => !r.schema))}\nInternal, not counted: ${M.CONFIG_INTERNAL.map((x) => '`' + x + '`').join(', ')}.\n\n## CLI flags (${flagRows.length})\n\n| rea flag | RevLens | status | note |\n|---|---|---|---|\n${flagRows.map((r) => `| \`${r.name}\` | ${code(r.rl)} | ${statusCell(r)} | ${esc(r.note)} |`).join('\n')}\n\n## RevLens environment variables (${rl.envNames.length})\n\n| variable | read in |\n|---|---|\n${rl.envNames.map((e) => `| \`${e.name}\` | ${e.files.slice(0, 3).join(', ')} |`).join('\n')}\n`;
writeFileSync(join(DOCS, 'config.md'), md);

// ---------- summary.md ----------
const tables = [
  ['MCP tools (rea-tools.md)', toolRows],
  ['CLI commands (rea-cli.md)', cliRows],
  ['Input formats (formats.md)', fmtRows],
  ['Output formats (formats.md)', outRows],
  ['Settings (config.md)', cfgRows],
  ['CLI flags (config.md)', flagRows],
];
const allGaps = [];
for (const [table, rows] of tables) for (const r of rows) {
  if (r.status !== 'partial' && r.status !== 'missing') continue;
  // a CLI command that wraps a tool with its own gap row repeats that gap; keep only CLI-specific gaps
  if (table.startsWith('CLI commands') && r.via && ['partial', 'missing'].includes(M.TOOLS[r.via].status)) continue;
  allGaps.push({ table, ...r });
}
const owners = [...new Set(allGaps.map((g) => g.owner ?? 'unassigned'))].sort();
md = header('Parity summary: rea against RevLens', 'Totals per table, then every partial or missing row grouped by the RevLens package that should own it. In the work lists a CLI command that only wraps an MCP tool with its own gap is not repeated; closing the tool row closes it.');
md += '\n## Totals\n\n| table | rows | equal | better | partial | missing | in progress | covered |\n|---|---|---|---|---|---|---|---|\n';
for (const [table, rows] of tables) { const t = totals(rows); md += `| ${table} | ${t.rows} | ${t.equal} | ${t.better} | ${t.partial} | ${t.missing} | ${t.inProgress} | ${t.covered} (${Math.round(100 * t.covered / t.rows)}%) |\n`; }
md += `\nRevLens has ${rl.tools.length} MCP tools; ${rlOnly.length} of them have no rea counterpart (listed at the end of rea-tools.md).\n`;
const r4 = allGaps.filter((g) => !g.wip);
const wip = allGaps.filter((g) => g.wip);
md += `\n## Round 4 work list (${r4.length} rows: partial or missing and not in progress)\n\nGrouped by proposed owner package.\n`;
for (const o of owners) {
  const rows = r4.filter((g) => (g.owner ?? 'unassigned') === o);
  if (!rows.length) continue;
  md += `\n### ${o} (${rows.length})\n\n| table | rea item | status | gap |\n|---|---|---|---|\n` + rows.map((g) => `| ${g.table.replace(/ \(.*/, '')} | \`${g.name}\` | ${g.status} | ${esc(g.note)} |`).join('\n') + '\n';
}
md += `\n## In progress on round-3 branches (${wip.length} rows)\n\n`;
const byBranch = {};
for (const g of wip) { const w = M.IN_PROGRESS[g.wip]; (byBranch[w.branch] ??= []).push(g); }
for (const [br, rows] of Object.entries(byBranch).sort()) {
  md += `\n### ${br} (${rows.length})\n\n| table | rea item | status | area | owner |\n|---|---|---|---|---|\n` + rows.map((g) => `| ${g.table.replace(/ \(.*/, '')} | \`${g.name}\` | ${g.status} | ${M.IN_PROGRESS[g.wip].label} | ${g.owner ?? '-'} |`).join('\n') + '\n';
}
const unusedWip = Object.entries(M.IN_PROGRESS).filter(([k]) => !allGaps.some((g) => g.wip === k)).map(([, v]) => `${v.label} (${v.branch})`);
md += `\nIn-progress areas with no matching rea row (RevLens-only work or process work): ${unusedWip.join(', ') || 'none'}.\n`;
if (bench) {
  md += `\n## Efficiency\n\n${bench.note}\n\n| operation | fixture | rea | RevLens | ratio (rea / RevLens) |\n|---|---|---|---|---|\n`;
  for (const r of bench.rows) md += `| ${esc(r.operation)} | ${esc(r.fixture)} | ${r.rea ?? 'n/a'} | ${r.revlens ?? 'n/a'} | ${r.ratio ?? 'n/a'} |\n`;
  if (bench.notes?.length) md += '\n' + bench.notes.map((n) => `- ${n}`).join('\n') + '\n';
}
writeFileSync(join(DOCS, 'summary.md'), md);
writeFileSync(join(DOCS, 'data', 'totals.json'), JSON.stringify(Object.fromEntries(tables.map(([n, rows]) => [n, totals(rows)])), null, 1) + '\n');
console.log(JSON.stringify(Object.fromEntries(tables.map(([n, rows]) => [n, totals(rows)]))));
if (problems.length) console.error(`${problems.length} problems, see above`);
