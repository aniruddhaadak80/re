#!/usr/bin/env node
// Run one RevLens CLI command N times in one process and report timings as JSON (used by bench.mjs).
// Usage: PARITY_N=7 node scripts/parity/revlens-loop.mjs <group> <command> [args...]
// Output of the command is counted, not printed.
import { pathToFileURL } from 'node:url';
import { join, resolve } from 'node:path';

const ROOT = resolve(process.env.PARITY_ROOT ?? '.');
const n = Number(process.env.PARITY_N ?? 5);
const [group, name, ...args] = process.argv.slice(2);
const engine = await import(pathToFileURL(join(ROOT, 'packages/engine/dist/node.js')).href);
const importMs = performance.now();
const cmds = group === 'top' ? engine.TOP_LEVEL_COMMANDS : engine.TOOL_GROUPS.find((g) => g.id === group)?.commands;
const cmd = cmds?.find((c) => c.name === name);
if (!cmd) { console.error(`unknown command ${group} ${name}`); process.exit(2); }
const write = process.stdout.write.bind(process.stdout);
let bytes = 0;
process.stdout.write = (c) => { bytes += String(c).length; return true; };
const times = [];
let code = 0;
for (let i = 0; i < n; i++) {
  const t = performance.now();
  code = await cmd.run([...args]);
  times.push(performance.now() - t);
}
process.stdout.write = write;
const cpu = process.cpuUsage();
console.log(JSON.stringify({ importMs, times, bytes: Math.round(bytes / n), exitCode: code, cpuMs: (cpu.user + cpu.system) / 1000, maxRssKiB: process.resourceUsage().maxRSS }));
