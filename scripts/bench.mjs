#!/usr/bin/env node
// RevLens benchmark: startup time of the CLI and the MCP server, analyzeAll on real fixtures, and MCP
// tool calls over stdio, with memory for each. Needs the packages built (npm run build).
//
//   node scripts/bench.mjs                       everything, human readable
//   node scripts/bench.mjs --json                machine readable
//   node scripts/bench.mjs --only startup        one part: startup, analyze, mcp
//   node scripts/bench.mjs --runs 5              repeat each measurement (median is reported)
//   node scripts/bench.mjs --cli <entry.js> --mcp <entry.js>   time other builds (for before and after)
import { spawn, spawnSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { basename, dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { performance } from 'node:perf_hooks';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const argv = process.argv.slice(2);
const opt = (k, d) => { const i = argv.indexOf(`--${k}`); return i >= 0 ? argv[i + 1] : d; };
const flag = (k) => argv.includes(`--${k}`);
const runs = Math.max(1, Math.min(Number(opt('runs', 3)) || 3, 50));
const only = opt('only', 'all');
const cliEntry = resolve(opt('cli', join(root, 'packages/cli/dist/index.js')));
const mcpEntry = resolve(opt('mcp', join(root, 'packages/mcp/dist/index.js')));
const json = flag('json');

const FIXTURES = [
  'disasm/hello-x64.elf', 'disasm/hello-arm64.elf', 'extras/go-hello-stripped.elf',
  'managed/dotnet/System.IO.Compression.Brotli.dll', 'mobile/apk/org.rayg.streaktracker_12.apk',
  'mobile/java/commons-cli-1.6.0.jar', 'webrt/dns_udp.pcap',
].map((p) => join(root, 'samples', p)).filter((p) => existsSync(p));

const median = (xs) => { const s = [...xs].sort((a, b) => a - b); return s.length ? s[Math.floor((s.length - 1) / 2)] : NaN; };
const ms = (x) => Math.round(x * 10) / 10;
const mb = (b) => Math.round(b / 1048576 * 10) / 10;

/** Peak and current RSS of a child process in bytes (Linux /proc, else ps). */
function childMemory(pid) {
  try {
    const s = readFileSync(`/proc/${pid}/status`, 'utf8');
    const kb = (k) => Number(new RegExp(`^${k}:\\s+(\\d+)`, 'm').exec(s)?.[1] ?? NaN) * 1024;
    return { rss: kb('VmRSS'), peak: kb('VmHWM') };
  } catch {
    const r = spawnSync('ps', ['-o', 'rss=', '-p', String(pid)], { encoding: 'utf8' });
    const rss = Number(r.stdout.trim()) * 1024;
    return { rss, peak: rss };
  }
}

/** Wall time for `node <entry> <args>` to exit, median of runs. */
function timeProcess(entry, args) {
  const times = [];
  let out = '';
  for (let i = 0; i < runs; i++) {
    const t0 = performance.now();
    const r = spawnSync(process.execPath, [entry, ...args], { encoding: 'utf8', maxBuffer: 64 << 20 });
    times.push(performance.now() - t0);
    out = (r.stdout || '').slice(0, 200);
    if (r.status !== 0) throw new Error(`${basename(entry)} ${args.join(' ')} exited ${r.status}: ${(r.stderr || '').slice(0, 400)}`);
  }
  return { ms: ms(median(times)), samples: times.map(ms), out: out.trim().split('\n')[0] };
}

/** Time from spawn to an MCP initialize answer and a tools/list answer, raw JSON-RPC over stdio. */
async function timeMcpStartup(entry, extraArgs = []) {
  const res = [];
  for (let i = 0; i < runs; i++) {
    const t0 = performance.now();
    const child = spawn(process.execPath, [entry, ...extraArgs], { stdio: ['pipe', 'pipe', 'ignore'] });
    let buf = '';
    const waitFor = (id) => new Promise((ok, bad) => {
      const on = (d) => {
        buf += d.toString('utf8');
        let nl;
        while ((nl = buf.indexOf('\n')) >= 0) {
          const line = buf.slice(0, nl); buf = buf.slice(nl + 1);
          try { const m = JSON.parse(line); if (m.id === id) { child.stdout.off('data', on); ok(m); return; } } catch { /* ignore */ }
        }
      };
      child.stdout.on('data', on);
      child.once('exit', (c) => bad(new Error(`server exited ${c}`)));
    });
    const send = (m) => child.stdin.write(JSON.stringify(m) + '\n');
    send({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'bench', version: '1' } } });
    await waitFor(1);
    const tInit = performance.now() - t0;
    send({ jsonrpc: '2.0', method: 'notifications/initialized' });
    send({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} });
    const list = await waitFor(2);
    const tList = performance.now() - t0;
    const mem = childMemory(child.pid);
    child.stdin.end();
    child.kill();
    res.push({ init: tInit, list: tList, tools: list.result?.tools?.length ?? 0, rss: mem.rss });
  }
  return { initializeMs: ms(median(res.map((r) => r.init))), toolsListMs: ms(median(res.map((r) => r.list))), tools: res[0].tools, rssMB: mb(median(res.map((r) => r.rss))) };
}

async function benchStartup() {
  const out = { node: process.version, cli: {}, mcp: {} };
  out.cli.version = timeProcess(cliEntry, ['--version']);
  out.cli.help = timeProcess(cliEntry, ['--help']);
  out.cli.analyzeElf = timeProcess(cliEntry, ['analyze', FIXTURES[0], '--json']);
  out.mcp.full = await timeMcpStartup(mcpEntry);
  if (!flag('no-profiles')) {
    try { out.mcp.minimal = await timeMcpStartup(mcpEntry, ['--tool-profile', 'minimal']); } catch (e) { out.mcp.minimal = { error: e.message }; }
  }
  return out;
}

async function benchAnalyze() {
  const { analyzeAllNode } = await import('@revlens/engine/node');
  const rows = [];
  for (const f of FIXTURES) {
    const bytes = new Uint8Array(readFileSync(f));
    await analyzeAllNode(bytes, { name: basename(f) }); // warm up: loads decoders and caches
    const times = [];
    let heapPeak = 0;
    globalThis.gc?.();
    const rss0 = process.memoryUsage().rss;
    for (let i = 0; i < runs; i++) {
      const t0 = performance.now();
      const r = await analyzeAllNode(bytes, { name: basename(f) });
      times.push(performance.now() - t0);
      heapPeak = Math.max(heapPeak, process.memoryUsage().heapUsed);
      if (!r.file) throw new Error('no report');
    }
    rows.push({ file: basename(f), bytes: bytes.length, ms: ms(median(times)), mbPerSec: Math.round(bytes.length / 1048576 / (median(times) / 1000) * 100) / 100, heapMB: mb(heapPeak), rssGrowthMB: mb(process.memoryUsage().rss - rss0) });
  }
  return { runs, rows, processRssMB: mb(process.memoryUsage().rss) };
}

async function benchMcp() {
  const { Client } = await import('@modelcontextprotocol/sdk/client/index.js');
  const { StdioClientTransport } = await import('@modelcontextprotocol/sdk/client/stdio.js');
  const client = new Client({ name: 'revlens-bench', version: '1.0.0' });
  const transport = new StdioClientTransport({ command: process.execPath, args: [mcpEntry], stderr: 'ignore' });
  const t0 = performance.now();
  await client.connect(transport);
  const connectMs = performance.now() - t0;
  const S = (p) => join(root, 'samples', p);
  const calls = [
    ['analyze_file', { path: S('disasm/hello-x64.elf') }],
    ['disasm_pseudocode', { path: S('disasm/hello-x64.elf'), function: 'main' }],
    ['mobile_manifest', { path: S('mobile/apk/org.rayg.streaktracker_12.apk') }],
    ['managed_dotnet_info', { path: S('managed/dotnet/System.IO.Compression.Brotli.dll') }],
    ['web_pcap_summary', { path: S('webrt/dns_udp.pcap') }],
    ['search_guidance', { query: 'exported activities permissions' }],
    ['discover_tools', { goal: 'find network endpoints in a javascript bundle' }],
  ];
  const rows = [];
  const pid = transport.pid;
  for (const [name, args] of calls) {
    const times = [];
    let chars = 0;
    let error = null;
    for (let i = 0; i <= runs; i++) {
      const t = performance.now();
      try {
        const r = await client.callTool({ name, arguments: args });
        if (r.isError) error = r.content?.[0]?.text?.slice(0, 200) ?? 'error';
        chars = r.content?.map((c) => c.text?.length ?? 0).reduce((a, b) => a + b, 0) ?? 0;
      } catch (e) { error = e.message; }
      if (i > 0 || runs === 0) times.push(performance.now() - t); // the first call includes lazy loading; reported separately
      else rows.push({ tool: name, firstCallMs: ms(performance.now() - t) });
    }
    Object.assign(rows[rows.length - 1], { ms: ms(median(times)), outputChars: chars, ...(error ? { error } : {}) });
  }
  const mem = pid ? childMemory(pid) : { rss: NaN, peak: NaN };
  await client.close();
  return { connectMs: ms(connectMs), rows, serverRssMB: mb(mem.rss), serverPeakMB: mb(mem.peak) };
}

const result = { when: new Date().toISOString(), node: process.version, platform: `${process.platform}-${process.arch}`, runs, cliEntry, mcpEntry };
if (only === 'all' || only === 'startup') result.startup = await benchStartup();
if (only === 'all' || only === 'analyze') result.analyze = await benchAnalyze();
if (only === 'all' || only === 'mcp') result.mcp = await benchMcp();

if (json) process.stdout.write(JSON.stringify(result, null, 2) + '\n');
else {
  const L = [`RevLens bench  ${result.platform}  node ${result.node}  runs ${runs} (median)`];
  if (result.startup) {
    const s = result.startup;
    L.push('', 'Startup');
    L.push(`  cli --version        ${s.cli.version.ms} ms`, `  cli --help           ${s.cli.help.ms} ms`, `  cli analyze (elf)    ${s.cli.analyzeElf.ms} ms`);
    L.push(`  mcp initialize       ${s.mcp.full.initializeMs} ms   tools/list ${s.mcp.full.toolsListMs} ms   ${s.mcp.full.tools} tools   rss ${s.mcp.full.rssMB} MB`);
    if (s.mcp.minimal?.initializeMs) L.push(`  mcp minimal profile  ${s.mcp.minimal.initializeMs} ms   tools/list ${s.mcp.minimal.toolsListMs} ms   ${s.mcp.minimal.tools} tools   rss ${s.mcp.minimal.rssMB} MB`);
  }
  if (result.analyze) {
    L.push('', 'analyzeAll');
    for (const r of result.analyze.rows) L.push(`  ${r.file.padEnd(44)} ${String(r.bytes).padStart(9)} B  ${String(r.ms).padStart(8)} ms  ${String(r.mbPerSec).padStart(7)} MB/s  heap ${r.heapMB} MB`);
  }
  if (result.mcp) {
    L.push('', `MCP over stdio (connect ${result.mcp.connectMs} ms, server rss ${result.mcp.serverRssMB} MB, peak ${result.mcp.serverPeakMB} MB)`);
    for (const r of result.mcp.rows) L.push(`  ${r.tool.padEnd(22)} first ${String(r.firstCallMs).padStart(8)} ms   then ${String(r.ms).padStart(8)} ms   ${r.outputChars} chars${r.error ? `   ERROR ${r.error}` : ''}`);
  }
  console.log(L.join('\n'));
}
