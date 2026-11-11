// Analyzers that enrich a RevLens report with output from installed external tools. They are
// opt in, because they spawn processes: they only run when the analyze() call lists their id in
// options.analyzers, or when REVLENS_BRIDGES=1 is set. Node only.
import { writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import type { Analyzer, AnalyzerContext } from '@revlens/core';
import { withTempDir } from './exec.js';
import { detectAll } from './detect.js';
import { isUnavailable } from './providers/common.js';
import { r2Functions, r2Info } from './providers/radare2.js';
import { jadxDecompile } from './providers/jvm.js';

const NATIVE = new Set(['elf', 'pe', 'macho', 'macho-fat']);
const JVM = new Set(['dex', 'apk', 'jar', 'class']);
const MAX_BYTES = 256 * 1024 * 1024;

function optedIn(ctx: AnalyzerContext, id: string): boolean {
  const list = ctx.options.analyzers;
  if (Array.isArray(list) && list.includes(id)) return true;
  return typeof process !== 'undefined' && process.env.REVLENS_BRIDGES === '1';
}

async function onDisk<T>(ctx: AnalyzerContext, fn: (path: string) => Promise<T>): Promise<T> {
  return withTempDir(async (dir) => {
    const ext = ctx.format === 'apk' ? '.apk' : ctx.format === 'jar' ? '.jar' : ctx.format === 'dex' ? '.dex' : ctx.format === 'class' ? '.class' : '.bin';
    const p = join(dir, 'input' + ext);
    await writeFile(p, ctx.bytes);
    return fn(p);
  });
}

function meta(ctx: AnalyzerContext): Record<string, unknown> {
  const m = (ctx.report.meta.bridges ??= {}) as Record<string, unknown>;
  return m;
}

/** radare2 or rizin: binary info and the function list for native executables. */
export const r2Analyzer: Analyzer = {
  id: 'bridges-r2',
  title: 'radare2 bridge',
  description: 'Recovers functions with radare2 or rizin when installed (opt in).',
  applies: (ctx) => NATIVE.has(ctx.format) && ctx.depth === 0 && ctx.bytes.length <= MAX_BYTES && optedIn(ctx, 'bridges-r2'),
  async run(ctx) {
    const t0 = Date.now();
    await onDisk(ctx, async (path) => {
      const info = await r2Info({ path });
      if (isUnavailable(info)) { meta(ctx).r2 = { available: false, install: info.install }; return; }
      const fns = await r2Functions({ path, limit: 500 });
      if (isUnavailable(fns) || !('ok' in fns) || !fns.ok) { meta(ctx).r2 = { available: true, ok: false, error: (fns as { error?: string }).error }; return; }
      const f = fns as Extract<typeof fns, { functions: unknown }>;
      meta(ctx).r2 = { available: true, tool: f.tool, toolVersion: f.toolVersion, info: 'info' in info ? info.info : null, total: f.total, functions: f.functions };
      ctx.report.findings.push({
        id: 'bridges.r2.functions', analyzer: 'bridges-r2', title: `${f.tool} recovered ${f.total} functions`, severity: 'info',
        detail: `Function boundaries from ${f.tool} ${f.toolVersion ?? ''} (analysis level aa). See report.meta.bridges.r2.functions.`.trim(),
        evidence: f.functions.slice(0, 5).map((x) => ({ snippet: `${x.address} ${x.name} size ${x.size}` })),
        tags: ['bridges', 'functions'],
      });
    });
    ctx.report.timings['bridges-r2'] = Date.now() - t0;
  },
};

/** jadx: class list for DEX, APK, JAR and class files. */
export const jadxAnalyzer: Analyzer = {
  id: 'bridges-jadx',
  title: 'jadx bridge',
  description: 'Lists decompiled Java classes with jadx when installed (opt in).',
  applies: (ctx) => JVM.has(ctx.format) && ctx.depth === 0 && ctx.bytes.length <= MAX_BYTES && optedIn(ctx, 'bridges-jadx'),
  async run(ctx) {
    const t0 = Date.now();
    await onDisk(ctx, async (path) => {
      const r = await jadxDecompile({ path, limit: 2000 });
      if (isUnavailable(r)) { meta(ctx).jadx = { available: false, install: r.install }; return; }
      if (!('classes' in r)) { meta(ctx).jadx = { available: true, ok: false, error: (r as { error?: string }).error }; return; }
      meta(ctx).jadx = { available: true, tool: 'jadx', toolVersion: r.toolVersion, total: r.total, classes: r.classes.map((c) => c.className) };
      ctx.report.findings.push({
        id: 'bridges.jadx.classes', analyzer: 'bridges-jadx', title: `jadx decompiled ${r.total} classes`, severity: 'info',
        detail: 'Class names from jadx. Use bridge_jadx_decompile for source.', evidence: r.classes.slice(0, 5).map((c) => ({ snippet: c.className })),
        tags: ['bridges', 'java'],
      });
    });
    ctx.report.timings['bridges-jadx'] = Date.now() - t0;
  },
};

/** Puts the tool inventory summary on the report. Cheap, no target execution. */
export const inventoryAnalyzer: Analyzer = {
  id: 'bridges-inventory',
  title: 'Bridge tool inventory',
  description: 'Records which external RE tools are available (opt in).',
  applies: (ctx) => ctx.depth === 0 && optedIn(ctx, 'bridges-inventory'),
  async run(ctx) {
    const d = await detectAll({ skipVersion: true });
    meta(ctx).tools = Object.fromEntries([...d.values()].map((x) => [x.id, x.available]));
  },
};

export const ANALYZERS: Analyzer[] = [inventoryAnalyzer, r2Analyzer, jadxAnalyzer];
