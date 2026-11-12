// Golden outputs for the core deep PE view: runs the @revlens/extras x_pe_inspect and x_pe_resources
// tools (the implementation before the move) on every PE fixture and writes their JSON, plus timings
// of both implementations for packages/core/README.md.
// Run from the repo root after building core: node --import tsx packages/core/scripts/gen_pe_golden.mts
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { TOOLS } from '../../extras/src/index.ts';
import { peAuthenticode } from '../../extras/src/pe/pe.ts';
import { inspectPeDeep, peResourceView } from '../src/pe/deep.ts';

const FIXTURES = ['samples/extras/hello-res.exe', 'samples/disasm/hello-x64.exe', 'samples/bridges/hello-dotnet.dll', 'samples/managed/dotnet/RevDemoLib-1.0.0.dll', 'samples/managed/dotnet/System.IO.Compression.Brotli.dll', 'samples/.cache/esbuild.exe'];
const tool = (n: string) => TOOLS.find((t: { name: string }) => t.name === n)!;
const out = 'samples/core/pe-golden';
mkdirSync(out, { recursive: true });
const timings: Record<string, unknown>[] = [];
const time = async (f: () => unknown, n: number): Promise<number> => { for (let i = 0; i < 3; i++) await f(); const t = performance.now(); for (let i = 0; i < n; i++) await f(); return (performance.now() - t) / n; };
for (const f of FIXTURES) {
  if (!existsSync(f)) { console.log('skip (not present)', f); continue; }
  const name = f.split('/').pop()!;
  const inspect = await tool('x_pe_inspect').run({ path: f });
  const resources = await tool('x_pe_resources').run({ path: f });
  if (!f.includes('.cache')) {
    writeFileSync(`${out}/${name}.inspect.json`, JSON.stringify(inspect));
    writeFileSync(`${out}/${name}.resources.json`, JSON.stringify(resources));
  }
  const n = f.includes('esbuild') ? 5 : 40;
  // before: the extras tools, reading the file each time like the CLI does; after: the core functions on the same input
  const beforeRes = await time(() => tool('x_pe_resources').run({ path: f }), n);
  const afterRes = await time(() => peResourceView(new Uint8Array(readFileSync(f))), n);
  const beforeDeep = await time(() => tool('x_pe_inspect').run({ path: f }), n);
  const afterDeep = await time(() => inspectPeDeep(new Uint8Array(readFileSync(f)), { authenticode: peAuthenticode }), n);
  timings.push({ file: f, size: readFileSync(f).length, resources: { beforeMs: +beforeRes.toFixed(3), afterMs: +afterRes.toFixed(3), speedup: +(beforeRes / afterRes).toFixed(1) }, deep: { beforeMs: +beforeDeep.toFixed(3), afterMs: +afterDeep.toFixed(3), speedup: +(beforeDeep / afterDeep).toFixed(1) } });
  console.log(JSON.stringify(timings[timings.length - 1]));
}
writeFileSync(`${out}/timings.json`, JSON.stringify(timings, null, 1));
