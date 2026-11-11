// 10 MB Go binaries (esbuild 0.24.0). Run packages/disasm/scripts/fetch-fixtures.mjs first; skipped
// when the cache is absent. Independent checks: the function the pclntab names at the header entry
// point is the Go runtime entry stub, and main.main starts with Go's stack bound check.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { openProgram, disasmListFunctions, disasmPseudocode, disasmFindReferences, disasmFunction } from '../src/node.ts';

const cache = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..', 'samples', '.cache', 'disasm');
const cases = [
  { file: 'esbuild-linux-x64', rt0: '_rt0_amd64_linux', check: /^cmp rsp, (qword ptr )?\[r14\+0x10\]$|^lea r12, \[rsp-/ },
  { file: 'esbuild-win32-x64.exe', rt0: '_rt0_amd64_windows', check: /^cmp rsp, (qword ptr )?\[r14\+0x10\]$|^lea r12, \[rsp-/ },
  { file: 'esbuild-darwin-arm64', rt0: '_rt0_arm64_darwin', check: /^ldr x16, \[x28, #0x10\]$/ },
];

for (const c of cases) {
  const path = join(cache, c.file);
  test(`Go ${c.file}: pclntab names, entry stub, main.main prologue, bounded time`, { skip: !existsSync(path) && 'run fetch-fixtures.mjs' }, async () => {
    const t0 = Date.now();
    const p = await openProgram({ path });
    assert.ok(p.img.bytes.length > 9_000_000);
    assert.match(p.img.goVersionHint ?? '', /go1\./);
    const l = await disasmListFunctions({ path, filter: 'main.main', limit: 5 });
    const mm = l.functions.find((f) => f.name === 'main.main');
    assert.ok(mm, 'main.main listed');
    assert.equal(mm!.source, 'gopclntab');
    assert.ok(l.total >= 1);
    assert.equal(p.functions.get(p.img.entry!)?.name, c.rt0);
    const d = await disasmFunction({ path, function: 'main.main', limit: 4 });
    assert.match(String(d.blocks[0]!.insns[0]!.text), c.check);
    const pc = await disasmPseudocode({ path, function: 'main.main', maxLines: 80 });
    assert.ok(pc.summary.instructions > 50);
    assert.ok(Date.now() - t0 < 20000, `took ${Date.now() - t0} ms`);
    // budgeted program wide index: returns quickly, flags completeness
    const t1 = Date.now();
    const fr = await disasmFindReferences({ path, string: 'esbuild', budgetMs: 3000 });
    assert.ok(Date.now() - t1 < 15000);
    assert.equal(typeof fr.complete, 'boolean');
    assert.ok(p.functions.size > 5000);
  });
}

// Memory: this file used to peak at about 730 MB of resident memory (esbuild darwin-arm64 was the
// largest part). Whole program passes now analyze functions without caching them, so a complete
// cross reference index of the darwin build fits well below that.
test('Go esbuild-darwin-arm64: complete xref index with bounded memory', { skip: !existsSync(join(cache, 'esbuild-darwin-arm64')) && 'run fetch-fixtures.mjs' }, async () => {
  const path = join(cache, 'esbuild-darwin-arm64');
  const fr = await disasmFindReferences({ path, string: 'esbuild', budgetMs: 60000 });
  assert.equal(fr.complete, true);
  assert.ok(fr.functionsScanned > 8000);
  const maxRssMb = process.resourceUsage().maxRSS / 1024;
  assert.ok(maxRssMb < 600, `peak resident memory ${maxRssMb | 0} MB`);
});
