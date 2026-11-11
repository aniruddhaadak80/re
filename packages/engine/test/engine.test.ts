// The engine runs core plus every package analyzer on one report, and core detects the new formats by magic.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join, basename } from 'node:path';
import { detectFormat, verifyClaim } from '@revlens/core';
import { analyzeAll, ALL_ANALYZERS, PACKAGES } from '../src/index.js';
import { PACKAGE_TOOLS, TOOL_GROUPS } from '../src/node.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
const B = (p: string) => new Uint8Array(readFileSync(join(root, 'samples', p)));

const CASES: [string, string, (m: any) => unknown][] = [
  ['managed/dotnet/System.IO.Compression.Brotli.dll', 'dotnet', (m) => m.managed.dotnet.dotnet.assembly.name],
  ['mobile/ipa/Wikipedia-fixture.ipa', 'ipa', (m) => m.mobile.ipa],
  ['webrt/dns_udp.pcap', 'pcap', (m) => m.webrt.pcap.packetCount],
  ['webrt/pcapng-multi-interface.pcapng', 'pcapng', (m) => m.webrt.pcap.packetCount],
  ['webrt/fixture.sqlite', 'sqlite', (m) => m.webrt.sqlite],
  ['webrt/har-redirect.har', 'har', (m) => m.webrt.har],
  ['managed/lua/sample.5.4.luac', 'lua', (m) => m.managed.lua.version],
  ['managed/beam/elixir_sup.beam', 'beam', (m) => m.managed.beam.module],
  ['disasm/hello-arm64.elf', 'elf', (m) => m.disasm.functions],
  ['mobile/apk/org.rayg.streaktracker_12.apk', 'apk', (m) => m.mobile.apk],
];

for (const [path, format, pick] of CASES) {
  test(`${basename(path)} is ${format} and gets its package view`, async () => {
    const bytes = B(path);
    assert.equal(detectFormat(bytes, basename(path)), format);
    const r = await analyzeAll(bytes, { name: basename(path) });
    assert.equal(r.file.format, format);
    assert.ok(pick(r.meta), JSON.stringify(Object.keys(r.meta)));
  });
}

test('a pcapng is not mistaken for Python bytecode', async () => {
  const r = await analyzeAll(B('webrt/pcapng-multi-interface.pcapng'), { name: 'x.pcapng' });
  assert.equal((r.meta as any).managed, undefined);
});

test('format-is pe holds for a .NET assembly', () => {
  const b = B('managed/dotnet/System.IO.Compression.Brotli.dll');
  assert.equal(verifyClaim(b, { kind: 'format-is', format: 'pe' }).verdict, 'VERIFIED');
  assert.equal(verifyClaim(B('disasm/hello-x64.exe'), { kind: 'format-is', format: 'pe' }).verdict, 'VERIFIED');
  assert.equal(detectFormat(B('disasm/hello-x64.exe'), 'hello-x64.exe'), 'pe');
});

test('packages filter limits package analyzers', async () => {
  const r = await analyzeAll(B('disasm/hello-x64.elf'), { name: 'a.elf', packages: ['web'] });
  assert.equal((r.meta as any).disasm, undefined);
});

test('registry lists analyzers, tools and commands from every package', () => {
  assert.equal(PACKAGES.length, 4);
  assert.ok(ALL_ANALYZERS.some((a) => a.package === 'disasm'));
  const names = PACKAGE_TOOLS.map((t) => t.name);
  assert.equal(new Set(names).size, names.length);
  assert.equal(names.length, 47);
  assert.equal(TOOL_GROUPS.reduce((n, g) => n + g.commands.length, 0), 42);
});
