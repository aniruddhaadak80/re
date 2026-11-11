// Hostile input: random bytes, truncation, bit flips and crafted huge counts must end in a result or a ParseError,
// never a crash of another kind or a hang.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fc from 'fast-check';
import { sample, bytes } from './helpers.js';
import {
  ParseError, loadAssembly, dotnetInfo, methodIl, listTypes, parsePyc, unmarshal, disassemblePyc, walkCode, parseCArchive, extractPyInstaller,
  parseLua, luaListing, parseBeam, analyzeEvm, singleFileBundle, runManagedAnalyzers, type PyCode,
} from '../src/index.js';
import { analyze } from '../../core/src/index.js';

const RUNS = Number(process.env.REVLENS_FUZZ_RUNS ?? 150);

function safe(fn: () => unknown): void {
  try { fn(); } catch (e) {
    if (!(e instanceof ParseError)) throw new Error(`unexpected ${e instanceof Error ? `${e.name}: ${e.message}\n${e.stack}` : e}`);
  }
}

const dotnetAll = (b: Uint8Array) => safe(() => {
  const asm = loadAssembly(b);
  dotnetInfo(asm);
  listTypes(asm, { members: true });
  const n = asm.md.tables.get(6)?.rows.length ?? 0;
  for (let rid = 1; rid <= Math.min(n, 40); rid++) safe(() => methodIl(asm, rid));
});
const pycAll = (b: Uint8Array) => safe(() => { const p = parsePyc(b); walkCode(p.code, (c: PyCode) => { disassemblePyc(c, p.version); }); });
const luaAll = (b: Uint8Array) => safe(() => luaListing(parseLua(b)));
const beamAll = (b: Uint8Array) => safe(() => parseBeam(b));
const pyiAll = (b: Uint8Array) => safe(() => { parseCArchive(b); extractPyInstaller(b, { maxTotalBytes: 1 << 24 }); });
const evmAll = (b: Uint8Array) => safe(() => analyzeEvm(b));

const FIXTURES: [string, (b: Uint8Array) => void][] = [
  [sample('dotnet', 'System.IO.Compression.Brotli.dll'), dotnetAll],
  [sample('python', 'sample_mod.3.8.pyc'), pycAll],
  [sample('python', 'sample_mod.3.13.pyc'), pycAll],
  [sample('lua', 'sample.5.1.luac'), luaAll],
  [sample('lua', 'sample.5.4.luac'), luaAll],
  [sample('lua', 'sample.luajit2.1.luac'), luaAll],
  [sample('beam', 'Elixir.Version.beam'), beamAll],
  [sample('pyinstaller', 'mini-carchive.bin'), pyiAll],
];

test('hostile: random bytes never crash any parser', () => {
  fc.assert(fc.property(fc.uint8Array({ maxLength: 2048 }), (b) => {
    dotnetAll(b); pycAll(b); luaAll(b); beamAll(b); pyiAll(b); evmAll(b);
    safe(() => unmarshal(b, { minor: 12 }));
    safe(() => singleFileBundle(b));
  }), { numRuns: RUNS });
});

test('hostile: valid magic followed by random bytes', () => {
  const heads = FIXTURES.map(([p, f]) => [bytes(p).subarray(0, 64), f] as const);
  fc.assert(fc.property(fc.nat(heads.length - 1), fc.uint8Array({ maxLength: 4096 }), (i, tail) => {
    const [head, f] = heads[i]!;
    const b = new Uint8Array(head.length + tail.length); b.set(head); b.set(tail, head.length);
    f(b);
  }), { numRuns: RUNS });
});

test('hostile: every fixture truncated at many lengths', () => {
  for (const [p, f] of FIXTURES) {
    const b = bytes(p);
    const step = Math.max(1, Math.floor(b.length / 97));
    for (let n = 0; n < b.length; n += step) f(b.subarray(0, n));
  }
});

test('hostile: random bit flips in real fixtures', () => {
  const fx = FIXTURES.map(([p, f]) => [bytes(p), f] as const);
  fc.assert(fc.property(fc.nat(fx.length - 1), fc.array(fc.tuple(fc.nat(), fc.nat(255)), { minLength: 1, maxLength: 12 }), (i, flips) => {
    const [orig, f] = fx[i]!;
    const b = orig.slice();
    for (const [at, v] of flips) b[at % b.length] = v;
    f(b);
  }), { numRuns: RUNS });
});

test('hostile: crafted huge counts are refused quickly', () => {
  const t0 = Date.now();
  // marshal tuple claiming 4 billion items
  assert.throws(() => unmarshal(Uint8Array.from([0x28, 0xff, 0xff, 0xff, 0xff, 0x4e]), { minor: 12 }), ParseError);
  // marshal list nested far beyond the depth cap
  assert.throws(() => unmarshal(new Uint8Array(100000).fill(0x5b).map((x, i) => (i % 5 === 0 ? 0x5b : i % 5 === 1 ? 1 : 0)), { minor: 12 }), ParseError);
  // marshal long with a million digits
  assert.throws(() => unmarshal(Uint8Array.from([0x6c, 0xff, 0xff, 0xff, 0x7f]), { minor: 12 }), ParseError);
  // pyc header for 3.12 with a code object whose co_code length is huge
  const pyc = new Uint8Array(64); pyc.set([0xcb, 0x0d, 0x0d, 0x0a]); pyc[16] = 0xe3; pyc.fill(0, 17, 41); pyc.set([0x73, 0xff, 0xff, 0xff, 0x7f], 41);
  assert.throws(() => parsePyc(pyc), ParseError);
  // .NET: metadata table claiming 2^31 TypeDef rows
  const dll = bytes(sample('dotnet', 'System.IO.Compression.Brotli.dll')).slice();
  const asm = loadAssembly(dll);
  const ts = asm.md.streams.find((s) => s.name === '#~')!;
  const dv = new DataView(dll.buffer, dll.byteOffset);
  // row counts start at +24; Module is first, TypeRef second, TypeDef third
  dv.setUint32(ts.offset + 24 + 8, 0x7fffffff, true);
  assert.throws(() => loadAssembly(dll), ParseError);
  // BEAM atom table claiming 2^30 atoms
  const beam = bytes(sample('beam', 'elixir_sup.beam')).slice();
  const at = 12 + 8; new DataView(beam.buffer, beam.byteOffset).setInt32(at, 0x40000000, false);
  assert.throws(() => parseBeam(beam), ParseError);
  // Lua 5.4 code count varint near 2^53
  const lua = bytes(sample('lua', 'sample.5.4.luac')).slice(0, 40);
  const big = new Uint8Array(60); big.set(lua.subarray(0, 32)); big.set([0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0xff], 37);
  assert.throws(() => parseLua(big), ParseError);
  // PyInstaller cookie with absurd package length
  const mini = bytes(sample('pyinstaller', 'mini-carchive.bin')).slice();
  const ci = mini.length - 7 - 88;
  new DataView(mini.buffer, mini.byteOffset).setUint32(ci + 8, 0xfffffff0, false);
  assert.throws(() => parseCArchive(mini), ParseError);
  assert.ok(Date.now() - t0 < 5000);
});

test('hostile: analyzers on random input never throw', async () => {
  await fc.assert(fc.asyncProperty(fc.uint8Array({ maxLength: 1024 }), fc.constantFrom('x.dll', 'x.pyc', 'x.luac', 'x.beam', 'x.evm', 'x.bin', 'x.exe'), async (b, name) => {
    const r = await analyze(b, { name, analyzers: [] });
    await runManagedAnalyzers(b, r, name);
    JSON.stringify(r);
  }), { numRuns: Math.min(RUNS, 80) });
});
