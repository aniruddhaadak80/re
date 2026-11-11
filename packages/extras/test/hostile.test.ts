// Hostile input: random bytes, truncation, mutated real files and huge declared counts must
// end in a result or a ParseError, never a hang, a RangeError from a raw read, or a crash.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fc from 'fast-check';
import * as X from '../src/node.js';
import { fx } from './helpers.js';

type Fn = (b: Uint8Array) => unknown;
const PARSERS: Record<string, Fn> = {
  parseBin: (b) => X.parseBin(b), checksec: (b) => X.checksec(b), elfNotes: (b) => X.elfNotes(b), elfInitializers: (b) => X.elfInitializers(b),
  elfUnwind: (b) => X.elfUnwind(b), kernelModule: (b) => X.kernelModule(b), machoInfo: (b) => X.machoInfo(b), machoCodeSignature: (b) => X.machoCodeSignature(b),
  goSymbols: (b) => X.goSymbols(b), rustInfo: (b) => X.rustInfo(b), peHeaders: (b) => X.peHeaders(b), peResources: (b) => X.peResources(b),
  peVersionInfo: (b) => X.peVersionInfo(b), richHeader: (b) => X.richHeader(b), detectInstaller: (b) => X.detectInstaller(b),
  scanFirmware: (b) => X.scanFirmware(b), parseUImage: (b) => X.parseUImage(b), parseFdt: (b) => X.parseFdt(b), parseUf2: (b) => X.parseUf2(b),
  parseDfu: (b) => X.parseDfu(b), parseEspImage: (b) => X.parseEspImage(b), parseBootImage: (b) => X.parseBootImage(b), parseCpio: (b) => X.parseCpio(b),
  parseUefiVolume: (b) => X.parseUefiVolume(b, 0), parseTrx: (b) => X.parseTrx(b), inspectJsEngine: (b) => X.inspectJsEngine(b),
  inspectGpu: (b) => X.inspectGpu(b), parseSpirv: (b) => X.parseSpirv(b), parseFatbin: (b) => X.parseFatbin(b), inspectModel: (b) => X.inspectModel(b),
  parseGguf: (b) => X.parseGguf(b), parseSafetensors: (b) => X.parseSafetensors(b), parseLnk: (b) => X.parseLnk(b), parseIps: (b) => X.parseIps(b),
  parseIntelHex: (b) => X.parseIntelHex(new TextDecoder().decode(b)), searchBytes: (b) => X.searchBytes(b, { hex: '00 ?? ff' }),
  demangle: (b) => X.demangle(new TextDecoder().decode(b)), msvc: (b) => X.demangleMsvc('?' + new TextDecoder().decode(b)), itanium: (b) => X.demangleItanium('_Z' + new TextDecoder().decode(b)),
  rustV0: (b) => X.demangleRustV0('_R' + new TextDecoder().decode(b)),
};
const ASYNC: Record<string, (b: Uint8Array) => Promise<unknown>> = {
  peAuthenticode: (b) => X.peAuthenticode(b), parseSquashfs: (b) => X.parseSquashfs(b), kernelConfig: (b) => X.kernelConfig(b), inspectPe: (b) => X.inspectPe(b),
};

function safe(name: string, f: () => unknown): void {
  const t0 = Date.now();
  try { f(); } catch (e) {
    if (!(e instanceof X.ParseError) && !(e instanceof SyntaxError)) throw new Error(`${name} threw ${(e as Error).name}: ${(e as Error).message}`);
  }
  assert.ok(Date.now() - t0 < 3000, `${name} took ${Date.now() - t0} ms`);
}
async function safeAsync(name: string, f: () => Promise<unknown>): Promise<void> {
  try { await f(); } catch (e) { if (!(e instanceof X.ParseError) && !(e instanceof SyntaxError)) throw new Error(`${name} threw ${(e as Error).name}: ${(e as Error).message}`); }
}

const FIXTURES = ['demo-x64.elf', 'hello-res.exe', 'hello-arm64.macho', 'go-hello-stripped.elf', 'board.dtb', 'uimage.bin', 'tiny.gguf', 'tiny.safetensors', 'notepad.lnk', 'add.jsc', 'emboss.comp.spv', 'kernels-gfx906.o', 'fw-blob.bin'];

test('random bytes never crash any parser', () => {
  fc.assert(fc.property(fc.uint8Array({ minLength: 0, maxLength: 4096 }), (b) => { for (const [n, f] of Object.entries(PARSERS)) safe(n, () => f(b)); }), { numRuns: 150 });
});

test('random bytes behind each real magic never crash', () => {
  const magics = FIXTURES.map((f) => fx(f).subarray(0, 64));
  fc.assert(fc.property(fc.integer({ min: 0, max: magics.length - 1 }), fc.uint8Array({ maxLength: 2048 }), (i, tail) => {
    const b = new Uint8Array([...magics[i]!, ...tail]);
    for (const [n, f] of Object.entries(PARSERS)) safe(n, () => f(b));
  }), { numRuns: 120 });
});

test('every truncation of the small fixtures is handled', () => {
  for (const f of ['board.dtb', 'tiny.gguf', 'tiny.safetensors', 'notepad.lnk', 'add.jsc', 'triangle.frag.spv', 'uimage.bin']) {
    const b = fx(f);
    for (let n = 0; n < Math.min(b.length, 700); n += 7) for (const [name, fn] of Object.entries(PARSERS)) safe(`${name}(${f}[:${n}])`, () => fn(b.subarray(0, n)));
  }
});

test('mutated real binaries (byte flips) are handled, including async parsers', async () => {
  const rnd = fc.sample(fc.tuple(fc.integer({ min: 0, max: FIXTURES.length - 1 }), fc.array(fc.tuple(fc.nat(), fc.integer({ min: 0, max: 255 })), { minLength: 1, maxLength: 24 })), 60);
  for (const [i, flips] of rnd) {
    const b = fx(FIXTURES[i]!).slice();
    for (const [pos, v] of flips) b[pos % Math.min(b.length, 8192)] = v;
    for (const [n, f] of Object.entries(PARSERS)) safe(`${n}(${FIXTURES[i]})`, () => f(b));
    for (const [n, f] of Object.entries(ASYNC)) await safeAsync(`${n}(${FIXTURES[i]})`, () => f(b));
  }
});

test('huge declared counts are capped, not allocated', () => {
  const g = fx('tiny.gguf').slice(); new DataView(g.buffer).setBigUint64(16, 0xffffffffffn, true);
  assert.throws(() => X.parseGguf(g), X.ParseError);
  const s = new Uint8Array(16); new DataView(s.buffer).setBigUint64(0, 1n << 40n, true);
  assert.throws(() => X.parseSafetensors(s), X.ParseError);
  const sp = fx('triangle.frag.spv').slice(); new DataView(sp.buffer).setUint32(20, (0xffff << 16) | 17, true);
  assert.equal(X.parseSpirv(sp).complete, false);
  const e = fx('demo-x64.elf').slice();
  const hdr = X.parseBin(e).sections.find((x) => x.name === '.eh_frame_hdr')!;
  new DataView(e.buffer).setUint32(hdr.offset + 8, 0x7fffffff, true);
  assert.throws(() => X.elfUnwind(e), X.ParseError);
  assert.throws(() => X.readBytes(e, -1, 4), X.ParseError);
  assert.equal(X.readBytes(e, 0, 1 << 30).length, 64 * 1024);
  assert.throws(() => X.compilePattern('?? ??'), X.ParseError);
  assert.throws(() => X.parseIps('{"bug_type":"309"}\n{"threads": ['), X.ParseError);
});

test('deeply nested or pathological symbols finish quickly', () => {
  const deep = '_Z' + 'N1a'.repeat(5000) + 'E';
  safe('itanium-deep', () => X.demangleItanium(deep));
  safe('itanium-templates', () => X.demangleItanium('_Z1fI' + 'IiE'.repeat(3000) + 'Ev'));
  safe('msvc-deep', () => X.demangleMsvc('?' + 'a@'.repeat(5000) + '@YAXXZ'));
  safe('rust-backrefs', () => X.demangleRustV0('_RNv' + 'B_'.repeat(4000) + '3foo'));
});
