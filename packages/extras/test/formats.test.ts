// Firmware, JS engine, GPU, model, shortcut and crash report formats against binwalk 2.4.3,
// uboot, fdt, intelhex, node vm, llvm-readobj, GLSL sources, gguf-py, safetensors, pylnk3, Python json.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as X from '../src/node.js';
import { REF, fx, cached } from './helpers.js';

test('firmware scan finds every binwalk signature at the same offset', () => {
  const hits = X.scanFirmware(fx('fw-blob.bin'));
  const offsets = hits.map((h) => h.offset);
  assert.equal(REF.binwalk.length, 4);
  for (const b of REF.binwalk) assert.ok(offsets.includes(b.offset), `binwalk saw ${b.desc} at ${b.offset}`);
  const types = Object.fromEntries(hits.map((h) => [h.offset, h.type]));
  assert.equal(types[REF.binwalk[0].offset], 'uimage');
  assert.equal(types[REF.binwalk[2].offset], 'fdt');
});

test('uImage header matches the uboot package and binwalk', () => {
  const u = X.parseUImage(fx('uimage.bin'));
  assert.equal(u.name, REF.uimage.name);
  assert.equal(u.size, REF.uimage.size);
  assert.equal(parseInt(u.headerCrc, 16), REF.uimage.headerCrc);
  assert.equal(parseInt(u.dataCrc, 16), REF.uimage.dataCrc);
  assert.equal(u.headerCrcValid && u.dataCrcValid, true);
  assert.equal(u.loadAddress, REF.uimage.loadAddress);
  assert.match(REF.binwalk[0].desc, new RegExp(`header CRC: 0x${u.headerCrc}`, 'i'));
});

test('device tree matches the fdt package', () => {
  const d = X.parseFdt(fx('board.dtb'));
  assert.equal(d.version, REF.dtb.version);
  assert.equal(d.totalSize, REF.dtb.totalSize);
  assert.equal(d.root.props.model!.text, REF.dtb.model);
  assert.deepEqual(d.root.props.compatible!.text!.split('\0'), REF.dtb.compatible);
  const mem = d.root.children.find((c) => c.name === 'memory@80000000')!;
  assert.deepEqual(mem.props.reg!.u32, REF.dtb.memoryReg);
  assert.deepEqual(d.root.children.map((c) => c.path), ['/cpus', '/memory@80000000', '/serial@9000000']);
});

test('Intel HEX regions, size and start address match intelhex', () => {
  const h = X.parseIntelHex(new TextDecoder().decode(fx('fw.hex')));
  assert.deepEqual(h.badChecksums, []);
  assert.equal(h.dataBytes, REF.ihex.bytes);
  assert.deepEqual(h.regions.map((r) => [r.start, r.end]), REF.ihex.segments);
  assert.equal(h.startAddress, REF.ihex.start.EIP);
  const bad = new TextDecoder().decode(fx('fw.hex')).replace(/^(:10000000.{32})(..)/m, (_m, a: string, c: string) => a + ((parseInt(c, 16) + 1) & 0xff).toString(16).padStart(2, '0').toUpperCase());
  assert.equal(X.parseIntelHex(bad).badChecksums.length, 1);
});

test('V8 code cache header matches what node recorded when it made the cache', () => {
  const r = X.parseV8CodeCache(fx('add.jsc'));
  assert.equal(REF.v8.cachedDataRejected, false);
  assert.equal(fx('add.jsc').length, REF.v8.length);
  assert.equal(r.sourceLength, REF.v8.sourceLength);
  assert.equal(r.lengthMatches, true);
  assert.equal(r.headerSize + r.payloadLength, REF.v8.length);
  assert.equal(r.layout, 'v8-12+');
  assert.equal(r.isModule, false);
  assert.equal(X.inspectJsEngine(fx('add.jsc'))?.kind, 'v8-code-cache');
});

test('Hermes header reader rejects non Hermes data and reads a synthetic header', () => {
  assert.throws(() => X.parseHermes(fx('add.jsc')));
  const b = new Uint8Array(128); const dv = new DataView(b.buffer);
  dv.setBigUint64(0, X.HERMES_MAGIC, true); dv.setUint32(8, 96, true); dv.setUint32(32, 128, true); dv.setUint32(40, 7, true);
  const h = X.parseHermes(b);
  assert.equal(h.version, 96); assert.equal(h.functionCount, 7); assert.equal(h.lengthMatches, true);
});

test('PTX module directives and kernels match the PTX text', () => {
  const g = X.inspectGpu(fx('kernels.ptx'));
  assert.equal(g?.kind, 'ptx');
  const p = (g as { ptx: X.PtxInfo }).ptx;
  assert.equal(p.version, REF.ptx.version);
  assert.equal(p.target, REF.ptx.target);
  assert.deepEqual(p.entries.map((e) => e.name), REF.ptx.entries);
  assert.deepEqual(p.entries.map((e) => e.params), [3, 3]);
});

test('AMDGPU code object target, code object version, features and kernels match llvm-readobj', () => {
  const a = X.parseAmdgpu(fx('kernels-gfx906.o'));
  assert.equal(a.target, REF.amdgpu.mach);
  assert.equal(a.codeObjectVersion, REF.amdgpu.abiVersion + 2);
  assert.equal(a.xnack, REF.amdgpu.xnackOff ? 'xnack-' : 'xnack+');
  assert.equal(a.sramecc, REF.amdgpu.srameccOff ? 'sramecc-' : 'sramecc+');
  assert.deepEqual(a.kernels.sort(), REF.amdgpu.kernels);
});

test('SPIR-V header, stage and local size match the shaders GLSL sources', () => {
  for (const [name, r] of Object.entries(REF.spirv as Record<string, { version: string; generator: number; bound: number; model: string; glsl: number; localSize: number[] | null }>)) {
    const s = X.parseSpirv(fx(`${name}.spv`));
    assert.equal(s.version, r.version);
    assert.equal(parseInt(s.generator.hex, 16), r.generator);
    assert.equal(s.bound, r.bound);
    assert.equal(s.entryPoints[0]!.executionModel, r.model);
    assert.equal(s.entryPoints[0]!.name, 'main');
    assert.deepEqual(s.source, { language: 'GLSL', version: r.glsl });
    assert.equal(s.complete, true);
    if (r.localSize) assert.deepEqual(s.executionModes.find((m) => m.mode === 17)!.operands, r.localSize);
  }
});

test('fatbin reader parses a fatbin container built to the documented layout', () => {
  // no CUDA toolchain in the sandbox: build a container holding the real PTX
  const ptx = fx('kernels.ptx');
  const eh = 64, total = 16 + eh + ptx.length;
  const b = new Uint8Array(total); const dv = new DataView(b.buffer);
  dv.setUint32(0, X.FATBIN_MAGIC, true); dv.setUint16(4, 1, true); dv.setUint16(6, 16, true); dv.setBigUint64(8, BigInt(eh + ptx.length), true);
  dv.setUint16(16, 1, true); dv.setUint32(20, eh, true); dv.setBigUint64(24, BigInt(ptx.length), true); dv.setUint16(36, 0, true); dv.setUint16(38, 6, true); dv.setUint32(40, 70, true);
  b.set(ptx, 16 + eh);
  const f = X.parseFatbin(b);
  assert.equal(f.entries.length, 1);
  assert.equal(f.entries[0]!.kind, 'ptx'); assert.equal(f.entries[0]!.arch, 'sm_70');
  assert.deepEqual(f.entries[0]!.ptx!.entries.map((e) => e.name), REF.ptx.entries);
  assert.equal(X.findFatbins(new Uint8Array([...new Uint8Array(100), ...b])).length, 1);
});

test('GGUF metadata and tensor table match gguf-py GGUFReader', () => {
  const g = X.parseGguf(fx('tiny.gguf'));
  assert.equal(g.architecture, REF.gguf.arch);
  assert.equal(g.metadataCount, REF.gguf.kvCount);
  assert.deepEqual(g.tensors.map((t) => ({ name: t.name, shape: t.shape, type: t.type, fileOffset: t.fileOffset, bytes: t.bytes })), REF.gguf.tensors);
  assert.deepEqual(g.issues, []);
});

test('safetensors header matches safetensors safe_open', () => {
  const s = X.parseSafetensors(fx('tiny.safetensors'));
  assert.equal(s.headerSize, REF.safetensors.headerSize);
  assert.deepEqual(s.metadata, REF.safetensors.metadata);
  for (const t of s.tensors) { assert.deepEqual(t.shape, REF.safetensors.tensors[t.name].shape); assert.equal(t.dtype, REF.safetensors.tensors[t.name].dtype); assert.equal(t.sizeMatches, true); }
  assert.equal(s.tensors.length, Object.keys(REF.safetensors.tensors).length);
  const n = X.parseNpy(fx('tiny.npy'));
  assert.deepEqual(n.shape, [2, 3, 4]); assert.equal(n.descr, '<f8');
});

test('LNK target, arguments, working dir, description and icon match pylnk3', () => {
  const l = X.parseLnk(fx('notepad.lnk'));
  assert.equal(l.target, REF.lnk.path);
  assert.equal(l.arguments, REF.lnk.arguments);
  assert.equal(l.workingDir, REF.lnk.workDir);
  assert.equal(l.name, REF.lnk.description);
  assert.equal(l.iconLocation, REF.lnk.icon);
  assert.equal(l.idList[0]!.value, 'My Computer');
});

test('Apple .ips: real macOS 12 report with a trailing System Profile matches Python json (fetched fixture)', (t) => {
  const b = cached('WindowServer.ips');
  if (!b || !REF.ips) { t.skip('run packages/extras/scripts/fetch-fixtures.mjs'); return; }
  const r = X.parseIps(b);
  assert.equal(r.process?.name, REF.ips.proc);
  assert.equal(r.exception?.type, REF.ips.exception);
  assert.equal(r.exception?.signal, REF.ips.signal);
  assert.equal(r.threads.length, REF.ips.threads);
  assert.equal(r.images.length, REF.ips.images);
  assert.equal(r.crashedFrames[0]!.symbol, REF.ips.frame0.symbol);
  assert.equal(r.crashedFrames[0]!.image, REF.ips.frame0.image);
  assert.equal(r.crashedFrames[0]!.address, REF.ips.frame0.address);
  assert.match(r.trailer ?? '', /^System Profile:/);
});
