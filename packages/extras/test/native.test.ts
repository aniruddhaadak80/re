// ELF, PE, Mach-O, Go and Rust facts against pyelftools, readelf 2.44, pefile, lief, go tool nm.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as X from '../src/node.js';
import { REF, fx, cached, S } from './helpers.js';
import { join } from 'node:path';

const elf = fx('demo-x64.elf');

test('ELF x64: entry, DT_NEEDED and BIND_NOW match pyelftools', () => {
  const img = X.parseBin(elf);
  assert.equal('0x' + img.entry.toString(16), REF.elf_x64.entry);
  const d = X.elfDynamic(img);
  assert.deepEqual(d.needed, REF.elf_x64.needed);
  assert.equal(d.bindNow, REF.elf_x64.bindNow);
});

test('ELF x64: init_array targets and symbols match pyelftools', () => {
  const init = X.elfInitializers(elf);
  assert.deepEqual(init.map((i) => ({ target: '0x' + i.target.toString(16), symbol: i.symbol })), REF.elf_x64.initArray);
});

test('ELF x64: ABI tag note matches readelf -n', () => {
  const notes = X.elfNotes(elf);
  const abi = notes.find((n) => n.typeName === 'NT_GNU_ABI_TAG')!;
  assert.match(REF.elf_x64.readelfNotes, /OS: Linux, ABI: 2\.0\.0/);
  assert.deepEqual(abi.decoded, { os: 'Linux', abi: '2.0.0' });
});

test('ELF x64: checksec RELRO, NX, canary agree with program headers and dynsym', () => {
  const c = X.checksec(elf);
  const get = (n: string) => c.checks.find((x) => x.name === n)!.value;
  assert.equal(get('RELRO'), REF.elf_x64.relro ? (REF.elf_x64.bindNow ? 'full' : 'partial') : 'none');
  assert.equal(get('NX'), REF.elf_x64.nx);
  assert.equal(get('Stack canary'), REF.elf_x64.stackChk);
  assert.equal(get('PIE'), false); // ET_EXEC
});

test('ELF unwind: FDE count and the first 50 ranges match pyelftools EH CFI', () => {
  const u = X.elfUnwind(elf, { limit: 5000 });
  assert.equal(u.source, '.eh_frame_hdr');
  assert.equal(u.total, REF.elf_x64.fdeCount);
  assert.equal(u.ranges.length, REF.elf_x64.fdeCount);
  const mine = u.ranges.map((r) => ({ start: r.start, size: r.size })).sort((a, b) => parseInt(a.start, 16) - parseInt(b.start, 16));
  assert.deepEqual(mine.slice(0, 50), REF.elf_x64.fdes);
  assert.deepEqual(u.issues, []);
});

test('ELF unwind: stripped static aarch64 musl binary FDE count matches readelf --debug-dump=frames', () => {
  const u = X.elfUnwind(fx('demo-arm64-stripped.elf'), { limit: 5000 });
  assert.equal(u.total, REF.elf_arm64_stripped.fdeCount);
  const p = X.elfUnwind(fx('demo-arm64-stripped.elf'), { offset: 600, limit: 100 });
  assert.equal(p.ranges.length, REF.elf_arm64_stripped.fdeCount - 600);
});

const pe = fx('hello-res.exe');
test('PE: version info, string table entries and fixed versions match pefile', () => {
  const vi = X.peVersionInfo(pe)!;
  assert.equal(vi.fileVersion, REF.pe_hello.fileVersion);
  assert.equal(vi.productVersion, REF.pe_hello.productVersion);
  for (const [k, v] of Object.entries(REF.pe_hello.strings)) assert.equal(vi.strings[k], v, k);
  assert.deepEqual(X.peStringTable(pe).map((s) => s.value), ['first string', 'second string']);
});

test('PE: resources (type, name, language, size, file offset) match pefile', () => {
  const r = X.peResources(pe).map((x) => ({ type: x.typeId, name: Number(x.name), lang: x.lang, size: x.size, offset: x.offset }));
  const want = REF.pe_hello.resources.map((x: { type: number; name: number; lang: number; size: number; offset: number }) => ({ type: x.type, name: x.name, lang: x.lang, size: x.size, offset: x.offset }));
  assert.deepEqual(r, want);
  const m = X.peManifest(pe)!;
  assert.equal(m.requestedExecutionLevel, 'asInvoker');
  assert.equal(REF.pe_hello.manifestHasAsInvoker, true);
});

test('PE: headers, checksum, exports and imports match pefile', () => {
  const h = X.peHeaders(pe);
  assert.equal('0x' + h.imageBase.toString(16), REF.pe_hello.imageBase);
  assert.equal('0x' + h.entryRva.toString(16), REF.pe_hello.entry);
  assert.equal(h.checksum, REF.pe_hello.checksumHeader);
  assert.equal(h.computedChecksum, REF.pe_hello.checksumComputed);
  assert.equal(h.dllCharacteristics, REF.pe_hello.dllCharacteristics);
  assert.deepEqual(X.peExports(pe)!.functions.map((f) => f.name), REF.pe_hello.exports);
  assert.deepEqual(X.parseBin(pe).sections.map((s) => s.name), REF.pe_hello.sections);
});

test('PE: Authenticode digest of an unsigned file matches lief authentihash', async () => {
  assert.equal(await X.authenticodeDigest(pe), REF.pe_hello.authentihashSha256);
  assert.deepEqual(await X.peAuthenticode(pe), []);
});

test('PE: Microsoft signed strings64.exe verifies like lief (fetched fixture)', async (t) => {
  const b = cached('strings64.exe');
  if (!b || !REF.pe_strings64) { t.skip('run packages/extras/scripts/fetch-fixtures.mjs'); return; }
  const [sig] = await X.peAuthenticode(b);
  assert.ok(sig);
  assert.equal(sig.computedDigest, REF.pe_strings64.authentihashSha256);
  assert.equal(sig.signedDigest, REF.pe_strings64.signedDigest);
  assert.equal(sig.digestMatches, true);
  assert.equal(sig.signatureVerified, true);
  assert.equal(sig.messageDigestMatches, true);
  assert.equal(sig.signer.serial, REF.pe_strings64.signerSerial);
  assert.equal(REF.pe_strings64.verify, 'VERIFICATION_FLAGS.OK');
  // flip one byte inside .text: the digest must stop matching
  const bad = b.slice();
  const text = X.parseBin(bad).sections.find((s) => s.name === '.text')!;
  bad[text.offset + 100] = (bad[text.offset + 100]! ^ 0xff);
  const [s2] = await X.peAuthenticode(bad);
  assert.equal(s2!.digestMatches, false);
});

const mo = fx('hello-arm64.macho');
test('Mach-O: dylibs, code signature location and cdhash match lief plus SHA-256 of the CodeDirectory', () => {
  const info = X.machoInfo(mo);
  assert.deepEqual(info.dylibs.map((d) => d.name), REF.macho_hello.dylibs);
  assert.deepEqual(info.codeSignature, REF.macho_hello.codeSignature);
  const cs = X.machoCodeSignature(mo)!;
  assert.equal(cs.codeDirectories[0]!.cdhash, REF.macho_hello.codeDirectories[0].cdhash);
  assert.equal(cs.codeDirectories[0]!.identifier, REF.macho_hello.codeDirectories[0].identifier);
  assert.equal(cs.adhoc, true);
  assert.equal(cs.codeDirectories[0]!.pageHashesValid, true);
  assert.equal(info.build?.minos, REF.macho_hello.minos);
});

test('Go: stripped binary pclntab gives main.main and sampled symbols at go tool nm addresses', () => {
  const g = X.goSymbols(fx('go-hello-stripped.elf'))!;
  assert.ok(g);
  assert.equal(g.version, '1.20');
  const byName = new Map(g.functions.map((f) => [f.name, f.entry]));
  assert.equal('0x' + byName.get('main.main')!.toString(16), REF.go_hello.mainMain);
  let hit = 0;
  for (const [name, addr] of Object.entries(REF.go_hello.sample as Record<string, string>)) if (byName.has(name)) { assert.equal('0x' + byName.get(name)!.toString(16), addr, name); hit++; }
  assert.ok(hit >= Object.keys(REF.go_hello.sample).length - 3, `only ${hit} sampled symbols found`);
  assert.ok(Math.abs(g.functionCount - REF.go_hello.textSymbols) < REF.go_hello.textSymbols * 0.05);
});

test('Rust: jiter rustc version and crates match readelf .comment and registry paths', () => {
  const r = X.rustInfo(fx('jiter-0.5.0.so'));
  assert.equal(r.isRust, true);
  assert.equal(r.rustcVersion, REF.rust_jiter.rustc);
  assert.equal(r.rustcCommit?.slice(0, 9), REF.rust_jiter.rustc.match(/\(([0-9a-f]+)/)[1]);
  assert.deepEqual(r.crates.map((c) => [c.name, c.version]), REF.rust_jiter.crates);
  const o = X.rustInfo(fx('orjson-3.10.7.so'));
  assert.equal(o.rustcVersion, REF.rust_orjson.rustc);
  assert.equal(X.rustInfo(fx('demo-x64.elf')).isRust, false);
});

test('bytes tools: read, search with wildcards and address mapping agree with each other and the headers', async () => {
  const r = X.readBytes(elf, 0, 4);
  assert.equal(r.hex, '7f454c46');
  const s = X.searchBytes(elf, { hex: '7f 45 ?? 46' }, { limit: 5 });
  assert.equal(s.hits[0]!.offset, 0);
  const txt = X.searchBytes(pe, { text: 'RevLens Test Fixtures' });
  assert.ok(txt.hits.length >= 1);
  const vaHit = txt.hits.find((h) => h.section === '.rsrc')!;
  assert.ok(vaHit && vaHit.va);
  const back = X.addressMap(pe, { va: vaHit.va! });
  assert.equal(back.offset, vaHit.offset);
  assert.equal(back.section, '.rsrc');
  const entry = X.addressMap(elf, { va: REF.elf_x64.entry });
  assert.equal(entry.mapped, true);
  assert.equal(X.addressMap(elf, { offset: entry.offset }).va, REF.elf_x64.entry);
  const t = X.TOOLS.find((x) => x.name === 'x_read_bytes')!;
  const viaVa = await t.run({ path: join(S, 'demo-x64.elf'), va: REF.elf_x64.entry, length: 8 }) as { offset: number };
  assert.equal(viaVa.offset, entry.offset);
});
