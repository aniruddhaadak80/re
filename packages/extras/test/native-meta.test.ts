// Round 3 native metadata against independent tools:
//  * ObjC fixtures (samples/extras/native-meta/objc-*-macos, built with zig cc from t.m): llvm-objdump 19
//    --macho --objc-meta-data, llvm-nm and radare2 rabin2 -cj, recorded by scripts/gen_reference_r3.py.
//  * Maccy 2.8.0 (fetched, chained fixups, relative method lists, Swift 5 metadata): radare2 rabin2 -cj.
//  * Hermes 84, 94, 99 (fetched from hermes-dec's test folder): official hbcdump -raw-disassemble output
//    for 94 and 99, hermes-dec's disassembly for 84.
//  * Dart 3.5.4 AOT snapshot (samples/extras/dart): the V8 snapshot profile and instruction sizes written
//    by gen_snapshot itself.
// Hostile inputs: random bytes, truncation and bit flips must end fast with an error or a partial answer.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import fc from 'fast-check';
import {
  MachImage, readObjc, readSwift, nativeDispatchMetadata, dispatchMetadataView, HbcFile, hermesRawListing, hermesView,
  inspectDartAot, scanDartStrings, opcodeTable, SUPPORTED_HBC_VERSIONS, TOOLS, CLI_COMMANDS,
} from '../src/node.js';
import { S, CACHE } from './helpers.js';

const NM = join(S, 'native-meta');
const REF = JSON.parse(readFileSync(join(NM, 'reference.json'), 'utf8'));
const bin = (p: string) => new Uint8Array(readFileSync(p));
const MACCY = join(CACHE, 'maccy-Maccy.macho');
const HERMES = join(CACHE, 'hermes');
const hx = (n: number) => '0x' + n.toString(16);

for (const [arch, file] of [['aarch64', 'objc-aarch64-macos'], ['x86_64', 'objc-x86_64-macos']] as const) {
  test(`ObjC ${arch}: classes, methods, ivars, properties, protocols and categories match llvm-objdump`, () => {
    const ref = REF.objcFixture[arch];
    const img = new MachImage(bin(join(NM, file)));
    assert.equal(img.fixupSource, 'dyld-info');
    const md = readObjc(img);
    assert.deepEqual(md.errors, []);
    assert.equal(md.classes.length, ref.classes.length);
    for (const rc of ref.classes) {
      const c = md.classes.find((x) => x.name === rc.name)!;
      assert.ok(c, rc.name);
      assert.equal(c.flags, rc.flags, `${rc.name} flags`);
      assert.equal(c.instanceStart, rc.instanceStart);
      assert.equal(c.instanceSize, rc.instanceSize);
      assert.equal(c.superclass?.name ?? null, rc.superclass === '0x0' ? null : rc.superclass ?? null);
      assert.deepEqual(c.methods.map((m) => [m.name, m.types, m.imp, m.impSymbol]), rc.methods.map((m: any) => [m.name, m.types, m.imp, m.impSymbol]));
      assert.deepEqual(c.classMethods.map((m) => [m.name, m.types, m.imp]), rc.classMethods.map((m: any) => [m.name, m.types, m.imp]));
      assert.deepEqual(c.ivars.map((v) => [v.name, v.type, v.size, v.alignment]), rc.ivars.map((v: any) => [v.name, v.type, v.size, v.alignment]));
      for (const v of c.ivars) if (REF.objcFixture[arch].ivarOffsets[`${c.name}.${v.name}`] !== undefined) assert.equal(v.offset, ref.ivarOffsets[`${c.name}.${v.name}`], v.name);
      assert.deepEqual(c.properties, rc.properties);
      assert.deepEqual(c.protocols, rc.protocols);
    }
    assert.equal(md.categories.length, ref.categories.length);
    const cat = md.categories[0]!, rcat = ref.categories[0];
    assert.equal(cat.name, rcat.name);
    assert.equal(cat.class.name, 'RLWidget');
    assert.deepEqual(cat.instanceMethods.map((m) => [m.name, m.types, m.imp]), rcat.instanceMethods.map((m: any) => [m.name, m.types, m.imp]));
    assert.deepEqual(cat.classMethods.map((m) => [m.name, m.types, m.imp]), rcat.classMethods.map((m: any) => [m.name, m.types, m.imp]));
    assert.deepEqual(cat.properties, rcat.properties);
    assert.deepEqual(md.protocols.map((p) => p.name), ref.protocols);
    const g = md.protocols[0]!;
    assert.deepEqual(g.instanceMethods.map((m) => m.name), ['greet:name:']);
    assert.deepEqual(g.optionalInstanceMethods.map((m) => m.name), ['level']);
    assert.deepEqual(g.optionalClassMethods.map((m) => m.name), ['shared']);
    assert.deepEqual(g.extendedTypes, ['i28@0:8i16r*20', 'i16@0:8', '@16@0:8']);
    assert.equal(md.imageInfo?.flags, 0x40);
  });
}

for (const [arch, r2arch] of [['x86_64', 'x86_64'], ['arm64', 'arm64']] as const) {
  test(`Maccy ${arch}: ObjC classes (chained fixups${arch === 'arm64' ? ', relative method lists' : ''}) match radare2`, { skip: !existsSync(MACCY) && 'run packages/extras/scripts/fetch-fixtures.mjs' }, () => {
    const ref = REF.maccy[r2arch];
    const img = new MachImage(bin(MACCY), arch);
    assert.equal(img.fixupSource, 'chained');
    assert.equal(img.pointerFormat, 'DYLD_CHAINED_PTR_64_OFFSET');
    const md = readObjc(img);
    assert.deepEqual(md.errors, []);
    const refObjc = Object.entries(ref.objc) as [string, any][];
    assert.equal(md.classes.length, refObjc.length);
    let methods = 0, nameEq = 0;
    for (const [addr, rc] of refObjc) {
      const c = md.classes.find((x) => x.metaclass === addr || x.addr === addr);
      assert.ok(c, `class at ${addr}`);
      // swift-demangle prints private types as (Name in _HASH) where radare2 prints _HASH.Name; local types
      // (RepeatState #1 in ...) radare2 prints in its own short form, so names are compared as a rate
      if ((c!.demangledName ?? c!.name).replace(/\((\w+) in (_[0-9A-F]+)\)/g, '$2.$1') === rc.name.replace(/_\d+$/, '')) nameEq++;
      assert.equal(c!.superclass?.demangledName ?? c!.superclass?.name, rc.super);
      const mine = new Set([...c!.methods, ...c!.classMethods].map((m) => `${m.name}@${m.imp}`));
      // radare2 sometimes adds entries with an IMP outside __text (protocol data read as methods); compare the code ones
      for (const [name, imp] of rc.methods) { if (img.sectionOf(Number(imp))?.name !== '__text') continue; assert.ok(mine.has(`${name}@${imp}`), `${rc.name} ${name} ${imp}`); methods++; }
      const ivars = new Map(c!.ivars.map((v) => [v.name, v.offset]));
      for (const [name, off] of rc.ivars) if (off !== undefined && off !== null && off < 1 << 20) assert.equal(ivars.get(name), off, `${rc.name}.${name}`);
    }
    assert.ok(methods >= 70, `${methods} methods compared`);
    assert.ok(nameEq >= refObjc.length - 3, `${nameEq}/${refObjc.length} class names`);
    if (arch === 'arm64') assert.ok(md.classes.some((c) => c.methodListKind === 'relative'));
  });

  test(`Maccy ${arch}: Swift types, fields and field types match radare2, with demangled types radare2 misses`, { skip: !existsSync(MACCY) && 'run packages/extras/scripts/fetch-fixtures.mjs' }, () => {
    const ref = REF.maccy[r2arch];
    const img = new MachImage(bin(MACCY), arch);
    const md = readSwift(img);
    assert.deepEqual(md.errors, []);
    const byAddr = new Map<string, { name: string; fields: { name: string; type: string | null }[] }>([...md.types.map((t) => [t.addr, t] as const), ...md.protocols.map((p) => [p.addr, { name: p.name, fields: [] }] as const)]);
    let names = 0, nameEq = 0, fields = 0, typed = 0, typedEq = 0;
    const norm = (s: string) => s.replace(/^weak /, '').replace(/ : /g, ': ').replace(/\?$/, '');
    for (const [addr, rt] of Object.entries(ref.swift) as [string, any][]) {
      const t = byAddr.get(addr);
      assert.ok(t, `swift type at ${addr} (${rt.name})`);
      names++; if (t!.name === rt.name) nameEq++;
      if (rt.kind === 'interface') continue;
      for (const [fname, ftype] of rt.fields) {
        const f = t!.fields.find((x) => x.name === fname);
        assert.ok(f, `${rt.name}.${fname}`);
        fields++;
        if (ftype && !ftype.includes('?') && !/^Swift\.UnicodeScalar$/.test(ftype)) { typed++; if (f!.type !== null && norm(f!.type) === norm(ftype)) typedEq++; }
      }
    }
    // radare2 names extension members after the extending module and suffixes duplicates (_1); everything else agrees
    assert.ok(nameEq / names >= 0.97, `${nameEq}/${names} names`);
    assert.ok(fields >= 990, `${fields} fields`);
    assert.ok(typedEq / typed >= 0.85, `${typedEq}/${typed} typed fields`);
    // radare2 prints "?" for many field types; we resolve all but accessor function and existential shape references
    const unresolved = md.types.reduce((n, t) => n + t.fields.filter((f) => f.type === null && f.mangledType).length, 0);
    assert.ok(unresolved <= 3, `${unresolved} unresolved field types`);
    const ed = md.types.find((t) => t.name === 'Maccy.LargeTextView.EditorState')!;
    assert.equal(ed.kind, 'class');
    assert.equal(ed.superclass, '__C.NSObject');
    assert.deepEqual(ed.fields.map((f) => [f.name, f.type]), [['_hasChanges', 'Swift.Bool'], ['storedText', 'Swift.String'], ['textView', 'weak __C.NSTextView?'], ['undoManager', '__C.NSUndoManager'], ['_$observationRegistrar', 'Observation.ObservationRegistrar']]);
    assert.ok(ed.conformances.includes('Observation.Observable'));
    assert.ok(md.conformances.length >= 490);
    assert.ok(md.protocols.some((p) => p.name === 'Maccy.ItemsContainer' && p.associatedTypes.join(',') === 'Item,Items'));
    assert.ok(md.types.some((t) => (t.vtable?.length ?? 0) > 0));
  });
}

test('dispatch metadata tool views and aliases', async () => {
  const p = join(NM, 'objc-aarch64-macos');
  const t = TOOLS.find((x) => x.name === 'x_native_dispatch_metadata')!;
  const sum = await t.run({ path: p }) as any;
  assert.equal(sum.objc.classes, 2);
  assert.equal(sum.objc.categories, 1);
  const cls = await t.run({ path: p, view: 'objc-classes', filter: 'widget' }) as any;
  assert.equal(cls.total, 1);
  assert.equal(cls.items[0].methods.length, 5);
  assert.ok(TOOLS.find((x) => x.name === 'x_inspect_native_dispatch_metadata'));
  assert.ok(CLI_COMMANDS.find((c) => c.name === 'x-objc-swift'));
  assert.throws(() => dispatchMetadataView(nativeDispatchMetadata(bin(p)), 'nope'));
});

test('arm64e chained pointers: authenticated rebases and binds decode per the dyld format', () => {
  // Synthesized minimal image: one __DATA page with an arm64e (format 1) chain of an auth rebase, a plain rebase,
  // an auth bind and a plain bind with addend. No arm64e Mach-O is available as a license clean fixture.
  const b = new Uint8Array(0x3000);
  const dv = new DataView(b.buffer);
  dv.setUint32(0, 0xfeedfacf, true); dv.setUint32(4, 0x0100000c, true); dv.setUint32(8, 2, true); dv.setUint32(12, 2, true);
  let p = 32; let ncmds = 0;
  const seg = (name: string, vm: number, vmsize: number, off: number, size: number) => {
    dv.setUint32(p, 0x19, true); dv.setUint32(p + 4, 72, true);
    for (let i = 0; i < name.length; i++) b[p + 8 + i] = name.charCodeAt(i);
    dv.setBigUint64(p + 24, BigInt(vm), true); dv.setBigUint64(p + 32, BigInt(vmsize), true); dv.setBigUint64(p + 40, BigInt(off), true); dv.setBigUint64(p + 48, BigInt(size), true);
    p += 72; ncmds++;
  };
  seg('__TEXT', 0x100000000, 0x1000, 0, 0x1000);
  seg('__DATA', 0x100001000, 0x1000, 0x1000, 0x1000);
  dv.setUint32(p, 0x80000034, true); dv.setUint32(p + 4, 16, true); dv.setUint32(p + 8, 0x2000, true); dv.setUint32(p + 12, 0x200, true); p += 16; ncmds++;
  dv.setUint32(16, ncmds, true); dv.setUint32(20, p - 32, true);
  const h = 0x2000;
  dv.setUint32(h, 0, true); dv.setUint32(h + 4, 0x20, true); dv.setUint32(h + 8, 0x60, true); dv.setUint32(h + 12, 0x70, true);
  dv.setUint32(h + 16, 1, true); dv.setUint32(h + 20, 1, true);
  const st = h + 0x20; dv.setUint32(st, 2, true); dv.setUint32(st + 4, 0, true); dv.setUint32(st + 8, 12, true);
  const ss = st + 12; dv.setUint32(ss, 24, true); dv.setUint16(ss + 4, 0x1000, true); dv.setUint16(ss + 6, 1, true);
  dv.setBigUint64(ss + 8, 0x1000n, true); dv.setUint32(ss + 16, 0, true); dv.setUint16(ss + 20, 1, true); dv.setUint16(ss + 22, 0, true);
  dv.setUint32(h + 0x60, (0 << 9) | 1, true); // import 0: lib 1, name offset 0
  'OBJC_CLASS_$_NSObject'.split('').forEach((c, i) => { b[h + 0x70 + 1 + i] = c.charCodeAt(0); });
  b[h + 0x70] = 0x5f; // "_OBJC_CLASS_$_NSObject"
  const put = (off: number, hi: number, lo: number) => { dv.setUint32(0x1000 + off, lo >>> 0, true); dv.setUint32(0x1000 + off + 4, hi >>> 0, true); };
  // auth rebase: target 0x1234 (offset), diversity 0xabcd, addrDiv 1, key DA (2), next 1 (8 bytes)
  put(0, (1 << 31) | (1 << 19) | (2 << 17) | (1 << 16) | 0xabcd, 0x1234);
  // plain rebase: target vmaddr 0x100000800 (43 bits), next 1
  put(8, (1 << 19) | 0x1, 0x00000800);
  // auth bind: ordinal 0, key IA, next 1
  put(16, (1 << 31) | (1 << 30) | (1 << 19), 0);
  // plain bind: ordinal 0, addend 8, next 0
  put(24, (1 << 30) | 8, 0);
  const img = new MachImage(b);
  assert.equal(img.pointerFormat, 'DYLD_CHAINED_PTR_ARM64E');
  assert.equal(img.arch, 'arm64e');
  assert.deepEqual(img.readPointer(0x100001000), { addr: 0x100001234, auth: { diversity: 0xabcd, addrDiv: true, key: 'DA' }, raw: 0x100001234 });
  assert.equal(img.ptr(0x100001008), 0x100000800);
  assert.equal(img.readPointer(0x100001010).bind, '_OBJC_CLASS_$_NSObject');
  assert.equal(img.readPointer(0x100001010).auth?.key, 'IA');
  assert.equal(img.readPointer(0x100001018).addend, 8);
  // raw arm64e pointer stripping when no fixup covers the slot
  assert.equal(img.strip(0x0012_0001_0000_0800), 0x100000800);
});

// ---------- Hermes ----------

function officialLines(file: string, withEh: boolean): string[] {
  return readFileSync(file, 'utf8').split('\n').map((l) => l.replace(/^hbcdump> /, '')).filter((l) => (withEh ? /^(NC)?Function<|^\[@ |^Exception Handlers:|^\d+: start/ : /^(NC)?Function<|^\[@ /).test(l));
}

for (const v of [94, 99]) {
  test(`Hermes ${v}: every function heading, instruction and exception handler matches hbcdump -raw-disassemble`, { skip: !existsSync(join(HERMES, `${v}-sample.hbc`)) && 'run packages/extras/scripts/fetch-fixtures.mjs' }, () => {
    const b = bin(join(HERMES, `${v}-sample.hbc`));
    const want = officialLines(join(HERMES, `${v}-sample.hermes_raw_hasm`), v < 97);
    const got = hermesRawListing(b).filter((l) => v < 97 || !/^Exception Handlers:|^\d+: start/.test(l));
    assert.equal(got.length, want.length);
    for (let i = 0; i < want.length; i++) assert.equal(got[i], want[i], `line ${i}`);
    const h = new HbcFile(b);
    assert.equal(h.header.version, v);
    assert.equal(h.header.functionCount, 8);
    assert.equal(h.header.sourceHash, 'a692192bdc8ee6f7b2b9918faf18a64db39587c8');
    // the string table matches the "Global String Table" listing
    const table = readFileSync(join(HERMES, `${v}-sample.hermes_raw_hasm`), 'utf8').split('\n').filter((l) => /^[si]\d+\[(ASCII|UTF-16), /.test(l));
    assert.equal(table.length, h.header.stringCount);
    for (const l of table) {
      const m = /^([si])(\d+)\[(ASCII|UTF-16), (-?\d+)\.\.(-?\d+)\]/.exec(l)!;
      const s = h.string(Number(m[2]));
      assert.equal(s.kind, m[3]);
      assert.equal(s.identifier, m[1] === 'i');
      assert.equal(s.offset, Number(m[4]));
      assert.equal(s.offset + (s.kind === 'UTF-16' ? s.length * 2 : s.length) - 1, Number(m[5]), `string ${m[2]}`);
    }
  });
}

test('Hermes 84: 17899 functions and every instruction match hermes-dec', { skip: !existsSync(join(HERMES, '84-sample.hbc')) && 'run packages/extras/scripts/fetch-fixtures.mjs', timeout: 60000 }, () => {
  const h = new HbcFile(bin(join(HERMES, '84-sample.hbc')));
  assert.equal(h.functions.length, 17899);
  assert.equal(h.header.stringCount, 20549);
  assert.equal(h.header.overflowStringCount, 271);
  const text = readFileSync(join(HERMES, '84-sample.hermes_dec_hasm'), 'utf8');
  const hd = /^=> \[Function #(\d+) "(.*)" of (\d+) bytes\]: (\d+) params, frame size=(\d+), strict=(\d), exc handler=(\d), debug info=(\d)\s+@ offset 0x([0-9a-f]+)/;
  const ins = /^==> ([0-9a-f]{8}): <(\w+)>: <(.*?)>(?:\s+#.*)?$/;
  let fns = 0, insns = 0, k = 0;
  let cur: ReturnType<HbcFile['disassemble']>['insns'] = [];
  for (const line of text.split('\n')) {
    let m = hd.exec(line);
    if (m) {
      const f = h.functions[Number(m[1])]!;
      assert.deepEqual([f.name, f.size, f.paramCount, f.frameSize, +f.strictMode, +f.hasExceptionHandler, +f.hasDebugInfo, f.offset], [m[2], +m[3]!, +m[4]!, +m[5]!, +m[6]!, +m[7]!, +m[8]!, parseInt(m[9]!, 16)], `function ${m[1]}`);
      cur = h.disassemble(f).insns; k = 0; fns++;
      continue;
    }
    m = ins.exec(line);
    if (!m) continue;
    const i = cur[k++]!;
    assert.equal(i.offset, parseInt(m[1]!, 16));
    assert.equal(i.name, m[2]);
    const vals = m[3]!.split(', ').filter(Boolean).map((x) => x.split(': ')[1]!);
    vals.forEach((v, j) => {
      const o = i.operands[j]!;
      if (o.type === 'Double') assert.ok(v === 'inf' ? o.value === Infinity : v === '-inf' ? o.value === -Infinity : v === 'nan' ? Number.isNaN(o.value) : Math.abs(Number(v) - o.value) <= 1e-9 * Math.max(1, Math.abs(o.value)), `${v} vs ${o.value}`);
      else assert.equal(o.value, Number(v));
    });
    insns++;
  }
  assert.equal(fns, 17899);
  assert.ok(insns > 589000, `${insns}`);
});

test('Hermes views: strings, xrefs to a string, closures, raw disassembly', { skip: !existsSync(join(HERMES, '94-sample.hbc')) && 'run packages/extras/scripts/fetch-fixtures.mjs' }, async () => {
  const b = bin(join(HERMES, '94-sample.hbc'));
  const s = hermesView(b, { view: 'strings', filter: 'exception' }) as any;
  assert.deepEqual(s.items.map((x: any) => x.value), ['Hello! Exception handling']);
  const x = hermesView(b, { view: 'xrefs', string: 'Exception handling' }) as any;
  assert.equal(x.total, 1);
  assert.equal(x.items[0].name, '?anon_0_gen');
  assert.match(x.items[0].insn, /^LoadConstString r4, "Hello! Exception handling"$/);
  const c = hermesView(b, { view: 'closures' }) as any;
  assert.ok(c.items.some((r: any) => r.parentName === 'global' && r.childName === 'testx'));
  const d = await TOOLS.find((t) => t.name === 'x_hermes_bytecode')!.run({ path: join(HERMES, '94-sample.hbc'), view: 'disassemble', function: 'zb', format: 'raw' }) as any;
  assert.equal(d.items[0], '[@ 0] GetGlobalObject 0<Reg8>');
  const sum = hermesView(b) as any;
  assert.equal(sum.version, 94);
  assert.equal(sum.functionsWithDecodeErrors, 0);
});

test('Hermes opcode tables: one per version 84 to 99, generated from BytecodeList.def', () => {
  for (let v = 84; v <= 99; v++) assert.ok(SUPPORTED_HBC_VERSIONS.includes(v), String(v));
  const t94 = opcodeTable(94)!;
  assert.equal(t94[0]!.name, 'Unreachable');
  assert.equal(t94.find((o) => o.name === 'GetById')!.ids[3], 's');
  assert.deepEqual(t94.find((o) => o.name === 'JmpTrueLong')!.operands, ['Addr32', 'Reg8']);
  assert.ok(!opcodeTable(84)!.some((o) => o.name === 'LoadConstBigInt'));
  assert.ok(opcodeTable(87)!.some((o) => o.name === 'LoadConstBigInt'));
});

// ---------- Dart ----------

test('Dart AOT 3.5.4: snapshot headers, read only string pool and function symbols match gen_snapshot output', () => {
  const info = inspectDartAot(bin(join(S, 'dart', 'main-aot.so')));
  const data = info.snapshots.filter((s) => s.magicOk);
  assert.equal(data.length, 2);
  for (const s of data) {
    assert.equal(s.kindName, 'FullAOT');
    assert.equal(s.hash, '80a49c7111088100a233b2ae788e1f48');
    assert.equal(s.arch, 'arm64'); assert.equal(s.os, 'linux'); assert.equal(s.compressedPointers, false); assert.equal(s.product, true);
  }
  const ro: string[] = REF.dart.roStrings;
  const mine = new Set(info.strings.map((s) => s.value));
  const found = ro.filter((x) => mine.has(x)).length;
  assert.ok(found >= ro.length - 2, `${found}/${ro.length} read only strings`);
  for (const x of ['hunter2-revlens', 'access granted', 'https://api.example.com/v1/login', 'insufficient funds for ']) assert.ok(mine.has(x), x);
  assert.equal(info.functionSource, 'elf-symtab');
  const names = new Set(info.functions.map((f) => f.name));
  const user = (REF.dart.functions as string[]).filter((n) => /^(Account|Circle|Square)\.(?!Allocate)|^checkPassword$|^main$/.test(n));
  assert.ok(user.length >= 6);
  for (const n of user) assert.ok(names.has(n), n);
  assert.ok(info.functions.length >= REF.dart.instructionsEntries);
});

test('Dart AOT stripped: strings still found, functions reported as partial', () => {
  const info = inspectDartAot(bin(join(S, 'dart', 'main-aot-stripped.so')));
  assert.equal(info.functionSource, 'none');
  assert.ok(info.partial.length >= 2);
  assert.ok(info.strings.some((s) => s.value === 'hunter2-revlens'));
  assert.ok(info.libraries.includes('dart:core'));
});

// ---------- hostile input ----------

const fixtures = [join(NM, 'objc-aarch64-macos'), join(NM, 'objc-x86_64-macos')];
test('hostile Mach-O: random tails, truncation and bit flips end fast', () => {
  for (const f of fixtures) {
    const good = bin(f);
    for (const cut of [0, 16, 31, 32, 200, 1000, 4096, 16384, 0x8000, good.length - 1]) {
      const t0 = Date.now();
      try { const md = nativeDispatchMetadata(good.subarray(0, cut)); assert.ok(md.objc && md.swift); } catch (e) { assert.ok(e instanceof Error); }
      assert.ok(Date.now() - t0 < 2000);
    }
    fc.assert(fc.property(fc.array(fc.tuple(fc.nat(good.length - 1), fc.integer({ min: 0, max: 255 })), { minLength: 1, maxLength: 64 }), (flips) => {
      const b = good.slice();
      for (const [o, v] of flips) b[o] = v;
      const t0 = Date.now();
      try { nativeDispatchMetadata(b, { budgetMs: 2000 }); } catch (e) { assert.ok(e instanceof Error); }
      assert.ok(Date.now() - t0 < 3000);
    }), { numRuns: 120 });
  }
  fc.assert(fc.property(fc.uint8Array({ minLength: 0, maxLength: 4096 }), (b) => { try { nativeDispatchMetadata(b); } catch (e) { assert.ok(e instanceof Error); } }), { numRuns: 200 });
});

test('hostile Hermes bytecode: random bodies behind a real header end fast', { skip: !existsSync(join(HERMES, '94-sample.hbc')) && 'run packages/extras/scripts/fetch-fixtures.mjs' }, () => {
  const good = bin(join(HERMES, '94-sample.hbc'));
  fc.assert(fc.property(fc.array(fc.tuple(fc.nat(good.length - 1), fc.integer({ min: 0, max: 255 })), { minLength: 1, maxLength: 40 }), fc.nat(good.length), (flips, cut) => {
    const b = good.slice(0, Math.max(12, cut));
    for (const [o, v] of flips) if (o >= 12 && o < b.length) b[o] = v;
    const t0 = Date.now();
    try { hermesView(b, { view: 'summary', budgetMs: 1000 }); hermesRawListing(b); } catch (e) { assert.ok(e instanceof Error); }
    assert.ok(Date.now() - t0 < 3000);
  }), { numRuns: 200 });
  // huge counts in the header
  const b = good.slice();
  new DataView(b.buffer).setUint32(40, 0x7fffffff, true);
  assert.throws(() => new HbcFile(b));
});

test('hostile Dart snapshots: random data blobs and flipped headers end fast', () => {
  const good = bin(join(S, 'dart', 'main-aot-stripped.so'));
  fc.assert(fc.property(fc.array(fc.tuple(fc.nat(good.length - 1), fc.integer({ min: 0, max: 255 })), { minLength: 1, maxLength: 64 }), (flips) => {
    const b = good.slice();
    for (const [o, v] of flips) b[o] = v;
    const t0 = Date.now();
    try { inspectDartAot(b); } catch (e) { assert.ok(e instanceof Error); }
    assert.ok(Date.now() - t0 < 5000);
  }), { numRuns: 30 });
  fc.assert(fc.property(fc.uint8Array({ minLength: 0, maxLength: 8192 }), (b) => {
    const r = scanDartStrings(b, { name: 'x', offset: 0, size: b.length });
    assert.ok(Array.isArray(r.strings));
  }), { numRuns: 200 });
});
