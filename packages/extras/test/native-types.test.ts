// PDB types and COM type libraries on real files built from samples/extras/native-meta/src
// (zig cc 0.17.1 with -gcodeview and lld-link, widl 9.8, llvm-rc 19). PDB expectations come from
// llvm-pdbutil 19 pdb2yaml (samples/extras/native-meta/pdb-reference.json, written by
// make-pdb-reference.py). Type library expectations come from the IDL source widl compiled
// (revdemo.idl): names, GUIDs, DISPIDs widl assigns, vtable offsets and parameter flags.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import fc from 'fast-check';
import { readPdb, pdbTypeDecl, readTypeLib, typeLibsIn, typeInfoIdl, peDebug, TOOLS } from '../src/index.ts';

const dir = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..', 'samples', 'extras', 'native-meta');
const P = (n: string) => join(dir, n);
const bytes = (n: string) => new Uint8Array(readFileSync(P(n)));
const REF = JSON.parse(readFileSync(P('pdb-reference.json'), 'utf8')) as Record<string, any>;
const tool = (n: string) => TOOLS.find((t) => t.name === n)!;

for (const f of Object.keys(REF)) {
  const ref = REF[f];
  test(`${f}: GUID, age, user types, members and enumerators match llvm-pdbutil`, () => {
    const d = readPdb(bytes(f));
    assert.ok(d.complete, d.warnings.join('; '));
    assert.equal(d.guid, ref.guid);
    assert.equal(d.age, ref.age);
    for (const [name, t] of Object.entries<any>(ref.types)) {
      const x = d.types.find((y) => y.index === t.index)!;
      assert.equal(x.name, name);
      assert.equal(x.forwardRef, undefined);
      if (t.size !== null) assert.equal(x.size, t.size, name);
      if (t.leaf === 'LF_ENUM') {
        const want = t.members.map((m: any) => [m.name, m.value]);
        // llvm prints the stored unsigned value; RevLens sign extends for a signed underlying type
        assert.deepEqual(x.enumerators!.map((e) => [e.name, e.value < 0 ? e.value + 2 ** 32 : e.value]), want);
        continue;
      }
      const mine = x.members!;
      assert.equal(mine.length, t.members.length, name);
      t.members.forEach((m: any, i: number) => {
        const y = mine[i]!;
        const kind = m.kind === 'vfptr' ? 'vfptr' : m.kind;
        assert.equal(y.kind, kind, `${name}[${i}]`);
        if (m.name !== undefined) assert.equal(y.name, m.name);
        if (m.offset !== undefined) assert.equal(y.offset, m.offset, `${name}.${m.name ?? m.kind}`);
      });
    }
  });

  test(`${f}: function ids and procedures with parameters and locals match llvm-pdbutil`, () => {
    const d = readPdb(bytes(f));
    assert.deepEqual(d.funcIds.map((x) => ({ name: x.name, typeIndex: x.typeIndex })), ref.funcIds);
    assert.equal(d.procs.length, ref.procs.length);
    ref.procs.forEach((p: any, i: number) => {
      const x = d.procs[i]!;
      assert.deepEqual({ kind: x.kind, name: x.name, segment: x.segment, offset: x.offset, size: x.size, typeIndex: x.typeIndex }, { kind: p.kind, name: p.name, segment: p.segment, offset: p.offset, size: p.size, typeIndex: p.typeIndex });
      assert.deepEqual(x.locals.map((l) => ({ name: l.name, param: l.param })), p.locals);
    });
    for (const [ti, pr] of Object.entries<any>(ref.procedures)) assert.equal(d.types.find((t) => t.index === parseInt(ti, 16))!.params!.length, pr.params);
  });
}

test('types-x64.pdb: C declarations, typedefs, prototypes, RVAs and the PE CodeView link', () => {
  const d = readPdb(bytes('types-x64.pdb'));
  const node = d.types.find((t) => t.name === 'node' && !t.forwardRef)!;
  const decl = pdbTypeDecl(node);
  assert.match(decl, /int \(\*compare\)\(const void\*, const void\*\); \/\/ offset 64/);
  assert.match(decl, /unsigned ids\[4\]; \/\/ offset 44/);
  const flags = d.types.find((t) => t.name === 'flags' && !t.forwardRef)!;
  assert.deepEqual(flags.members!.map((m) => [m.name, m.bitSize, m.bitOffset]), [['a', 3, 0], ['b', 5, 3], ['c', 1, 8]]);
  const color = d.types.find((t) => t.name === 'color' && !t.forwardRef)!;
  assert.deepEqual(color.enumerators, [{ name: 'RED', value: 0 }, { name: 'GREEN', value: 5 }, { name: 'BLUE', value: -3 }]);
  assert.deepEqual(d.udts.find((u) => u.name === 'cmp_fn'), { name: 'cmp_fn', typeIndex: 0x1015, type: 'int (*)(const void*, const void*)' });
  assert.equal(d.udts.find((u) => u.name === 'u32_t')!.type, 'unsigned');
  const nw = d.procs.find((p) => p.name === 'node_weight')!;
  assert.equal(nw.prototype, 'int node_weight(node* n, int scale, color c)');
  assert.deepEqual(nw.locals.map((l) => [l.name, l.register]), [['n', 'rcx'], ['scale', 'edx'], ['c', 'r8d'], ['it', 'rcx']]);
  assert.equal(nw.rva, 0x1010);
  const g = d.globals.find((x) => x.name === 'g_root' && x.kind === 'S_GDATA32')!;
  assert.equal(g.kind, 'S_GDATA32');
  assert.equal(g.type, 'node');
  // the executable's CodeView RSDS record names this PDB by GUID and age
  const cv = peDebug(bytes('types-x64.exe')).find((e) => e.pdb)!;
  assert.equal(cv.pdb!.guid.toUpperCase().replace(/[{}]/g, ''), d.guid);
  assert.equal(cv.pdb!.age, d.age);
  assert.equal(cv.pdb!.symbolServerId, d.symbolServerId);
});

test('shapes-x64.pdb: C++ classes with base class, vtable pointer, static member and methods', async () => {
  const r: any = await tool('x_pdb_types').run({ path: P('shapes-x64.pdb'), view: 'type', name: 'geo::Shape' });
  assert.equal(r.found, true);
  assert.equal(r.kind, 'class');
  assert.equal(r.size, 24);
  assert.match(r.declarationText, /void \*\*__vfptr; \/\/ offset 0/);
  assert.match(r.declarationText, /static int count;/);
  assert.match(r.declarationText, /geo::Vec origin; \/\/ offset 12/);
  const rect: any = await tool('x_pdb_types').run({ path: P('shapes-x64.pdb'), view: 'type', name: 'geo::Rect' });
  assert.deepEqual(rect.members.filter((m: any) => m.kind === 'base').map((m: any) => [m.type, m.offset]), [['geo::Shape', 0]]);
  assert.equal(rect.members.find((m: any) => m.name === 'w_').access, 'private');
  const mode: any = await tool('x_pdb_types').run({ path: P('shapes-x64.pdb'), view: 'type', name: 'geo::Mode' });
  assert.equal(mode.underlying, 'unsigned char');
  const s: any = await tool('x_pdb_types').run({ path: P('shapes-x64.pdb') });
  assert.equal(s.machine, 'x64');
  assert.ok(s.userTypes >= 4);
});

const LIBID = '{7A3F0C11-5B2E-4C8A-9D21-0E5F6A7B8C90}';
for (const f of ['revdemo.tlb', 'revdemo-typelib.dll']) {
  test(`${f}: library, enum, record, interface, coclass and module read as the IDL declares`, () => {
    const libs = typeLibsIn(bytes(f));
    assert.equal(libs.length, 1);
    const t = libs[0]!;
    assert.equal(t.source!.kind, f.endsWith('.dll') ? 'pe-resource' : 'file');
    assert.equal(t.name, 'RevDemoLib');
    assert.equal(t.guid, LIBID);
    assert.equal(t.version, '1.2');
    assert.equal(t.syskind, 'win64');
    assert.equal(t.helpString, 'RevLens demo type library');
    const by = (n: string) => t.typeInfos.find((x) => x.name === n)!;
    assert.deepEqual(by('Shade').vars.map((v) => [v.name, v.value]), [['ShadeRed', 1], ['ShadeGreen', 2], ['ShadeBlue', -5]]);
    assert.equal(by('Shade').kind, 'enum');
    assert.deepEqual(by('Point').vars.map((v) => [v.name, v.type, v.offset]), [['x', 'long', 0], ['y', 'long', 4], ['weight', 'double', 8]]);
    assert.equal(by('Point').size, 16);
    const ip = by('IPainter');
    assert.equal(ip.kind, 'interface');
    assert.equal(ip.guid, '{7A3F0C14-5B2E-4C8A-9D21-0E5F6A7B8C90}');
    assert.deepEqual(ip.implements.map((x) => x.name), ['IUnknown']);
    assert.ok(ip.flags.includes('oleautomation'));
    assert.deepEqual(ip.funcs.map((x) => [x.name, x.invokeKind, x.vtableOffset]), [['Paint', 'func', 24], ['SetShade', 'func', 32], ['Name', 'propget', 40], ['Name', 'propput', 48], ['Move', 'func', 56]]);
    const paint = ip.funcs[0]!;
    assert.equal(paint.returns, 'HRESULT');
    assert.deepEqual(paint.params.map((p) => [p.name, p.type, p.flags]), [['count', 'long', ['in']], ['label', 'BSTR', ['in']], ['painted', 'long*', ['out', 'retval']]]);
    assert.deepEqual(ip.funcs[4]!.params.map((p) => [p.type, p.flags]), [['Point*', ['in']], ['VARIANT', ['in', 'optional']]]);
    assert.equal(ip.funcs[1]!.params[0]!.type, 'Shade');
    assert.equal(ip.funcs[2]!.memid, ip.funcs[3]!.memid, 'propget and propput share a DISPID');
    const co = by('Painter');
    assert.equal(co.kind, 'coclass');
    assert.deepEqual(co.implements, [{ name: 'IPainter', flags: ['default'] }]);
    assert.ok(co.flags.includes('cancreate'));
    const mod = by('RevDemoFns');
    assert.equal(mod.kind, 'module');
    assert.equal(mod.dllName, 'revdemo.dll');
    assert.equal(mod.funcs[0]!.name, 'RevAdd');
    assert.equal(mod.funcs[0]!.callConv, 'stdcall');
    assert.match(typeInfoIdl(ip), /\[propget, id\(0x60010002\)\] HRESULT Name\(\[out, retval\] BSTR\* value\);/);
  });
}

test('x_com_typelib tool: summary and type views', async () => {
  const s: any = await tool('x_com_typelib').run({ path: P('revdemo-typelib.dll') });
  assert.equal(s.name, 'RevDemoLib');
  assert.equal(s.kinds.interface, 2);
  const t: any = await tool('x_com_typelib').run({ path: P('revdemo.tlb'), view: 'type', name: '7A3F0C15-5B2E-4C8A-9D21-0E5F6A7B8C90' });
  assert.equal(t.name, 'Painter');
  assert.match(t.idl, /\[default\] interface IPainter;/);
});

test('hostile PDB and type library input: bit flips, random bytes and truncation fail cleanly and fast', () => {
  const pdb = bytes('types-x64.pdb');
  const tlb = bytes('revdemo.tlb');
  fc.assert(fc.property(fc.nat(), fc.uint8Array({ minLength: 1, maxLength: 64 }), fc.boolean(), (pos, junk, which) => {
    const base = which ? pdb : tlb;
    const b = base.slice();
    const at = which ? 4096 + (pos % (b.length - 4096)) : 32 + (pos % (b.length - 32));
    b.set(junk.subarray(0, Math.min(junk.length, b.length - at)), at);
    const t0 = Date.now();
    try { if (which) readPdb(b, { budgetMs: 2000 }); else readTypeLib(b); } catch (e) { assert.ok(e instanceof Error); }
    assert.ok(Date.now() - t0 < 3000);
  }), { numRuns: 200 });
  for (const n of [40, 100, 4096, 9000, 40000]) {
    try { readPdb(pdb.subarray(0, n)); } catch (e) { assert.ok(e instanceof Error); }
    try { readTypeLib(tlb.subarray(0, Math.min(n, tlb.length - 1))); } catch (e) { assert.ok(e instanceof Error); }
  }
  // a stream directory claiming 2^31 bytes
  const big = pdb.slice();
  new DataView(big.buffer).setUint32(44, 0x7fffffff, true);
  assert.throws(() => readPdb(big));
});
