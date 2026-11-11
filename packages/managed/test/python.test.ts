// .pyc parsing and disassembly checked against dis.get_instructions of CPython 3.8 to 3.13.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { sample, bytes, json } from './helpers.js';
import { parsePyc, disassemblePyc, walkCode, versionForMagic, pyRepr, isPyc, disText, PY_OPCODES, type PyCode } from '../src/index.js';

const VERSIONS = ['3.8', '3.9', '3.10', '3.11', '3.12', '3.13'];
const norm = (s: string) => s.replace(/ at 0x[0-9a-f]+/g, ' at 0x0').replace(/^to (L\d+|\d+)$/, 'to X');

for (const v of VERSIONS) {
  test(`pyc ${v}: header, code tree and every instruction match dis`, () => {
    const b = bytes(sample('python', `sample_mod.${v}.pyc`));
    const ref = json(sample('python', `sample_mod.${v}.json`));
    assert.ok(isPyc(b));
    const p = parsePyc(b);
    assert.equal(p.version, v);
    assert.equal(versionForMagic(p.header.magic), v);
    assert.equal(p.header.magic, PY_OPCODES[v]!.magic);
    assert.equal(p.header.hashBased, true); // compiled with UNCHECKED_HASH
    const codes: { c: PyCode; path: string }[] = [];
    walkCode(p.code, (c, path) => codes.push({ c, path }));
    assert.deepEqual(codes.map((x) => x.path), ref.codes.map((x: any) => x.path));
    let checked = 0;
    ref.codes.forEach((rc: any, i: number) => {
      const { c } = codes[i]!;
      assert.equal(c.firstlineno, rc.firstlineno);
      assert.deepEqual(c.names, rc.names);
      assert.deepEqual(c.varnames, rc.varnames);
      assert.deepEqual(c.freevars, rc.freevars);
      assert.deepEqual(c.cellvars, rc.cellvars);
      assert.equal(c.consts.length, rc.nconsts);
      assert.equal(c.code.length, rc.codeSize);
      const d = disassemblePyc(c, v);
      assert.equal(d.error, undefined);
      assert.equal(d.instructions.length, rc.ins.length, rc.path);
      rc.ins.forEach(([off, name, arg, argval, argrepr]: any[], k: number) => {
        const mi = d.instructions[k]!;
        const where = `${rc.path} @${off}`;
        assert.equal(mi.offset, off, where);
        assert.equal(mi.opname, name, where);
        assert.equal(mi.arg ?? null, arg, where);
        if (typeof argval === 'number' && mi.target !== undefined) assert.equal(mi.target, argval, where);
        if (argrepr && mi.argrepr !== undefined) assert.equal(norm(mi.argrepr), norm(argrepr), where);
        checked++;
      });
    });
    assert.ok(checked > 500);
  });
}

test('pyc: constants decode to Python values and reprs', () => {
  const p = parsePyc(bytes(sample('python', 'sample_mod.3.12.pyc')));
  assert.equal(p.code.consts[0], 'RevLens pyc fixture: exercises closures, comprehensions, exceptions, async and big constants.');
  const reprs = p.code.consts.map((c) => pyRepr(c));
  assert.ok(reprs.includes(`"hello\\tworld 'quoted'"`));
  assert.ok(reprs.includes("(1, 2.5, -3, 1000000000000000000000000000000, 1j, b'\\x00\\xffbytes', None, True, Ellipsis)"));
  assert.ok(reprs.includes("('OrderedDict',)"));
  const text = disText(p.code, p.version);
  assert.match(text, /Disassembly of <module>\/Widget\/scale\/inner/);
  assert.match(text, /LOAD_GLOBAL\s+\d+ \(NULL \+ range\)/);
});

test('pyc: magic table covers 2.7 to 3.13 and 3.7 opcode table differs from 3.8', () => {
  assert.equal(versionForMagic(62211), '2.7');
  assert.equal(versionForMagic(3394), '3.7');
  assert.equal(versionForMagic(3413), '3.8');
  assert.equal(versionForMagic(3495), '3.11');
  assert.equal(versionForMagic(3531), '3.12');
  assert.equal(versionForMagic(3571), '3.13');
  assert.equal(PY_OPCODES['3.7']!.names[120], 'SETUP_LOOP');
  assert.equal(PY_OPCODES['3.8']!.names[120], undefined);
  assert.equal(PY_OPCODES['3.8']!.names[6], 'ROT_FOUR');
});
