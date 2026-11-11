// Lua bytecode from the real Lua 5.1 to 5.4 and LuaJIT runtimes (via lupa), and BEAM files checked against pybeam.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { sample, bytes, json } from './helpers.js';
import { parseLua, luaListing, parseBeam, type LuaFunction } from '../src/index.js';

const all = (f: LuaFunction): LuaFunction[] => [f, ...f.children.flatMap(all)];

for (const [file, version, stripped] of [['sample.5.1.luac', '5.1', false], ['sample.5.2.luac', '5.2', false], ['sample.5.3.luac', '5.3', false], ['sample.5.3.stripped.luac', '5.3', true], ['sample.5.4.luac', '5.4', false], ['sample.5.4.stripped.luac', '5.4', true]] as const) {
  test(`lua ${file}: header, function tree and constants`, () => {
    const c = parseLua(bytes(sample('lua', file)));
    assert.equal(c.flavor, 'puc');
    assert.equal(c.version, version);
    assert.equal(c.stripped, stripped);
    assert.equal(c.functionCount, 3);
    const [main, add, shout] = [c.main, c.main.children[0]!, c.main.children[1]!];
    assert.equal(main.numParams, 0);
    assert.equal(main.isVararg, true);
    assert.deepEqual([add.numParams, add.isVararg, add.lineDefined, add.lastLineDefined], [2, false, 6, 8]);
    assert.deepEqual([shout.numParams, shout.isVararg, shout.lineDefined, shout.lastLineDefined], [1, true, 10, 13]);
    assert.ok(main.constants.includes('hello') && main.constants.includes('revlens') && main.constants.includes('shout') && main.constants.includes(2.5));
    assert.deepEqual(shout.constants.filter((k) => typeof k === 'string'), version === '5.1' ? ['string', 'upper', 'table', 'concat', ' '] : ['string', 'upper', 'table', 'concat', ' ']);
    if (!stripped) { assert.equal(main.source, '=sample.lua'); assert.deepEqual(add.locals, ['a', 'b']); }
    const ops = all(c.main).map((f) => f.instructions.map((i) => i.op));
    for (const o of ops) assert.ok(o.at(-1)!.startsWith('RETURN'), 'functions end with RETURN');
    if (version === '5.4') { assert.equal(ops[0]![0], 'VARARGPREP'); assert.deepEqual(ops[1], ['ADD', 'MMBIN', 'RETURN1', 'RETURN0']); }
    else assert.deepEqual(ops[1], ['ADD', 'RETURN', 'RETURN']);
    assert.match(luaListing(c), /function <=?sample\.lua:6,8>|function <\?:6,8>/);
  });
}

test('luajit 2.1: every prototype and bytecode word matches jit.util', () => {
  const ref = json(sample('lua', 'luajit.ref.json'))['luajit2.1'] as any[];
  for (const file of ['sample.luajit2.1.luac', 'sample.luajit2.1.stripped.luac']) {
    const c = parseLua(bytes(sample('lua', file)));
    assert.equal(c.flavor, 'luajit');
    assert.equal(c.version, 'luajit2.1');
    assert.equal(c.functionCount, ref.length);
    const mine = all(c.main).map((f) => ({ params: f.numParams, words: f.instructions.map((i) => i.word.toString(16).padStart(8, '0')).join(',') }));
    const theirs = ref.map((p) => ({ params: p.params, words: p.ins.join(',') }));
    const key = (x: { params: number; words: string }) => `${x.params}|${x.words}`;
    assert.deepEqual(mine.map(key).sort(), theirs.map(key).sort());
    assert.equal(c.main.instructions.at(-1)!.op, 'RET');
    assert.equal(c.main.instructions[0]!.op, 'KSTR');
    assert.equal(c.main.instructions[0]!.comment, '"hello"');
  }
});

test('beam: atoms, exports and imports match pybeam for an Erlang and an Elixir module', () => {
  const ref = json(sample('beam', 'beam.ref.json'));
  for (const f of Object.keys(ref)) {
    const b = parseBeam(bytes(sample('beam', f)));
    const r = ref[f];
    assert.equal(b.module, r.module);
    assert.deepEqual(b.atoms, r.atoms);
    assert.deepEqual(b.exports.map((e) => [e.name, e.arity, e.label]), r.exports);
    assert.deepEqual(b.imports.map((e) => [e.module, e.name, e.arity]), r.imports);
  }
  const sup = parseBeam(bytes(sample('beam', 'elixir_sup.beam')));
  assert.equal(sup.elixir, false);
  assert.deepEqual(sup.exports.map((e) => `${e.name}/${e.arity}`).sort(), ['init/1', 'module_info/0', 'module_info/1', 'start_link/0']);
  assert.deepEqual(sup.attributes, [{ tuple: [{ atom: 'vsn' }, ['146145147534225326979979009226905812178']] }, { tuple: [{ atom: 'behaviour' }, [{ atom: 'supervisor' }]] }]);
  assert.equal(sup.code?.functions, 4);
  const ver = parseBeam(bytes(sample('beam', 'Elixir.Version.beam')));
  assert.equal(ver.elixir, true);
  assert.equal(ver.hasDocs, true);
  assert.ok((ver.literals?.count ?? 0) > 0);
  assert.deepEqual((ver.compileInfo as any[]).map((t) => t.tuple[0].atom), ['version', 'options', 'source']);
});
