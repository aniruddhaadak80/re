#!/usr/bin/env node
// Generates samples/disasm/nav-reference.json: reference values for the navigation tools taken
// from radare2 (afij, axtj, fd, pdj, aoj, isj, aflj, afbj). The tests read only the JSON, radare2
// is not needed to run them. Usage (radare2 on PATH, for example after `. tools/env.sh`):
//   node packages/disasm/scripts/make-nav-reference.mjs
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { writeFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const run = promisify(execFile);
const here = dirname(fileURLToPath(import.meta.url));
const dir = join(here, '..', '..', '..', 'samples', 'disasm');
const MARK = '@@@REVLENS@@@';

/** Runs one r2 session over a file: `aa` then every command, each output split by a marker. */
async function r2(file, cmds) {
  const script = ['e scr.color=0', 'e scr.interactive=false', 'e bin.relocs.apply=true', 'aa', ...cmds.flatMap((c) => [c, `?e ${MARK}`])].join('\n');
  const tmp = join(here, '.r2-script.tmp');
  writeFileSync(tmp, script + '\n');
  const { stdout } = await run('r2', ['-q', '-i', tmp, file], { maxBuffer: 256 << 20, timeout: 600000 });
  const parts = stdout.split(MARK + '\n');
  return parts.slice(0, cmds.length).map((s) => s.trim());
}
const J = (s) => { try { return JSON.parse(s); } catch { return null; } };

async function luaReference() {
  const file = join(dir, 'lua-x64.elf');
  const fns = ['luaL_checkinteger', 'luaB_select', 'lua_pushstring', 'luaH_getint', 'str_format', 'luaL_traceback', 'math_random', 'db_getinfo'];
  const head = await r2(file, ['isj', 'aflj', ...fns.flatMap((f) => [`afij @ sym.${f}`, `axtj @ sym.${f}`, `pdfj @ sym.${f}`, `afbj @ sym.${f}`])]);
  const syms = J(head[0]).filter((s) => (s.type === 'FUNC' || s.type === 'OBJECT') && s.vaddr && !s.is_imported).map((s) => ({ name: s.realname ?? s.name, addr: s.vaddr, size: s.size, type: s.type, bind: s.bind }));
  const afl = J(head[1]).map((f) => f.addr).sort((a, b) => a - b);
  const functions = {};
  const opQueries = [];
  for (let k = 0; k < fns.length; k++) {
    const [afi, axt, pdf, afb] = head.slice(2 + k * 4, 6 + k * 4).map(J);
    const i = afi[0];
    const ops = pdf.ops ?? [];
    const insns = ops.map((o) => ({ addr: o.addr, size: o.size, text: o.disasm, opcode: o.opcode, type: o.type, jump: o.jump }));
    // operand queries: first 8 instructions plus every instruction with a memory operand (cap 24)
    const picks = [...insns.slice(0, 8), ...insns.filter((x) => x.opcode.includes('['))].slice(0, 24);
    for (const p of picks) opQueries.push(p.addr);
    functions[fns[k]] = {
      addr: i.addr, size: i.size, nbbs: i.nbbs, ninstrs: i.ninstrs, indegree: i.indegree, outdegree: i.outdegree,
      callers: (axt ?? []).map((x) => ({ from: x.from, type: x.type, fcn: x.realname ?? x.fcn_name })),
      blocks: (afb ?? []).map((b) => ({ addr: b.addr, size: b.size, jump: b.jump, fail: b.fail })),
      calls: insns.filter((x) => x.type === 'call' && x.jump).map((x) => ({ at: x.addr, target: x.jump })),
      insns: insns.map((x) => ({ addr: x.addr, size: x.size, opcode: x.opcode })),
      interior: insns.length > 2 ? insns[2].addr + 1 : i.addr,
    };
  }
  const tail = await r2(file, [...opQueries.map((a) => `aoj 1 @ ${a}`), ...Object.values(functions).map((f) => `fdj @ ${f.interior}`)]);
  const operands = {};
  opQueries.forEach((a, k) => { const o = J(tail[k])?.[0]; if (o) operands[a] = { mnemonic: o.mnemonic, opcode: o.opcode, size: o.size, operands: o.opex?.operands ?? [] }; });
  Object.values(functions).forEach((f, k) => { f.fd = J(tail[opQueries.length + k]); });
  return { file: 'lua-x64.elf', symbols: syms, functionStarts: afl, functions, operands };
}

async function switchReference() {
  const file = join(dir, 'switch-x64.elf');
  const out = await r2(file, ['aflj']);
  const fns = J(out[0]).filter((f) => !f.name.startsWith('sym.imp.')).map((f) => ({ name: f.name.replace(/^sym\./, ''), addr: f.addr }));
  const wanted = fns.filter((f) => /^(dispatch|classify|opcode_name|handler)/.test(f.name)).slice(0, 6);
  const blocks = await r2(file, wanted.map((f) => `afbj @ ${f.addr}`));
  const switches = {};
  wanted.forEach((f, k) => {
    const sw = (J(blocks[k]) ?? []).filter((b) => b.switch_op).map((b) => ({ block: b.addr, cases: b.switch_op.cases.map((c) => ({ value: c.value, jump: c.jump })), defval: b.switch_op.defval }));
    if (sw.length) switches[f.name] = { addr: f.addr, switches: sw };
  });
  return { file: 'switch-x64.elf', switches };
}

const { stdout: ver } = await run('r2', ['-v']);
const ref = { generator: 'packages/disasm/scripts/make-nav-reference.mjs', tool: ver.split('\n')[0], lua: await luaReference(), switch: await switchReference() };
writeFileSync(join(dir, 'nav-reference.json'), JSON.stringify(ref) + '\n');
console.log('wrote nav-reference.json', Object.keys(ref.lua.functions).length, 'functions', Object.keys(ref.lua.operands).length, 'operand rows', Object.keys(ref.switch.switches).length, 'switch functions');
