// Decoder level checks against capstone 5 output (recorded from the Python binding).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadDecoders, Program } from '../src/node.ts';

const hexb = (h: string) => new Uint8Array(h.match(/../g)!.map((x) => parseInt(x, 16)));

test('iced-x86 x86-64: text, flow, rip relative and branch targets', async () => {
  const d = (await loadDecoders()).get('x86_64')!;
  assert.equal(d.name, 'iced-x86');
  const ins = d.decode('x86_64', hexb('554889e5488d3d10000000e8f6ffffff4883ec20c3ff2512000000f30f1efa0f1f440000'), 0x1000, 100);
  // capstone: push rbp / mov rbp, rsp / lea rdi, [rip + 0x10] / call 0x1006 / sub rsp, 0x20 / ret / jmp qword ptr [rip + 0x12] / endbr64 / nop dword ptr [rax + rax]
  assert.deepEqual(ins.map((i) => i.mnemonic), ['push', 'mov', 'lea', 'call', 'sub', 'ret', 'jmp', 'endbr64', 'nop']);
  assert.deepEqual(ins.map((i) => i.address), [4096, 4097, 4100, 4107, 4112, 4116, 4117, 4123, 4127]);
  assert.equal(ins[2]!.memAddr, 0x100b + 0x10);
  assert.equal(ins[3]!.flow, 'call');
  assert.equal(ins[3]!.target, 0x1006);
  assert.equal(ins[5]!.flow, 'ret');
  assert.equal(ins[6]!.flow, 'ijump');
  assert.equal(ins[6]!.viaMemory, true);
  assert.equal(ins[6]!.memAddr, 0x101b + 0x12);
  assert.equal(ins[4]!.operands, 'rsp, 0x20');
});

test('iced-x86 x86-32: absolute memory and call target', async () => {
  const d = (await loadDecoders()).get('x86')!;
  const ins = d.decode('x86', hexb('5589e583ec08e8fcffffff8b45088b048530a00408c9c3'), 0x1000, 100);
  assert.deepEqual(ins.map((i) => i.mnemonic), ['push', 'mov', 'sub', 'call', 'mov', 'mov', 'leave', 'ret']);
  assert.equal(ins[3]!.target, 0x1007);
  assert.equal(ins[5]!.operands.includes('0x804a030'), true);
});

test('capstone AArch64: exact text and flow', async () => {
  const d = (await loadDecoders()).get('arm64')!;
  const ins = d.decode('arm64', hexb('fd7bbfa9fd030091000000900000009400000054e0031f2ac0035fd61f2003d5'), 0x1000, 100);
  assert.deepEqual(ins.map((i) => `${i.mnemonic} ${i.operands}`.trim()), ['stp x29, x30, [sp, #-0x10]!', 'mov x29, sp', 'adrp x0, #0x1000', 'bl #0x100c', 'b.eq #0x1010', 'mov w0, wzr', 'ret', 'nop']);
  assert.deepEqual(ins.map((i) => i.flow), ['seq', 'seq', 'seq', 'call', 'cjump', 'seq', 'ret', 'seq']);
  assert.equal(ins[3]!.target, 0x100c);
  assert.equal(ins[4]!.target, 0x1010);
});

test('capstone ARM and Thumb: text, returns and pc relative literal', async () => {
  const d = (await loadDecoders()).get('arm')!;
  const a = d.decode('arm', hexb('00482de904b08de2000090e5feffffeb0088bde8'), 0x1000, 100, false);
  assert.deepEqual(a.map((i) => `${i.mnemonic} ${i.operands}`.trim()), ['push {fp, lr}', 'add fp, sp, #4', 'ldr r0, [r0]', 'bl #0x100c', 'pop {fp, pc}']);
  assert.equal(a[4]!.flow, 'ret');
  const t = d.decode('arm', hexb('80b500af00f002f8034800f0fef880bd7047'), 0x1000, 100, true);
  assert.deepEqual(t.map((i) => `${i.mnemonic} ${i.operands}`.trim()), ['push {r7, lr}', 'add r7, sp, #0', 'bl #0x100c', 'ldr r0, [pc, #0xc]', 'bl #0x120a', 'pop {r7, pc}', 'bx lr']);
  assert.equal(t[3]!.memAddr, ((0x1008 + 4) & ~3) + 0xc);
  assert.equal(t[5]!.flow, 'ret');
  assert.equal(t[6]!.flow, 'ret');
});

test('capstone x86 fallback (browser path) agrees with iced-x86 on a real function', async () => {
  const dir = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..', 'samples', 'disasm');
  const bytes = new Uint8Array(readFileSync(join(dir, 'hello-x64.elf')));
  const a = await Program.open(bytes);
  const b = await Program.open(bytes, { preferCapstoneX86: true });
  assert.equal(b.decoder!.name, 'capstone');
  const fa = a.analyze([...a.discover().values()].find((f) => f.name === 'check_password')!.addr)!;
  const fb = b.analyze([...b.discover().values()].find((f) => f.name === 'check_password')!.addr)!;
  assert.deepEqual(fb.blocks.flatMap((x) => x.insns.map((i) => i.address)), fa.blocks.flatMap((x) => x.insns.map((i) => i.address)));
  assert.deepEqual(fb.calls.map((c) => c.name), fa.calls.map((c) => c.name));
  assert.deepEqual(fb.dataRefs.filter((d) => d.kind === 'string').map((d) => d.value), fa.dataRefs.filter((d) => d.kind === 'string').map((d) => d.value));
});
