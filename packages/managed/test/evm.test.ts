// EVM bytecode from OpenZeppelin contracts compiled with solc-js 0.8.26, checked against solc's own outputs.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { sample, json } from './helpers.js';
import { analyzeEvm, disassembleEvm, solcStyleOpcodes, evmBytes, KNOWN_SELECTORS } from '../src/index.js';

const ref = json(sample('evm', 'evm.ref.json'));
const code = (n: string) => evmBytes(readFileSync(sample('evm', `${n}.runtime.hex`), 'utf8'));

test('evm: disassembly equals solc evm.deployedBytecode.opcodes', () => {
  for (const n of ['RevToken', 'RevProxy']) assert.equal(solcStyleOpcodes(disassembleEvm(code(n)).instructions), ref.contracts[n].opcodes.trim(), n);
});

test('evm: ERC-20 selectors equal solc methodIdentifiers and carry known names', () => {
  const s = analyzeEvm(code('RevToken'));
  const ids = ref.contracts.RevToken.methodIdentifiers as Record<string, string>;
  assert.deepEqual(s.selectors.map((x) => x.selector).sort(), Object.values(ids).sort());
  for (const [sig, sel] of Object.entries(ids)) assert.equal(s.selectors.find((x) => x.selector === sel)?.signature, sig);
  for (const [sig, sel] of Object.entries(ids)) assert.equal(KNOWN_SELECTORS[sel], sig);
  assert.ok(s.selectors.every((x) => typeof x.target === 'number' && x.target > 0));
  assert.equal(s.metadata?.solc, '0.8.26');
  assert.match(s.metadata?.ipfs ?? '', /^Qm[1-9A-HJ-NP-Za-km-z]{44}$/);
  assert.deepEqual(s.events.map((e) => e.signature).sort(), ['Approval(address,address,uint256)', 'Transfer(address,address,uint256)']);
  assert.deepEqual(s.proxy, []);
  assert.equal(s.flags.delegatecall, false);
});

test('evm: ERC1967Proxy shows the EIP-1967 implementation slot and DELEGATECALL', () => {
  const s = analyzeEvm(code('RevProxy'));
  assert.deepEqual(s.proxy.map((p) => p.kind), ['eip1967.implementation', 'delegatecall']);
  assert.equal(s.selectors.length, 0);
  assert.equal(s.metadata?.solc, '0.8.26');
});

test('evm: EIP-1167 minimal proxy runtime (bytes from the EIP text)', () => {
  const impl = 'bebebebebebebebebebebebebebebebebebebebe';
  const s = analyzeEvm(`0x363d3d373d3d3d363d73${impl}5af43d82803e903d91602b57fd5bf3`);
  assert.equal(s.proxy[0]?.kind, 'eip1167-minimal-proxy');
  assert.equal(s.proxy[0]?.implementation, '0x' + impl);
});
