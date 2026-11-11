// EVM bytecode: disassembler, dispatcher selector extraction, proxy pattern and Solidity metadata detection.
import { ParseError, LIMITS, hex, hexToBytes, utf8 } from '../util.js';
import { KNOWN_SELECTORS, KNOWN_EVENTS, PROXY_SLOTS } from './known.js';

const OP: Record<number, string> = {
  0x00: 'STOP', 0x01: 'ADD', 0x02: 'MUL', 0x03: 'SUB', 0x04: 'DIV', 0x05: 'SDIV', 0x06: 'MOD', 0x07: 'SMOD', 0x08: 'ADDMOD', 0x09: 'MULMOD', 0x0a: 'EXP', 0x0b: 'SIGNEXTEND',
  0x10: 'LT', 0x11: 'GT', 0x12: 'SLT', 0x13: 'SGT', 0x14: 'EQ', 0x15: 'ISZERO', 0x16: 'AND', 0x17: 'OR', 0x18: 'XOR', 0x19: 'NOT', 0x1a: 'BYTE', 0x1b: 'SHL', 0x1c: 'SHR', 0x1d: 'SAR',
  0x20: 'KECCAK256',
  0x30: 'ADDRESS', 0x31: 'BALANCE', 0x32: 'ORIGIN', 0x33: 'CALLER', 0x34: 'CALLVALUE', 0x35: 'CALLDATALOAD', 0x36: 'CALLDATASIZE', 0x37: 'CALLDATACOPY', 0x38: 'CODESIZE', 0x39: 'CODECOPY',
  0x3a: 'GASPRICE', 0x3b: 'EXTCODESIZE', 0x3c: 'EXTCODECOPY', 0x3d: 'RETURNDATASIZE', 0x3e: 'RETURNDATACOPY', 0x3f: 'EXTCODEHASH',
  0x40: 'BLOCKHASH', 0x41: 'COINBASE', 0x42: 'TIMESTAMP', 0x43: 'NUMBER', 0x44: 'PREVRANDAO', 0x45: 'GASLIMIT', 0x46: 'CHAINID', 0x47: 'SELFBALANCE', 0x48: 'BASEFEE', 0x49: 'BLOBHASH', 0x4a: 'BLOBBASEFEE',
  0x50: 'POP', 0x51: 'MLOAD', 0x52: 'MSTORE', 0x53: 'MSTORE8', 0x54: 'SLOAD', 0x55: 'SSTORE', 0x56: 'JUMP', 0x57: 'JUMPI', 0x58: 'PC', 0x59: 'MSIZE', 0x5a: 'GAS', 0x5b: 'JUMPDEST',
  0x5c: 'TLOAD', 0x5d: 'TSTORE', 0x5e: 'MCOPY', 0x5f: 'PUSH0',
  0xf0: 'CREATE', 0xf1: 'CALL', 0xf2: 'CALLCODE', 0xf3: 'RETURN', 0xf4: 'DELEGATECALL', 0xf5: 'CREATE2', 0xfa: 'STATICCALL', 0xfd: 'REVERT', 0xfe: 'INVALID', 0xff: 'SELFDESTRUCT',
};
for (let i = 1; i <= 32; i++) OP[0x5f + i] = `PUSH${i}`;
for (let i = 1; i <= 16; i++) { OP[0x7f + i] = `DUP${i}`; OP[0x8f + i] = `SWAP${i}`; }
for (let i = 0; i <= 4; i++) OP[0xa0 + i] = `LOG${i}`;
export const EVM_OPCODES = OP;

export interface EvmInstruction { pc: number; opcode: number; op: string; push?: string; size: number; /** false for bytes that are not an opcode (often metadata or data) */ defined?: false }

/** Accept raw bytes, or text holding hex (with or without 0x), as found in .bin / .hex files and explorers. */
export function evmBytes(input: Uint8Array | string): Uint8Array {
  if (typeof input === 'string') return hexToBytes(input);
  // A file of ASCII hex is common; detect it.
  let ascii = input.length > 0;
  const n = Math.min(input.length, 4096);
  for (let i = 0; i < n; i++) { const c = input[i] as number; if (!((c >= 48 && c <= 57) || (c >= 97 && c <= 102) || (c >= 65 && c <= 70) || c === 120 || c === 10 || c === 13 || c === 32 || c === 9)) { ascii = false; break; } }
  return ascii ? hexToBytes(utf8(input)) : input;
}

export function disassembleEvm(code: Uint8Array, max = LIMITS.maxInstructions * 5): { instructions: EvmInstruction[]; truncated: boolean } {
  const out: EvmInstruction[] = [];
  let pc = 0;
  while (pc < code.length) {
    if (out.length >= max) return { instructions: out, truncated: true };
    const opcode = code[pc] as number;
    const op = OP[opcode] ?? 'INVALID';
    if (opcode >= 0x60 && opcode <= 0x7f) {
      const n = opcode - 0x5f;
      const data = code.subarray(pc + 1, Math.min(code.length, pc + 1 + n));
      out.push({ pc, opcode, op, push: hex(data), size: 1 + n });
      pc += 1 + n;
    } else { out.push(OP[opcode] ? { pc, opcode, op, size: 1 } : { pc, opcode, op, size: 1, defined: false }); pc++; }
  }
  return { instructions: out, truncated: false };
}

/** Text listing in the same style solc prints for evm.bytecode.opcodes. */
export function solcStyleOpcodes(ins: EvmInstruction[]): string {
  return ins.map((i) => (i.defined === false ? '0x' + i.opcode.toString(16).toUpperCase().padStart(2, '0') : i.push !== undefined ? `${i.op} 0x${i.push.length ? i.push.replace(/^0+(?=.)/, '').toUpperCase() : ''}` : i.op)).join(' ');
}

export interface SolcMetadata { offset: number; length: number; solc?: string; ipfs?: string; bzzr0?: string; bzzr1?: string; experimental?: boolean; raw: Record<string, unknown> }

/** Decode the CBOR metadata Solidity (and Vyper style) compilers append to runtime code. */
export function solidityMetadata(code: Uint8Array): SolcMetadata | undefined {
  if (code.length < 4) return undefined;
  const len = ((code[code.length - 2] as number) << 8) | (code[code.length - 1] as number);
  const start = code.length - 2 - len;
  if (len < 4 || start < 0) return undefined;
  const cbor = code.subarray(start, code.length - 2);
  let pos = 0;
  const byte = () => { if (pos >= cbor.length) throw new ParseError('cbor past end'); return cbor[pos++] as number; };
  const arg = (info: number): number => {
    if (info < 24) return info;
    if (info === 24) return byte();
    if (info === 25) return (byte() << 8) | byte();
    if (info === 26) return ((byte() << 24) | (byte() << 16) | (byte() << 8) | byte()) >>> 0;
    throw new ParseError('unsupported cbor length');
  };
  const item = (depth: number): unknown => {
    if (depth > 8) throw new ParseError('cbor too deep');
    const ib = byte(); const major = ib >> 5; const info = ib & 31;
    if (major === 0) return arg(info);
    if (major === 2) { const n = arg(info); if (pos + n > cbor.length) throw new ParseError('cbor bytes past end'); const b = cbor.subarray(pos, pos + n); pos += n; return b; }
    if (major === 3) { const n = arg(info); if (pos + n > cbor.length) throw new ParseError('cbor text past end'); const s = utf8(cbor.subarray(pos, pos + n)); pos += n; return s; }
    if (major === 5) { const n = arg(info); const m: Record<string, unknown> = {}; for (let i = 0; i < n && i < 32; i++) { const k = item(depth + 1); m[String(k)] = item(depth + 1); } return m; }
    if (major === 7) return info === 20 ? false : info === 21 ? true : null;
    throw new ParseError('unsupported cbor item');
  };
  try {
    const m = item(0);
    if (!m || typeof m !== 'object' || m instanceof Uint8Array || pos !== cbor.length) return undefined;
    const raw = m as Record<string, unknown>;
    const res: SolcMetadata = { offset: start, length: len + 2, raw: {} };
    for (const [k, v] of Object.entries(raw)) res.raw[k] = v instanceof Uint8Array ? hex(v) : v;
    const s = raw.solc;
    if (s instanceof Uint8Array && s.length === 3) res.solc = `${s[0]}.${s[1]}.${s[2]}`;
    else if (typeof s === 'string') res.solc = s;
    if (raw.ipfs instanceof Uint8Array) res.ipfs = base58(raw.ipfs);
    if (raw.bzzr0 instanceof Uint8Array) res.bzzr0 = hex(raw.bzzr0);
    if (raw.bzzr1 instanceof Uint8Array) res.bzzr1 = hex(raw.bzzr1);
    if (typeof raw.experimental === 'boolean') res.experimental = raw.experimental;
    if (!res.solc && !res.ipfs && !res.bzzr0 && !res.bzzr1 && !('vyper' in raw)) return undefined;
    return res;
  } catch { return undefined; }
}

function base58(b: Uint8Array): string {
  const A = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  let n = 0n;
  for (const x of b) n = (n << 8n) | BigInt(x);
  let s = '';
  while (n > 0n) { s = A[Number(n % 58n)] + s; n /= 58n; }
  for (const x of b) { if (x === 0) s = '1' + s; else break; }
  return s;
}

export interface SelectorHit { selector: string; signature?: string; pc: number; target?: number }

/**
 * Find 4 byte function selectors from the Solidity / Vyper dispatcher: PUSH4 compared with EQ
 * (directly or through a DUP), usually followed by PUSHn dest JUMPI.
 */
export function extractSelectors(ins: EvmInstruction[]): SelectorHit[] {
  const seen = new Map<string, SelectorHit>();
  for (let i = 0; i < ins.length; i++) {
    const a = ins[i] as EvmInstruction;
    if (a.op !== 'PUSH4' || a.push === undefined || a.push.length !== 8) continue;
    let j = i + 1;
    if (ins[j]?.op.startsWith('DUP')) j++;
    if (ins[j]?.op !== 'EQ') continue;
    const p = ins[j + 1], jumpi = ins[j + 2];
    const target = p?.push !== undefined && jumpi?.op === 'JUMPI' ? parseInt(p.push || '0', 16) : undefined;
    if (!seen.has(a.push)) seen.set(a.push, { selector: a.push, signature: KNOWN_SELECTORS[a.push], pc: a.pc, target });
  }
  return [...seen.values()];
}

export interface ProxyHit { kind: string; evidence: string; pc?: number; implementation?: string }

export function detectProxy(code: Uint8Array, ins: EvmInstruction[]): ProxyHit[] {
  const hits: ProxyHit[] = [];
  const h = hex(code);
  // EIP-1167 minimal proxy
  const m = /^363d3d373d3d3d363d73([0-9a-f]{40})5af43d82803e903d91602b57fd5bf3/.exec(h);
  if (m) hits.push({ kind: 'eip1167-minimal-proxy', evidence: 'EIP-1167 clone runtime', pc: 0, implementation: '0x' + m[1] });
  for (const i of ins) {
    if (i.op === 'PUSH32' && i.push && PROXY_SLOTS[i.push]) hits.push({ kind: PROXY_SLOTS[i.push] as string, evidence: `PUSH32 slot 0x${i.push}`, pc: i.pc });
  }
  const dc = ins.filter((i) => i.op === 'DELEGATECALL');
  if (dc.length) hits.push({ kind: 'delegatecall', evidence: `${dc.length} DELEGATECALL instruction(s)`, pc: dc[0]?.pc });
  return hits;
}

export interface EvmSummary {
  size: number;
  instructionCount: number;
  codeSize: number;
  selectors: SelectorHit[];
  proxy: ProxyHit[];
  metadata?: SolcMetadata;
  events: { topic: string; signature: string; pc: number }[];
  opcodeStats: Record<string, number>;
  flags: { selfdestruct: boolean; delegatecall: boolean; create2: boolean; callcode: boolean; tstore: boolean };
}

export function analyzeEvm(input: Uint8Array | string): EvmSummary & { instructions: EvmInstruction[] } {
  const code = evmBytes(input);
  if (code.length === 0) throw new ParseError('empty EVM bytecode');
  const meta = solidityMetadata(code);
  const body = meta ? code.subarray(0, meta.offset) : code;
  const { instructions } = disassembleEvm(body);
  const stats: Record<string, number> = {};
  const events: EvmSummary['events'] = [];
  for (const i of instructions) {
    stats[i.op] = (stats[i.op] ?? 0) + 1;
    if (i.op === 'PUSH32' && i.push && KNOWN_EVENTS[i.push]) events.push({ topic: i.push, signature: KNOWN_EVENTS[i.push] as string, pc: i.pc });
  }
  return {
    size: code.length, codeSize: body.length, instructionCount: instructions.length,
    selectors: extractSelectors(instructions), proxy: detectProxy(body, instructions), metadata: meta, events, opcodeStats: stats,
    flags: { selfdestruct: !!stats.SELFDESTRUCT, delegatecall: !!stats.DELEGATECALL, create2: !!stats.CREATE2, callcode: !!stats.CALLCODE, tstore: !!stats.TSTORE },
    instructions,
  };
}

export { KNOWN_SELECTORS, KNOWN_EVENTS, PROXY_SLOTS };
