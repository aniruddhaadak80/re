// Parsers for GNU objdump and llvm-objdump text output (-d, -h, -t).
import { lines, PARSE_LIMITS } from './common.js';

export interface ObjdumpInstruction {
  address: string;
  bytes?: string;
  text: string;
}

export interface ObjdumpFunction {
  name: string;
  address: string;
  section?: string;
  instructions: ObjdumpInstruction[];
}

export interface ObjdumpSection {
  index: number;
  name: string;
  size: number;
  vma: string;
  lma?: string;
  fileOffset: string;
  align: number;
  flags: string[];
}

export interface ObjdumpSymbol {
  address: string;
  flags: string;
  section: string;
  size: number;
  name: string;
  /** symbol version, for example GLIBC_2.17 */
  version?: string;
}

const RE_FUNC = /^([0-9a-fA-F]{1,16}) <([^>\n]{1,4096})>:\s*$/;
const RE_SECTION_HDR = /^Disassembly of section (\S{1,256}):\s*$/;
const RE_INS = /^\s{0,16}([0-9a-fA-F]{1,16}):\s(.*)$/;
function isHexBytes(s: string): boolean {
  if (!s || s.length > 200) return false;
  const toks = s.split(/\s+/).filter(Boolean);
  return toks.length > 0 && toks.length <= 32 && toks.every((t) => /^[0-9a-fA-F]{2,8}$/.test(t));
}

function normAddr(h: string): string {
  const v = h.replace(/^0+(?=.)/, '').toLowerCase();
  return '0x' + v;
}

/** Parse `objdump -d` output into functions with instructions. */
export function parseObjdumpDisasm(text: string): { format?: string; functions: ObjdumpFunction[] } {
  const out: ObjdumpFunction[] = [];
  let format: string | undefined;
  let section: string | undefined;
  let cur: ObjdumpFunction | undefined;
  let count = 0;
  for (const raw of lines(text)) {
    const line = raw.trimEnd();
    if (!format) {
      const fm = /file format (\S{1,64})$/.exec(line);
      if (fm) { format = fm[1]; continue; }
    }
    const sh = RE_SECTION_HDR.exec(line);
    if (sh) { section = sh[1]; cur = undefined; continue; }
    const fh = RE_FUNC.exec(line);
    if (fh) {
      cur = { name: fh[2]!, address: normAddr(fh[1]!), instructions: [] };
      if (section) cur.section = section;
      out.push(cur);
      continue;
    }
    if (!cur) continue;
    const im = RE_INS.exec(line);
    if (!im) continue;
    if (++count > PARSE_LIMITS.maxItems) break;
    const rest = im[2]!;
    const parts = rest.split('\t').map((p) => p.trim());
    let bytes: string | undefined;
    let textPart: string;
    if (parts.length > 1 && isHexBytes(parts[0]!)) {
      bytes = parts[0]!.replace(/\s+/g, '').toLowerCase();
      textPart = parts.slice(1).filter(Boolean).join(' ');
    } else {
      textPart = parts.filter(Boolean).join(' ');
    }
    // Continuation lines of long byte sequences have bytes and no text.
    if (!textPart && bytes) {
      const last = cur.instructions[cur.instructions.length - 1];
      if (last && last.bytes) last.bytes += bytes;
      continue;
    }
    const ins: ObjdumpInstruction = { address: normAddr(im[1]!), text: textPart.replace(/\s+/g, ' ') };
    if (bytes) ins.bytes = bytes;
    cur.instructions.push(ins);
  }
  return { ...(format ? { format } : {}), functions: out };
}

/** Parse `objdump -h` section headers. */
export function parseObjdumpSections(text: string): ObjdumpSection[] {
  const out: ObjdumpSection[] = [];
  const ls = lines(text);
  const re = /^\s*(\d{1,6})\s+(\S{1,256})\s+([0-9a-fA-F]{1,16})\s+([0-9a-fA-F]{1,16})\s+([0-9a-fA-F]{1,16})\s+([0-9a-fA-F]{1,16})\s+2\*\*(\d{1,2})\s*$/;
  // llvm-objdump: Idx Name Size VMA Type
  const reLlvm = /^\s*(\d{1,6})\s+(\S{1,256})\s+([0-9a-fA-F]{1,16})\s+([0-9a-fA-F]{1,16})(?:\s+(\S.*))?$/;
  let llvmStyle = false;
  for (let i = 0; i < ls.length && out.length < PARSE_LIMITS.maxItems; i++) {
    const l = ls[i]!;
    if (/^Idx\s+Name\s+Size\s+VMA\s+Type/.test(l.trim())) { llvmStyle = true; continue; }
    const m = re.exec(l);
    if (m) {
      const next = ls[i + 1] ?? '';
      const flags = /^\s+[A-Z_, ]+$/.test(next) ? next.trim().split(/,\s*/).filter(Boolean) : [];
      out.push({ index: Number(m[1]), name: m[2]!, size: parseInt(m[3]!, 16), vma: normAddr(m[4]!), lma: normAddr(m[5]!),
        fileOffset: normAddr(m[6]!), align: 2 ** Number(m[7]), flags });
      continue;
    }
    if (llvmStyle) {
      const n = reLlvm.exec(l);
      if (n) out.push({ index: Number(n[1]), name: n[2]!, size: parseInt(n[3]!, 16), vma: normAddr(n[4]!), fileOffset: '0x0', align: 0,
        flags: (n[5] ?? '').trim().split(/\s+/).filter(Boolean) });
    }
  }
  return out;
}

/** Parse `objdump -t` symbol table lines. */
export function parseObjdumpSymbols(text: string): ObjdumpSymbol[] {
  const out: ObjdumpSymbol[] = [];
  const re = /^([0-9a-fA-F]{8,16}) (.{7}) (\S{1,256})\s+([0-9a-fA-F]{1,16})\s+(.{0,4096})$/;
  for (const l of lines(text)) {
    if (out.length >= PARSE_LIMITS.maxItems) break;
    const m = re.exec(l.trimEnd());
    if (!m) continue;
    // GNU puts optional version info before the name, for example "GLIBC_2.17" or "(GLIBC_2.17)".
    const tail = m[5]!.trim().split(/\s+/);
    let name = tail[tail.length - 1] ?? '';
    let version: string | undefined;
    const at = name.indexOf('@', 1);
    if (at > 0) { version = name.slice(at).replace(/^@+/, ''); name = name.slice(0, at); }
    const sym: ObjdumpSymbol = { address: normAddr(m[1]!), flags: m[2]!, section: m[3]!, size: parseInt(m[4]!, 16), name };
    if (version) sym.version = version;
    out.push(sym);
  }
  return out;
}
