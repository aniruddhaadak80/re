// RevLens names JSON: one portable file of function names, signatures, comments, labels and C
// types that RevLens can write into Ghidra, IDA and radare2 projects, and export back out of them.
// Pure, browser safe.
//
// {
//   "schema": "revlens/names@1",
//   "imageBase": "0x0",            // base the addresses were recorded against (optional)
//   "addressing": "va",            // "va" (default) or "rva" (offsets from the image base)
//   "functions": [{ "address": "0x848", "name": "verify_secret", "signature": "int verify_secret(const char *input)", "comment": "..." }],
//   "comments":  [{ "address": "0x868", "text": "length check", "kind": "eol" }],
//   "labels":    [{ "address": "0x2010", "name": "g_secret" }],
//   "types":     [{ "name": "rl_pair", "c": "struct rl_pair { int a; char *b; };" }]
// }
//
// Each tool maps an address with: toolAddress = address - imageBase + toolImageBase. Without
// imageBase, "va" addresses are taken as the file's own declared base (lowest ELF PT_LOAD, PE
// ImageBase, Mach-O __TEXT), so files exported by Ghidra (which moves a PIE to 0x100000) and
// radare2 (which keeps 0) can be exchanged.

export type CommentKind = 'eol' | 'pre' | 'plate' | 'post' | 'repeatable';

export interface NamedFunction { address: string; name?: string; signature?: string; comment?: string }
export interface NamedComment { address: string; text: string; kind?: CommentKind }
export interface NamedLabel { address: string; name: string }
export interface NamedType { name?: string; c: string }

export interface RevLensNames {
  schema: 'revlens/names@1';
  imageBase?: string;
  addressing?: 'va' | 'rva';
  binary?: { sha256?: string; name?: string };
  /** which tool wrote this file, when exported */
  source?: string;
  functions: NamedFunction[];
  comments: NamedComment[];
  labels: NamedLabel[];
  types: NamedType[];
}

export const NAMES_SCHEMA = 'revlens/names@1';

export const NAMES_LIMITS = {
  maxFunctions: 200_000,
  maxComments: 200_000,
  maxLabels: 200_000,
  maxTypes: 5_000,
  maxCommentChars: 4096,
  maxTypeChars: 64 * 1024,
  maxTotalTypeChars: 2 * 1024 * 1024,
  maxSignatureChars: 2048,
} as const;

/** Symbol names: C, C++ (::, <>, ~) and the usual tool prefixes (sub_, FUN_, sym.). */
export const NAME_RE = /^[A-Za-z_.$?@][\w.$?@:<>~-]{0,511}$/;
const ADDR_RE = /^0x[0-9a-fA-F]{1,16}$/;
const COMMENT_KINDS = new Set<CommentKind>(['eol', 'pre', 'plate', 'post', 'repeatable']);

export class NamesError extends Error {
  constructor(readonly problems: string[]) {
    super(`names JSON is not valid: ${problems.slice(0, 10).join('; ')}${problems.length > 10 ? ` (and ${problems.length - 10} more)` : ''}`);
  }
}

function addr(v: unknown, where: string, problems: string[]): string | undefined {
  if (typeof v === 'number' && Number.isSafeInteger(v) && v >= 0) return '0x' + v.toString(16);
  if (typeof v === 'string' && ADDR_RE.test(v)) return '0x' + v.slice(2).toLowerCase().replace(/^0+(?=.)/, '');
  problems.push(`${where}: address must be 0x hex`);
  return undefined;
}

function text(v: unknown, max: number, where: string, problems: string[], allowNewline: boolean): string | undefined {
  if (typeof v !== 'string' || v.length === 0 || v.length > max || v.includes('\0') || (!allowNewline && /[\r\n]/.test(v))) {
    problems.push(`${where}: must be 1 to ${max} characters${allowNewline ? '' : ' on one line'}`);
    return undefined;
  }
  return v;
}

/** Check and normalise a names object (or its JSON text). Throws NamesError listing every problem. */
export function validateNames(input: unknown): RevLensNames {
  let v = input;
  if (typeof v === 'string') {
    if (v.length > 256 * 1024 * 1024) throw new NamesError(['names JSON is larger than 256 MiB']);
    try { v = JSON.parse(v); } catch (e) { throw new NamesError([`not JSON: ${(e as Error).message}`]); }
  }
  if (!v || typeof v !== 'object' || Array.isArray(v)) throw new NamesError(['names must be an object']);
  const o = v as Record<string, unknown>;
  const problems: string[] = [];
  if (o.schema !== undefined && o.schema !== NAMES_SCHEMA) problems.push(`schema must be ${NAMES_SCHEMA}`);
  const out: RevLensNames = { schema: NAMES_SCHEMA, functions: [], comments: [], labels: [], types: [] };
  if (o.imageBase !== undefined) { const b = addr(o.imageBase, 'imageBase', problems); if (b) out.imageBase = b; }
  if (o.addressing !== undefined) {
    if (o.addressing === 'va' || o.addressing === 'rva') out.addressing = o.addressing;
    else problems.push('addressing must be va or rva');
  }
  if (o.binary && typeof o.binary === 'object') {
    const b = o.binary as Record<string, unknown>;
    out.binary = {};
    if (typeof b.sha256 === 'string' && /^[0-9a-fA-F]{64}$/.test(b.sha256)) out.binary.sha256 = b.sha256.toLowerCase();
    if (typeof b.name === 'string') out.binary.name = b.name.slice(0, 512);
  }
  if (typeof o.source === 'string') out.source = o.source.slice(0, 64);
  const list = (k: string, max: number): unknown[] => {
    const a = o[k];
    if (a === undefined) return [];
    if (!Array.isArray(a)) { problems.push(`${k} must be an array`); return []; }
    if (a.length > max) { problems.push(`${k} has more than ${max} entries`); return []; }
    return a;
  };
  list('functions', NAMES_LIMITS.maxFunctions).forEach((f, i) => {
    const w = `functions[${i}]`;
    if (!f || typeof f !== 'object') { problems.push(`${w}: must be an object`); return; }
    const r = f as Record<string, unknown>;
    const a = addr(r.address, w, problems);
    const e: NamedFunction = { address: a ?? '0x0' };
    if (r.name !== undefined) { if (typeof r.name === 'string' && NAME_RE.test(r.name)) e.name = r.name; else problems.push(`${w}: name must match ${NAME_RE.source}`); }
    if (r.signature !== undefined) {
      const s = text(r.signature, NAMES_LIMITS.maxSignatureChars, `${w}.signature`, problems, false);
      if (s && !/^[\w\s*&,().:<>[\]~$-]+;?$/.test(s)) problems.push(`${w}.signature: only C declaration characters are allowed`);
      else if (s) e.signature = s.replace(/;\s*$/, '');
    }
    if (r.comment !== undefined) { const c = text(r.comment, NAMES_LIMITS.maxCommentChars, `${w}.comment`, problems, true); if (c) e.comment = c; }
    if (!e.name && !e.signature && !e.comment) problems.push(`${w}: give at least one of name, signature, comment`);
    if (a) out.functions.push(e);
  });
  list('comments', NAMES_LIMITS.maxComments).forEach((c, i) => {
    const w = `comments[${i}]`;
    if (!c || typeof c !== 'object') { problems.push(`${w}: must be an object`); return; }
    const r = c as Record<string, unknown>;
    const a = addr(r.address, w, problems);
    const t = text(r.text, NAMES_LIMITS.maxCommentChars, `${w}.text`, problems, true);
    let kind: CommentKind = 'eol';
    if (r.kind !== undefined) { if (COMMENT_KINDS.has(r.kind as CommentKind)) kind = r.kind as CommentKind; else problems.push(`${w}.kind must be eol, pre, plate, post or repeatable`); }
    if (a && t) out.comments.push({ address: a, text: t, kind });
  });
  list('labels', NAMES_LIMITS.maxLabels).forEach((l, i) => {
    const w = `labels[${i}]`;
    if (!l || typeof l !== 'object') { problems.push(`${w}: must be an object`); return; }
    const r = l as Record<string, unknown>;
    const a = addr(r.address, w, problems);
    if (typeof r.name !== 'string' || !NAME_RE.test(r.name)) { problems.push(`${w}: name must match ${NAME_RE.source}`); return; }
    if (a) out.labels.push({ address: a, name: r.name });
  });
  let total = 0;
  list('types', NAMES_LIMITS.maxTypes).forEach((t, i) => {
    const w = `types[${i}]`;
    if (!t || typeof t !== 'object') { problems.push(`${w}: must be an object`); return; }
    const r = t as Record<string, unknown>;
    const c = text(r.c, NAMES_LIMITS.maxTypeChars, `${w}.c`, problems, true);
    if (c && /["`!\\#]/.test(c)) { problems.push(`${w}.c: quotes, backticks, !, backslashes and preprocessor lines are not allowed`); return; }
    if (c) { total += c.length; out.types.push({ ...(typeof r.name === 'string' && NAME_RE.test(r.name) ? { name: r.name } : {}), c }); }
  });
  if (total > NAMES_LIMITS.maxTotalTypeChars) problems.push('types are larger than 2 MiB in total');
  if (problems.length) throw new NamesError(problems);
  return out;
}

/** Image base the file itself declares: lowest ELF PT_LOAD vaddr, PE ImageBase, Mach-O __TEXT vmaddr. */
export function declaredImageBase(b: Uint8Array): bigint | undefined {
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const len = b.length;
  // ELF
  if (len >= 64 && b[0] === 0x7f && b[1] === 0x45 && b[2] === 0x4c && b[3] === 0x46) {
    const is64 = b[4] === 2;
    const le = b[5] === 1;
    const phoff = is64 ? Number(dv.getBigUint64(32, le)) : dv.getUint32(28, le);
    const phentsize = dv.getUint16(is64 ? 54 : 42, le);
    const phnum = Math.min(dv.getUint16(is64 ? 56 : 44, le), 4096);
    let low: bigint | undefined;
    for (let i = 0; i < phnum; i++) {
      const o = phoff + i * phentsize;
      if (o + (is64 ? 56 : 32) > len || o < 0) break;
      if (dv.getUint32(o, le) !== 1) continue; // PT_LOAD
      const vaddr = is64 ? dv.getBigUint64(o + 16, le) : BigInt(dv.getUint32(o + 8, le));
      const align = is64 ? dv.getBigUint64(o + 48, le) : BigInt(dv.getUint32(o + 28, le));
      const base = align > 1n && (align & (align - 1n)) === 0n ? vaddr & ~(align - 1n) : vaddr;
      if (low === undefined || base < low) low = base;
    }
    return low ?? 0n;
  }
  // PE
  if (len >= 0x40 && b[0] === 0x4d && b[1] === 0x5a) {
    const pe = dv.getUint32(0x3c, true);
    if (pe + 24 + 32 > len || dv.getUint32(pe, true) !== 0x4550) return undefined;
    const opt = pe + 24;
    const magic = dv.getUint16(opt, true);
    if (magic === 0x20b && opt + 32 <= len) return dv.getBigUint64(opt + 24, true);
    if (magic === 0x10b && opt + 32 <= len) return BigInt(dv.getUint32(opt + 28, true));
    return undefined;
  }
  // Mach-O 64 little endian
  if (len >= 32 && dv.getUint32(0, true) === 0xfeedfacf) {
    const ncmds = Math.min(dv.getUint32(16, true), 4096);
    let o = 32;
    for (let i = 0; i < ncmds && o + 8 <= len; i++) {
      const cmd = dv.getUint32(o, true);
      const size = dv.getUint32(o + 4, true);
      if (size < 8) break;
      if (cmd === 0x19 && o + 72 <= len) {
        const name = new TextDecoder().decode(b.subarray(o + 8, o + 24)).replace(/\0.*$/s, '');
        if (name === '__TEXT') return dv.getBigUint64(o + 24, true);
      }
      o += size;
    }
    return undefined;
  }
  return undefined;
}

/** Map an address from the names file into a tool's address space. */
export function mapAddress(address: string, names: Pick<RevLensNames, 'imageBase' | 'addressing'>, fileBase: bigint, toolBase: bigint): bigint {
  const a = BigInt(address);
  if (names.addressing === 'rva') return a + toolBase;
  const recorded = names.imageBase !== undefined ? BigInt(names.imageBase) : fileBase;
  return a - recorded + toolBase;
}
