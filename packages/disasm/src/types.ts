// Shared types for @revlens/disasm. Plain data, JSON friendly. Addresses are JS numbers
// (exact up to 2^53, which covers every real user space and kernel image layout we load).

export type Arch = 'x86' | 'x86_64' | 'arm64' | 'arm' | 'unknown';
export type BinFormat = 'elf' | 'pe' | 'macho' | 'raw';

export interface Segment {
  name: string;
  vaddr: number;
  vsize: number;
  offset: number;
  fsize: number;
  r: boolean;
  w: boolean;
  x: boolean;
}

export interface SectionInfo {
  name: string;
  vaddr: number;
  size: number;
  offset: number;
  /** bytes present in the file (0 for bss style sections) */
  fsize: number;
  exec: boolean;
  write: boolean;
}

export type SymbolSource =
  | 'symtab' | 'dynsym' | 'export' | 'coff' | 'macho' | 'gopclntab' | 'entry' | 'import' | 'pdata'
  | 'function-starts' | 'eh-frame' | 'call' | 'prologue' | 'arm-exidx';

export interface Sym {
  addr: number;
  name: string;
  size?: number;
  kind: 'func' | 'object' | 'unknown';
  source: SymbolSource;
  /** ARM only: code at this address is Thumb */
  thumb?: boolean;
  /** local (static) binding */
  local?: boolean;
}

export interface ImportRef {
  name: string;
  library?: string;
  /** pointer slot the loader fills: GOT entry, IAT entry, Mach-O got / la_symbol_ptr */
  slot?: number;
  /** stub code that jumps through the slot: PLT entry, Mach-O __stubs entry, PE jmp thunk */
  stub?: number;
}

export interface FunctionHint {
  addr: number;
  size?: number;
  source: SymbolSource;
  thumb?: boolean;
}

export interface BinaryImage {
  format: BinFormat;
  arch: Arch;
  bits: 32 | 64;
  endian: 'le' | 'be';
  entry?: number;
  entryThumb?: boolean;
  imageBase: number;
  segments: Segment[];
  sections: SectionInfo[];
  symbols: Sym[];
  imports: ImportRef[];
  hints: FunctionHint[];
  /** the bytes of this image (for fat Mach-O, the selected slice) */
  bytes: Uint8Array;
  /** offset of `bytes` inside the original file */
  fileOffset: number;
  /** other slices in a fat Mach-O */
  slices?: { arch: Arch; offset: number; size: number }[];
  /** pointer values the dynamic loader writes (ELF RELATIVE relocations), keyed by address */
  relocPtrs?: Map<number, number>;
  /** non loaded sections with debug info (ELF .debug_*), by file offset */
  debugSections?: { name: string; offset: number; size: number }[];
  /** debug sections stored compressed (SHF_COMPRESSED), not decoded */
  debugCompressed?: string[];
  /** Go build detected through a pclntab */
  goVersionHint?: string;
  warnings: string[];
}

export type Flow = 'seq' | 'call' | 'icall' | 'jump' | 'ijump' | 'cjump' | 'ret' | 'trap' | 'invalid';

export interface Insn {
  address: number;
  size: number;
  /** hex encoded instruction bytes */
  bytes: string;
  mnemonic: string;
  operands: string;
  flow: Flow;
  /** direct branch or call target */
  target?: number;
  /** resolved memory operand address (rip relative, absolute, pc literal, adrp pair) */
  memAddr?: number;
  /** true when the branch target is read through memAddr (call [slot]) */
  viaMemory?: boolean;
  /** x86: size in bytes of the memory operand, when the instruction has one */
  memSize?: number;
  /** literal immediates (non branch) */
  imms: number[];
  thumb?: boolean;
}

export interface Decoder {
  readonly name: string;
  supports(arch: Arch): boolean;
  /** decode up to maxInsns instructions from bytes placed at address; stops at the first undecodable byte (returned as an invalid insn) */
  decode(arch: Arch, bytes: Uint8Array, address: number, maxInsns: number, thumb?: boolean): Insn[];
}

export interface Edge {
  from: number;
  to: number;
  /** 'case' edges leave a block that ends in a resolved jump table */
  kind: 'fallthrough' | 'jump' | 'true' | 'false' | 'case';
}

/** A jump table (switch) or a table of code pointers reached by an indirect jump or call. */
export interface SwitchTable {
  /** address of the indirect jump or call */
  at: number;
  /** address of the table in memory */
  table: number;
  /** bytes per entry */
  entrySize: number;
  /** number of entries read */
  count: number;
  /** target per index (index 0 first), duplicates kept so case values line up */
  targets: number[];
  /** how the entry count was found: a bounds check before the jump, an and with a bit mask (an upper limit), a scan of plausible entries, or a single constant target */
  bound: 'cmp' | 'mask' | 'scan' | 'const';
  /** value subtracted from the switch variable before indexing, when the code does that */
  bias?: number;
  /** 'switch' when targets are inside the function, 'call-table' when they are function entries */
  kind: 'switch' | 'call-table';
  /** register holding the index */
  indexReg?: string;
  /** address of the bounds check (cmp) */
  boundAt?: number;
  /** the single target was read from writable data: it is the pointer's initial value, which may change at run time */
  initialValue?: boolean;
  /** same table as the dispatch at this address (repeated interpreter dispatch with the same operand) */
  sharedWith?: number;
}

export interface BasicBlock {
  start: number;
  end: number;
  insns: Insn[];
  succ: Edge[];
  pred: number[];
  /** block ends with a return, tail jump, indirect jump or trap */
  exit?: 'ret' | 'tail' | 'indirect' | 'trap' | 'invalid' | 'noreturn';
}

export interface CallSite {
  at: number;
  target?: number;
  name?: string;
  indirect: boolean;
  tail?: boolean;
  /** indirect calls: possible targets found by table reads, constant propagation or vtable scan */
  candidates?: number[];
  /** how candidates were found */
  resolvedBy?: 'table' | 'constant' | 'vtable' | 'itab' | 'initial-value';
}

export interface DataRef {
  at: number;
  addr: number;
  kind: 'string' | 'import-slot' | 'data' | 'code';
  value?: string;
}

export interface FunctionInfo {
  addr: number;
  name: string;
  size?: number;
  source: SymbolSource;
  thumb?: boolean;
  isImportStub?: boolean;
}

export interface AnalyzedFunction extends FunctionInfo {
  blocks: BasicBlock[];
  calls: CallSite[];
  dataRefs: DataRef[];
  constants: number[];
  insnCount: number;
  /** bytes covered by decoded instructions */
  codeSize: number;
  truncated: boolean;
  unresolvedIndirect: number;
  /** jump tables and code pointer tables resolved in this function */
  switches?: SwitchTable[];
}
