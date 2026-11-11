// Dalvik opcode table: name and instruction format for every opcode byte.
// Formats follow the Dalvik bytecode spec (source.android.com/docs/core/runtime/instruction-formats).

export type Fmt =
  | '10x' | '12x' | '11n' | '11x' | '10t' | '20t' | '22x' | '21t' | '21s' | '21h' | '21c'
  | '23x' | '22b' | '22t' | '22s' | '22c' | '30t' | '32x' | '31i' | '31t' | '31c'
  | '35c' | '3rc' | '45cc' | '4rcc' | '51l' | 'xx';

/** What the index operand of a 21c/22c/31c/35c/3rc instruction points at. */
export type RefKind = 'string' | 'type' | 'field' | 'method' | 'proto' | 'callsite' | 'methodhandle' | 'none';

export interface OpInfo { op: number; name: string; fmt: Fmt; ref: RefKind; units: number }

const UNITS: Record<Fmt, number> = {
  '10x': 1, '12x': 1, '11n': 1, '11x': 1, '10t': 1, '20t': 2, '22x': 2, '21t': 2, '21s': 2, '21h': 2, '21c': 2,
  '23x': 2, '22b': 2, '22t': 2, '22s': 2, '22c': 2, '30t': 3, '32x': 3, '31i': 3, '31t': 3, '31c': 3,
  '35c': 3, '3rc': 3, '45cc': 4, '4rcc': 4, '51l': 5, 'xx': 1,
};

export const OPS: OpInfo[] = new Array(256);

function def(op: number, name: string, fmt: Fmt, ref: RefKind = 'none'): void {
  OPS[op] = { op, name, fmt, ref, units: UNITS[fmt] };
}

for (let i = 0; i < 256; i++) def(i, `unused-${i.toString(16).padStart(2, '0')}`, 'xx');

def(0x00, 'nop', '10x');
def(0x01, 'move', '12x'); def(0x02, 'move/from16', '22x'); def(0x03, 'move/16', '32x');
def(0x04, 'move-wide', '12x'); def(0x05, 'move-wide/from16', '22x'); def(0x06, 'move-wide/16', '32x');
def(0x07, 'move-object', '12x'); def(0x08, 'move-object/from16', '22x'); def(0x09, 'move-object/16', '32x');
def(0x0a, 'move-result', '11x'); def(0x0b, 'move-result-wide', '11x'); def(0x0c, 'move-result-object', '11x');
def(0x0d, 'move-exception', '11x');
def(0x0e, 'return-void', '10x'); def(0x0f, 'return', '11x'); def(0x10, 'return-wide', '11x'); def(0x11, 'return-object', '11x');
def(0x12, 'const/4', '11n'); def(0x13, 'const/16', '21s'); def(0x14, 'const', '31i'); def(0x15, 'const/high16', '21h');
def(0x16, 'const-wide/16', '21s'); def(0x17, 'const-wide/32', '31i'); def(0x18, 'const-wide', '51l'); def(0x19, 'const-wide/high16', '21h');
def(0x1a, 'const-string', '21c', 'string'); def(0x1b, 'const-string/jumbo', '31c', 'string'); def(0x1c, 'const-class', '21c', 'type');
def(0x1d, 'monitor-enter', '11x'); def(0x1e, 'monitor-exit', '11x');
def(0x1f, 'check-cast', '21c', 'type'); def(0x20, 'instance-of', '22c', 'type'); def(0x21, 'array-length', '12x');
def(0x22, 'new-instance', '21c', 'type'); def(0x23, 'new-array', '22c', 'type');
def(0x24, 'filled-new-array', '35c', 'type'); def(0x25, 'filled-new-array/range', '3rc', 'type');
def(0x26, 'fill-array-data', '31t'); def(0x27, 'throw', '11x');
def(0x28, 'goto', '10t'); def(0x29, 'goto/16', '20t'); def(0x2a, 'goto/32', '30t');
def(0x2b, 'packed-switch', '31t'); def(0x2c, 'sparse-switch', '31t');
['cmpl-float', 'cmpg-float', 'cmpl-double', 'cmpg-double', 'cmp-long'].forEach((n, i) => def(0x2d + i, n, '23x'));
['if-eq', 'if-ne', 'if-lt', 'if-ge', 'if-gt', 'if-le'].forEach((n, i) => def(0x32 + i, n, '22t'));
['if-eqz', 'if-nez', 'if-ltz', 'if-gez', 'if-gtz', 'if-lez'].forEach((n, i) => def(0x38 + i, n, '21t'));
const KINDS = ['', '-wide', '-object', '-boolean', '-byte', '-char', '-short'];
KINDS.forEach((k, i) => { def(0x44 + i, `aget${k}`, '23x'); def(0x4b + i, `aput${k}`, '23x'); });
KINDS.forEach((k, i) => { def(0x52 + i, `iget${k}`, '22c', 'field'); def(0x59 + i, `iput${k}`, '22c', 'field'); });
KINDS.forEach((k, i) => { def(0x60 + i, `sget${k}`, '21c', 'field'); def(0x67 + i, `sput${k}`, '21c', 'field'); });
['invoke-virtual', 'invoke-super', 'invoke-direct', 'invoke-static', 'invoke-interface'].forEach((n, i) => {
  def(0x6e + i, n, '35c', 'method');
  def(0x74 + i, `${n}/range`, '3rc', 'method');
});
['neg-int', 'not-int', 'neg-long', 'not-long', 'neg-float', 'neg-double', 'int-to-long', 'int-to-float', 'int-to-double',
  'long-to-int', 'long-to-float', 'long-to-double', 'float-to-int', 'float-to-long', 'float-to-double', 'double-to-int',
  'double-to-long', 'double-to-float', 'int-to-byte', 'int-to-char', 'int-to-short'].forEach((n, i) => def(0x7b + i, n, '12x'));
const BIN = ['add', 'sub', 'mul', 'div', 'rem', 'and', 'or', 'xor', 'shl', 'shr', 'ushr'];
const BINF = ['add', 'sub', 'mul', 'div', 'rem'];
const binops: string[] = [
  ...BIN.map((b) => `${b}-int`), ...BIN.map((b) => `${b}-long`), ...BINF.map((b) => `${b}-float`), ...BINF.map((b) => `${b}-double`),
];
binops.forEach((n, i) => { def(0x90 + i, n, '23x'); def(0xb0 + i, `${n}/2addr`, '12x'); });
['add-int/lit16', 'rsub-int', 'mul-int/lit16', 'div-int/lit16', 'rem-int/lit16', 'and-int/lit16', 'or-int/lit16', 'xor-int/lit16']
  .forEach((n, i) => def(0xd0 + i, n, '22s'));
['add-int/lit8', 'rsub-int/lit8', 'mul-int/lit8', 'div-int/lit8', 'rem-int/lit8', 'and-int/lit8', 'or-int/lit8', 'xor-int/lit8',
  'shl-int/lit8', 'shr-int/lit8', 'ushr-int/lit8'].forEach((n, i) => def(0xd8 + i, n, '22b'));
def(0xfa, 'invoke-polymorphic', '45cc', 'method'); def(0xfb, 'invoke-polymorphic/range', '4rcc', 'method');
def(0xfc, 'invoke-custom', '35c', 'callsite'); def(0xfd, 'invoke-custom/range', '3rc', 'callsite');
def(0xfe, 'const-method-handle', '21c', 'methodhandle'); def(0xff, 'const-method-type', '21c', 'proto');

export const PAYLOAD = { PACKED: 0x0100, SPARSE: 0x0200, ARRAY: 0x0300 } as const;
