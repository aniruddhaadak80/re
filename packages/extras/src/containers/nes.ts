// iNES and NES 2.0 ROM headers (written from the NESdev wiki descriptions of the two formats).

import { sha1 } from '@revlens/core';
import { ParseError, crc32 } from '../util.js';

export interface InesInfo {
  format: 'iNES' | 'NES 2.0' | 'archaic iNES';
  mapper: number; submapper?: number;
  prgRomSize: number; chrRomSize: number;
  prgRamSize?: number; prgNvramSize?: number; chrRamSize?: number; chrNvramSize?: number;
  mirroring: 'horizontal' | 'vertical' | 'four-screen'; battery: boolean; trainer: boolean;
  console: string; timing: string; vsPpu?: number; vsHardware?: number; extendedConsole?: number; miscRoms?: number; defaultExpansion?: number;
  prgOffset: number; chrOffset: number; trailingBytes: number;
  prgCrc32: string; chrCrc32?: string; romCrc32: string; romSha1: string;
  warnings: string[];
}

const CONSOLE = ['NES/Famicom', 'Vs. System', 'PlayChoice-10', 'extended'];
const TIMING = ['NTSC (RP2C02)', 'PAL (RP2C07)', 'multiple regions', 'Dendy (UA6538)'];

/** NES 2.0 ROM size field: 12 bit count of 16 KiB or 8 KiB units, or the exponent-multiplier form. */
function romSize(lsb: number, msbNibble: number, unit: number): number {
  if (msbNibble !== 0xf) return ((msbNibble << 8) | lsb) * unit;
  const exp = lsb >> 2, mul = (lsb & 3) * 2 + 1;
  return 2 ** exp * mul;
}
const shiftSize = (n: number) => (n ? 64 << n : 0);

export function isInes(b: Uint8Array): boolean { return b.length >= 16 && b[0] === 0x4e && b[1] === 0x45 && b[2] === 0x53 && b[3] === 0x1a; }

/** Parse the 16 byte header of an iNES or NES 2.0 ROM and hash its PRG and CHR data. */
export function parseInes(b: Uint8Array): InesInfo {
  if (!isInes(b)) throw new ParseError('not an iNES ROM (no NES\\x1a magic)');
  const h = (k: number) => b[k] as number;
  const warnings: string[] = [];
  const nes2 = (h(7) & 0x0c) === 0x08;
  const archaic = !nes2 && (h(7) & 0x0c) === 0x04 || (!nes2 && (h(12) | h(13) | h(14) | h(15)) !== 0);
  const trainer = (h(6) & 4) !== 0;
  const mirroring = h(6) & 8 ? 'four-screen' : h(6) & 1 ? 'vertical' : 'horizontal';
  let mapper = (h(6) >> 4) | (archaic ? 0 : h(7) & 0xf0);
  let prg: number, chr: number;
  const out: Partial<InesInfo> = {};
  const cons = h(7) & 3;
  let timing = 'NTSC (RP2C02)';
  if (nes2) {
    mapper |= (h(8) & 0x0f) << 8;
    out.submapper = h(8) >> 4;
    prg = romSize(h(4), h(9) & 0x0f, 16384);
    chr = romSize(h(5), h(9) >> 4, 8192);
    out.prgRamSize = shiftSize(h(10) & 0x0f); out.prgNvramSize = shiftSize(h(10) >> 4);
    out.chrRamSize = shiftSize(h(11) & 0x0f); out.chrNvramSize = shiftSize(h(11) >> 4);
    timing = TIMING[h(12) & 3]!;
    if (cons === 1) { out.vsPpu = h(13) & 0x0f; out.vsHardware = h(13) >> 4; }
    if (cons === 3) out.extendedConsole = h(13) & 0x0f;
    out.miscRoms = h(14) & 3;
    out.defaultExpansion = h(15) & 0x3f;
  } else {
    prg = h(4) * 16384;
    chr = h(5) * 8192;
    if (!archaic) { out.prgRamSize = (h(8) || 1) * 8192; if (h(9) & 1) timing = 'PAL (RP2C07)'; }
    else warnings.push('bytes 7 to 15 look like archaic iNES or a ripper signature; the mapper high nibble was ignored');
    if (!chr) out.chrRamSize = 8192;
  }
  const prgOffset = 16 + (trainer ? 512 : 0);
  const chrOffset = prgOffset + prg;
  if (chrOffset > b.length) warnings.push(`file is ${b.length} bytes but the header declares ${chrOffset + chr}`);
  const prgData = b.subarray(prgOffset, Math.min(b.length, chrOffset));
  const chrData = b.subarray(Math.min(b.length, chrOffset), Math.min(b.length, chrOffset + chr));
  const rom = b.subarray(prgOffset, Math.min(b.length, chrOffset + chr));
  const hex32 = (n: number) => n.toString(16).padStart(8, '0');
  return {
    format: nes2 ? 'NES 2.0' : archaic ? 'archaic iNES' : 'iNES', mapper, ...out,
    prgRomSize: prg, chrRomSize: chr, mirroring, battery: (h(6) & 2) !== 0, trainer,
    console: CONSOLE[cons]!, timing,
    prgOffset, chrOffset, trailingBytes: Math.max(0, b.length - (chrOffset + chr)),
    prgCrc32: hex32(crc32(prgData)), ...(chr ? { chrCrc32: hex32(crc32(chrData)) } : {}), romCrc32: hex32(crc32(rom)), romSha1: sha1(rom),
    warnings,
  } as InesInfo;
}

