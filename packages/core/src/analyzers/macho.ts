import type { Analyzer, Section } from '../types.js';
import { Reader, entropy } from '../bytes.js';

const CPU: Record<number, string> = { 7: 'x86', 0x01000007: 'x86-64', 12: 'ARM', 0x0100000c: 'AArch64', 18: 'PowerPC' };
const LC_SEGMENT = 0x1, LC_SEGMENT_64 = 0x19, LC_LOAD_DYLIB = 0xc, LC_LOAD_WEAK_DYLIB = 0x80000018, LC_CODE_SIGNATURE = 0x1d, LC_MAIN = 0x80000028, LC_ID_DYLIB = 0xd;

export const machoAnalyzer: Analyzer = {
  id: 'macho',
  title: 'Mach-O',
  description: 'Parses Mach-O load commands, segments, linked dylibs and code signature presence. Reads the fat header too.',
  applies: (ctx) => ctx.format === 'macho' || ctx.format === 'macho-fat',
  run(ctx) {
    const { bytes, report } = ctx;
    if (ctx.format === 'macho-fat') {
      const r = new Reader(bytes, false);
      const n = r.u32(4);
      const arches: string[] = [];
      for (let i = 0; i < n && i < 32; i++) {
        const b = 8 + i * 20;
        arches.push(CPU[r.u32(b)] ?? `cpu 0x${r.u32(b).toString(16)}`);
      }
      report.file.arch = `universal (${arches.join(', ')})`;
      report.meta.macho = { fat: true, arches };
      return;
    }
    const magic = ((bytes[0] as number) | ((bytes[1] as number) << 8) | ((bytes[2] as number) << 16) | ((bytes[3] as number) << 24)) >>> 0;
    const little = magic === 0xfeedface || magic === 0xfeedfacf;
    const is64 = magic === 0xfeedfacf || magic === 0xcffaedfe;
    const r = new Reader(bytes, little);
    report.file.endian = little ? 'le' : 'be';
    report.file.bits = is64 ? 64 : 32;
    const cpu = r.u32(4);
    report.file.arch = CPU[cpu] ?? `cpu 0x${cpu.toString(16)}`;
    const ncmds = r.u32(16);
    let off = is64 ? 32 : 28;
    const sections: Section[] = [];
    const dylibs: string[] = [];
    let signed = false, hasMain = false;
    for (let i = 0; i < ncmds && off + 8 <= bytes.length; i++) {
      const cmd = r.u32(off);
      const size = r.u32(off + 4);
      if (size < 8) break;
      if (cmd === LC_SEGMENT_64 || cmd === LC_SEGMENT) {
        const seg64 = cmd === LC_SEGMENT_64;
        let name = '';
        for (let j = 0; j < 16 && bytes[off + 8 + j]; j++) name += String.fromCharCode(bytes[off + 8 + j] as number);
        const fileoff = seg64 ? Number(r.u64(off + 40)) : r.u32(off + 32);
        const filesize = seg64 ? Number(r.u64(off + 48)) : r.u32(off + 36);
        const vaddr = seg64 ? Number(r.u64(off + 24)) : r.u32(off + 24);
        const ent = fileoff + filesize <= bytes.length && filesize > 0 ? Number(entropy(bytes, fileoff, fileoff + filesize).toFixed(3)) : 0;
        sections.push({ name, offset: fileoff, size: filesize, vaddr, entropy: ent });
      } else if (cmd === LC_LOAD_DYLIB || cmd === LC_LOAD_WEAK_DYLIB || cmd === LC_ID_DYLIB) {
        const strOff = r.u32(off + 8);
        let s = '';
        for (let j = off + strOff; j < off + size && bytes[j]; j++) s += String.fromCharCode(bytes[j] as number);
        if (s && cmd !== LC_ID_DYLIB) dylibs.push(s);
      } else if (cmd === LC_CODE_SIGNATURE) signed = true;
      else if (cmd === LC_MAIN) hasMain = true;
      off += size;
    }
    report.sections = sections;
    if (dylibs.length) report.imports.push({ library: 'dylibs', symbols: dylibs });
    report.hardening = { codeSignature: signed, hasEntryPoint: hasMain, pie: true };
    if (signed) {
      report.findings.push({
        id: 'macho.codesign', analyzer: 'macho', title: 'Code signature present', severity: 'info',
        detail: 'The binary has an LC_CODE_SIGNATURE command. Verify it with codesign to confirm the signer; presence alone is not trust.',
        evidence: [], tags: ['signature'],
      });
    }
    report.meta.macho = { arch: report.file.arch, dylibs, segments: sections.length };
  },
};
