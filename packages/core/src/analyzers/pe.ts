import type { Analyzer, Section } from '../types.js';
import { Reader, entropy } from '../bytes.js';
import { md5 } from '../hash.js';

const MACHINE: Record<number, string> = { 0x14c: 'x86', 0x8664: 'x86-64', 0x1c0: 'ARM', 0xaa64: 'AArch64', 0x1c4: 'ARMv7', 0x200: 'IA-64' };
const SUBSYS: Record<number, string> = { 1: 'native', 2: 'Windows GUI', 3: 'Windows console', 5: 'OS/2', 7: 'POSIX', 9: 'Windows CE', 10: 'EFI application' };

export const peAnalyzer: Analyzer = {
  id: 'pe',
  title: 'PE',
  description: 'Parses PE headers, sections, imports, the import hash (imphash), DLL characteristics and Authenticode presence.',
  applies: (ctx) => ctx.format === 'pe' || ctx.format === 'dotnet',
  run(ctx) {
    const { bytes, report } = ctx;
    const r = new Reader(bytes, true);
    const peOff = r.u32(0x3c);
    const machine = r.u16(peOff + 4);
    const numSections = r.u16(peOff + 6);
    const optSize = r.u16(peOff + 20);
    const optOff = peOff + 24;
    const magic = r.u16(optOff);
    const is64 = magic === 0x20b;
    report.file.bits = is64 ? 64 : 32;
    report.file.endian = 'le';
    report.file.arch = MACHINE[machine] ?? `machine 0x${machine.toString(16)}`;
    const subsystem = r.u16(optOff + 68);
    const dllChars = r.u16(optOff + 70);
    const numRva = r.u32(optOff + (is64 ? 108 : 92));
    const dirStart = optOff + (is64 ? 112 : 96);

    const dir = (i: number): { rva: number; size: number } => {
      const b = dirStart + i * 8;
      return { rva: r.u32(b), size: r.u32(b + 4) };
    };
    const importDir = numRva > 1 ? dir(1) : { rva: 0, size: 0 };
    const certDir = numRva > 4 ? dir(4) : { rva: 0, size: 0 };

    const secOff = optOff + optSize;
    const sections: Section[] = [];
    const secList: { name: string; vaddr: number; vsize: number; raw: number; rawSize: number }[] = [];
    for (let i = 0; i < numSections; i++) {
      const b = secOff + i * 40;
      if (b + 40 > bytes.length) break;
      let name = '';
      for (let j = 0; j < 8 && bytes[b + j]; j++) name += String.fromCharCode(bytes[b + j] as number);
      const vsize = r.u32(b + 8), vaddr = r.u32(b + 12), rawSize = r.u32(b + 16), raw = r.u32(b + 20);
      const ent = raw + rawSize <= bytes.length && rawSize > 0 ? Number(entropy(bytes, raw, raw + rawSize).toFixed(3)) : 0;
      sections.push({ name, offset: raw, size: rawSize, vaddr, entropy: ent });
      secList.push({ name, vaddr, vsize, raw, rawSize });
    }
    report.sections = sections;

    const rvaToOff = (rva: number): number => {
      for (const s of secList) if (rva >= s.vaddr && rva < s.vaddr + Math.max(s.vsize, s.rawSize)) return s.raw + (rva - s.vaddr);
      return -1;
    };
    const cstr = (off: number): string => {
      let s = '';
      for (let i = off; i >= 0 && i < bytes.length && bytes[i]; i++) s += String.fromCharCode(bytes[i] as number);
      return s;
    };

    // Import table and imphash (pefile style: lowercase dll without ext, dot, import name).
    const imphashParts: string[] = [];
    if (importDir.rva) {
      let p = rvaToOff(importDir.rva);
      for (let n = 0; p >= 0 && n < 1024; n++, p += 20) {
        if (p + 20 > bytes.length) break;
        const origThunk = r.u32(p), nameRva = r.u32(p + 12), firstThunk = r.u32(p + 16);
        if (nameRva === 0 && firstThunk === 0) break;
        const dllOff = rvaToOff(nameRva);
        if (dllOff < 0) break;
        const dll = cstr(dllOff);
        const dllKey = dll.toLowerCase().replace(/\.(dll|ocx|sys)$/i, '');
        const symbols: string[] = [];
        let tRva = origThunk || firstThunk;
        let t = rvaToOff(tRva);
        const ptr = is64 ? 8 : 4;
        for (let k = 0; t >= 0 && k < 4096; k++, t += ptr) {
          if (t + ptr > bytes.length) break;
          const val = is64 ? Number(r.u64(t)) : r.u32(t);
          if (val === 0) break;
          const isOrdinal = is64 ? (val & 0x8000000000000000) !== 0 : (val & 0x80000000) !== 0;
          if (isOrdinal) {
            const ord = val & 0xffff;
            symbols.push(`ord${ord}`);
            imphashParts.push(`${dllKey}.ord${ord}`);
          } else {
            const hintOff = rvaToOff(val & 0x7fffffff);
            if (hintOff < 0) break;
            const fn = cstr(hintOff + 2);
            if (fn) { symbols.push(fn); imphashParts.push(`${dllKey}.${fn.toLowerCase()}`); }
          }
        }
        report.imports.push({ library: dll, symbols });
      }
    }
    const imphash = imphashParts.length ? md5(new TextEncoder().encode(imphashParts.join(','))) : undefined;

    report.hardening = {
      subsystem: SUBSYS[subsystem] ?? `subsystem ${subsystem}`,
      aslr: (dllChars & 0x0040) !== 0,
      dep_nx: (dllChars & 0x0100) !== 0,
      cfg: (dllChars & 0x4000) !== 0,
      highEntropyVA: (dllChars & 0x0020) !== 0,
      signed: certDir.rva !== 0 && certDir.size !== 0,
      ...(imphash ? { imphash } : {}),
    };
    if (certDir.rva) {
      report.findings.push({
        id: 'pe.authenticode', analyzer: 'pe', title: 'Authenticode signature present', severity: 'info',
        detail: `The file carries a WIN_CERTIFICATE table of ${certDir.size} bytes at file offset ${certDir.rva}. Verify the signer chain to confirm trust; presence alone is not trust.`,
        evidence: [{ offset: certDir.rva, length: certDir.size }], tags: ['signature'],
      });
    }
    report.meta.pe = { machine: report.file.arch, imphash, importedDlls: report.imports.length, subsystem: SUBSYS[subsystem] };
  },
};
