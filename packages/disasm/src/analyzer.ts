// Analyzer for @revlens/core: adds a native code overview under report.meta.disasm and findings for
// call sites of sensitive APIs (process execution, injection, dynamic loading).
import type { Analyzer, Finding } from '@revlens/core';
import { Program } from './analysis/program.js';
import { summarizeFunction } from './api.js';
import { hx } from './util.js';
import { normName } from './analysis/program.js';

const SENSITIVE: { names: string[]; title: string; attack: string; severity: Finding['severity'] }[] = [
  { names: ['system', 'popen', 'execve', 'execv', 'execvp', 'execl', 'execlp', 'posix_spawn', 'winexec', 'shellexecutea', 'shellexecutew', 'shellexecuteexw', 'createprocessa', 'createprocessw', 'createprocessasusera', 'createprocessasuserw'], title: 'Process execution call sites', attack: 'T1059', severity: 'low' },
  { names: ['virtualallocex', 'writeprocessmemory', 'createremotethread', 'ntcreatethreadex', 'queueuserapc', 'setthreadcontext', 'ptrace', 'process_vm_writev'], title: 'Process injection API call sites', attack: 'T1055', severity: 'medium' },
  { names: ['dlopen', 'dlsym', 'loadlibrarya', 'loadlibraryw', 'loadlibraryexa', 'loadlibraryexw', 'getprocaddress', 'ldrloaddll'], title: 'Dynamic code loading call sites', attack: 'T1129', severity: 'info' },
  { names: ['mprotect', 'virtualprotect', 'virtualalloc', 'mmap'], title: 'Memory protection change call sites', attack: 'T1027', severity: 'info' },
];

export const disasmAnalyzer: Analyzer = {
  id: 'disasm',
  title: 'Native code analysis',
  description: 'Disassembles x86, x86-64, AArch64 and ARM code in ELF, PE and Mach-O files: functions, CFG, call graph, string and import references.',
  applies: (ctx) => ctx.format === 'elf' || ctx.format === 'pe' || ctx.format === 'macho' || ctx.format === 'macho-fat',
  async run(ctx) {
    let p: Program;
    try {
      p = await Program.open(ctx.bytes, { discoveryMs: 2500 });
    } catch (e) {
      ctx.report.meta.disasm = { error: (e as Error).message };
      return;
    }
    if (!p.decoder) {
      ctx.report.meta.disasm = { arch: p.img.arch, error: 'no decoder for this architecture', decoderErrors: p.decoderErrors };
      return;
    }
    p.discover();
    const idx = p.xrefs(3000);
    const fns = [...p.functions.values()].filter((f) => !f.isImportStub);
    const pick = (n: string) => fns.find((f) => normName(f.name) === n);
    const keyFns = [p.img.entry !== undefined ? p.functions.get(p.img.entry) : undefined, pick('main'), pick('winmain'), pick('dllmain'), pick('main.main')]
      .filter((f, i, a): f is NonNullable<typeof f> => !!f && a.indexOf(f) === i);
    const findings: Finding[] = [];
    for (const group of SENSITIVE) {
      const evidence: { offset?: number; snippet?: string }[] = [];
      for (const [stub, imp] of p.importByStub) if (group.names.includes(normName(imp.name))) {
        for (const r of idx.to.get(stub) ?? []) evidence.push({ offset: p.mem.toOffset(r.from) + p.img.fileOffset, snippet: `${hx(r.from)} in ${p.functions.get(r.func)?.name ?? hx(r.func)} calls ${imp.name}` });
      }
      for (const [slot, imp] of p.importBySlot) if (group.names.includes(normName(imp.name))) {
        for (const r of idx.to.get(slot) ?? []) evidence.push({ offset: p.mem.toOffset(r.from) + p.img.fileOffset, snippet: `${hx(r.from)} in ${p.functions.get(r.func)?.name ?? hx(r.func)} uses ${imp.name}` });
      }
      if (evidence.length) {
        findings.push({
          id: `disasm.${group.attack.toLowerCase()}`, analyzer: 'disasm', title: group.title, severity: group.severity,
          detail: `${evidence.length} call site(s) found by disassembly.`, evidence: evidence.slice(0, 25), attack: [group.attack], tags: ['disasm'],
        });
      }
    }
    for (const f of findings) ctx.report.findings.push(f);
    ctx.report.meta.disasm = {
      arch: p.img.arch, format: p.img.format, entry: p.img.entry !== undefined ? hx(p.img.entry) : undefined,
      decoder: p.decoder.name, functions: fns.length, importStubs: p.importByStub.size,
      discoveryComplete: p.discoveryComplete, xrefsComplete: idx.complete, go: p.img.goVersionHint,
      keyFunctions: keyFns.map((f) => { const af = p.analyze(f.addr); return af ? summarizeFunction(p, af) : { addr: hx(f.addr), name: f.name }; }),
      largestFunctions: [...fns].sort((a, b) => (b.size ?? 0) - (a.size ?? 0)).slice(0, 10).map((f) => ({ addr: hx(f.addr), name: f.name, size: f.size })),
    };
  },
};
