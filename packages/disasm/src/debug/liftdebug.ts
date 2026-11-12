// Builds the debug name and type view the lifter uses from DWARF function records.
import type { AnalyzedFunction } from '../types.js';
import type { Program } from '../analysis/program.js';
import type { FlowResult } from '../analysis/dataflow.js';
import type { LiftDebug } from '../analysis/lift.js';
import { canon } from '../analysis/regs.js';
import type { DwarfFunction } from './dwarf.js';

const SP = new Set(['rsp', 'esp', 'sp']);

/** DWARF frame relative offset of a variable, keyed by the base it is relative to (fb: frame base, sp: stack pointer) */
function frameOff(v: DwarfFunction['params'][number], f: DwarfFunction): { base: 'fb' | 'sp'; off: number } | undefined {
  const l = v.location;
  if (!l) return undefined;
  if (l.fbreg !== undefined) return { base: 'fb', off: l.fbreg };
  if (l.breg && SP.has(l.breg.reg)) return { base: 'sp', off: l.breg.offset };
  if (l.breg && f.frameBase?.reg === l.breg.reg) return { base: 'fb', off: l.breg.offset };
  return undefined;
}

/** Offset added to a DWARF frame base (or stack pointer) offset to get an offset from the stack pointer at entry. */
function frameDelta(p: Program, f: DwarfFunction, fl: FlowResult, base: 'fb' | 'sp'): number | undefined {
  const fb = f.locals.concat(f.params).map((v) => frameOff(v, f)).filter((x) => x?.base === base).map((x) => x!.off);
  if (!fb.length || !fl.stackVars.length) return undefined;
  const have = new Set(fl.stackVars.map((v) => v.off));
  const arch = p.arch;
  const canonical = base === 'sp' ? Math.min(...fl.stackVars.map((v) => v.off)) : arch === 'x86_64' ? -8 : arch === 'x86' ? -4 : arch === 'arm64' ? -16 : 0;
  const cands = new Set<number>([canonical, 0, -4, -8, -16, 8, 16]);
  for (const o of fb.slice(0, 64)) for (const v of fl.stackVars.slice(0, 256)) cands.add(v.off - o);
  let best: number | undefined, bestN = 0;
  for (const d of cands) {
    let n = 0;
    for (const o of fb) if (have.has(o + d)) n++;
    if (n > bestN || (n === bestN && d === canonical)) { best = d; bestN = n; }
  }
  return bestN > 0 ? best : undefined;
}

/** Debug view for one function, or undefined when the binary has no DWARF record for it. */
export function liftDebugFor(p: Program, af: AnalyzedFunction, fl: FlowResult | undefined): LiftDebug | undefined {
  const f = p.debugFunction(af.addr);
  if (!f) return undefined;
  const types = p.debugTypes();
  const paramByReg = new Map<string, { name: string; typeRef?: number }>();
  const argRegs = fl?.argRegs ?? p.abi().argRegs;
  let k = 0;
  let ordered = true;
  for (const prm of f.params) {
    const loc = prm.location?.reg ? canon(p.arch, prm.location.reg) ?? prm.location.reg : undefined;
    if (loc && argRegs.includes(loc)) { paramByReg.set(loc, { name: prm.name, typeRef: prm.typeRef }); k = Math.max(k, argRegs.indexOf(loc) + 1); continue; }
    if (types.isFloat(prm.typeRef)) continue;
    if (types.isAggregate(prm.typeRef)) {
      const sz = types.sizeOf(prm.typeRef) ?? 99;
      if (p.img.format === 'pe' && p.arch === 'x86_64') { if (sz > 8) { k++; continue; } }
      else if (sz > 16) continue;
      else { if (!prm.location?.reg) ordered = false; k += Math.ceil(sz / 8); continue; }
    }
    if (!ordered || prm.location?.reg) continue;
    const r = argRegs[k++];
    if (r && !paramByReg.has(r)) paramByReg.set(r, { name: prm.name, typeRef: prm.typeRef });
  }
  const varByOff = new Map<number, { name: string; type: string; typeRef?: number; param?: boolean }>();
  if (fl) {
    const deltas = { fb: frameDelta(p, f, fl, 'fb'), sp: frameDelta(p, f, fl, 'sp') };
    const paramNames = new Set(f.params.map((x) => x.name));
    for (const v of [...f.params, ...f.locals]) {
      const o = frameOff(v, f);
      const d = o ? deltas[o.base] : undefined;
      if (!o || d === undefined || varByOff.has(o.off + d)) continue;
      varByOff.set(o.off + d, { name: v.name, type: v.type, typeRef: v.typeRef, ...(paramNames.has(v.name) ? { param: true } : {}) });
    }
  }
  return {
    prototype: f.prototype,
    paramByReg, varByOff,
    field: (t, off) => types.fieldPath(t, off),
    source: `DWARF (${f.name}${f.line !== undefined ? ', line ' + f.line : ''})`,
  };
}
