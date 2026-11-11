// Binary hardening report for ELF, PE and Mach-O, in the spirit of checksec, with evidence
// for every verdict (header flags, dynamic entries, imported symbols, notes).

import { parseBin, elfSymbols, type BinImage } from './container.js';
import { elfDynamic, elfNotes } from '../elf/elfx.js';
import { peHeaders, peLoadConfig, peDebug } from '../pe/pe.js';
import { machoInfo, machoSymbols, machoCodeSignature, type CodeSignature } from '../macho/machox.js';

export interface Check { name: string; value: string | boolean; evidence: string }
export interface Checksec { format: string; arch: string; bits: number; checks: Check[]; score: number; max: number }

const FORTIFIABLE = ['memcpy', 'memmove', 'memset', 'strcpy', 'strncpy', 'strcat', 'strncat', 'sprintf', 'snprintf', 'vsprintf', 'vsnprintf', 'printf', 'fprintf', 'vprintf', 'vfprintf', 'gets', 'fgets', 'read', 'recv', 'recvfrom', 'stpcpy', 'stpncpy', 'wcscpy', 'wmemcpy', 'realpath', 'getcwd', 'mbstowcs', 'wcstombs', 'syslog', 'vsyslog', 'pread', 'readlink', 'confstr', 'getgroups', 'ttyname_r', 'poll', 'ppoll'];

function elfChecks(img: BinImage): Check[] {
  const checks: Check[] = [];
  const v = img.view;
  const type = v.u16(16);
  const dyn = elfDynamic(img);
  const seg = (t: number) => img.segments.find((s) => s.ptype === t);
  const relro = seg(0x6474e552);
  checks.push({ name: 'RELRO', value: relro ? (dyn.bindNow ? 'full' : 'partial') : 'none', evidence: relro ? `PT_GNU_RELRO present${dyn.bindNow ? ', BIND_NOW set' : ''}` : 'no PT_GNU_RELRO segment' });
  const stack = seg(0x6474e551);
  checks.push({ name: 'NX', value: stack ? (stack.flags & 1) === 0 : false, evidence: stack ? `PT_GNU_STACK flags 0x${stack.flags.toString(16)}` : 'no PT_GNU_STACK (stack may be executable)' });
  const hasInterp = !!seg(3);
  const pie = type === 3 && (hasInterp || (dyn.flags1 & 0x08000000) !== 0);
  checks.push({ name: 'PIE', value: type === 2 ? false : pie ? true : type === 3 ? 'shared object' : false, evidence: `e_type ${type === 2 ? 'EXEC' : type === 3 ? 'DYN' : type}${dyn.flags1 & 0x08000000 ? ', DF_1_PIE' : ''}` });
  let syms: string[] = [];
  try { syms = [...elfSymbols(img, 'dynsym'), ...elfSymbols(img, 'symtab')].map((s) => s.name.replace(/@.*$/, '')); } catch { syms = []; }
  const set = new Set(syms);
  const canary = set.has('__stack_chk_fail') || set.has('__stack_chk_guard') || set.has('__intel_security_cookie');
  checks.push({ name: 'Stack canary', value: canary, evidence: canary ? 'references __stack_chk_fail' : 'no __stack_chk_fail reference' });
  const fortified = [...set].filter((s) => /^__\w+_chk$/.test(s) && s !== '__stack_chk_fail');
  const fortifiable = FORTIFIABLE.filter((f) => set.has(f));
  checks.push({ name: 'FORTIFY_SOURCE', value: fortified.length > 0, evidence: `${fortified.length} fortified (${fortified.slice(0, 8).join(', ')}), ${fortifiable.length} unfortified candidates` });
  checks.push({ name: 'RPATH', value: dyn.rpath ?? false, evidence: dyn.rpath ? `DT_RPATH ${dyn.rpath}` : 'no DT_RPATH' });
  checks.push({ name: 'RUNPATH', value: dyn.runpath ?? false, evidence: dyn.runpath ? `DT_RUNPATH ${dyn.runpath}` : 'no DT_RUNPATH' });
  const stripped = !img.sections.some((s) => s.type === 2);
  checks.push({ name: 'Symbols', value: stripped ? 'stripped' : 'present', evidence: stripped ? 'no .symtab' : '.symtab present' });
  let feats: string[] = [];
  try {
    for (const n of elfNotes(img.view.bytes)) {
      const props = (n.decoded?.properties as { features?: string[] }[] | undefined) ?? [];
      for (const p of props) if (p.features) feats = feats.concat(p.features);
    }
  } catch { feats = []; }
  if (img.machine === 'x86-64' || img.machine === 'x86') {
    checks.push({ name: 'CET IBT', value: feats.includes('IBT'), evidence: 'GNU_PROPERTY_X86_FEATURE_1_AND' });
    checks.push({ name: 'CET SHSTK', value: feats.includes('SHSTK'), evidence: 'GNU_PROPERTY_X86_FEATURE_1_AND' });
  }
  if (img.machine === 'aarch64') {
    checks.push({ name: 'BTI', value: feats.includes('BTI'), evidence: 'GNU_PROPERTY_AARCH64_FEATURE_1_AND' });
    checks.push({ name: 'PAC', value: feats.includes('PAC'), evidence: 'GNU_PROPERTY_AARCH64_FEATURE_1_AND' });
  }
  const san = ['__asan_init', '__ubsan_handle_add_overflow', '__msan_init', '__tsan_init', '__safestack_init', '__cfi_check'].filter((s) => set.has(s));
  checks.push({ name: 'Sanitizers or CFI', value: san.length ? san.join(', ') : false, evidence: san.length ? 'runtime symbols present' : 'none found' });
  return checks;
}

function peChecks(bytes: Uint8Array): Check[] {
  const h = peHeaders(bytes);
  const dc = h.dllCharacteristics;
  const lc = (() => { try { return peLoadConfig(bytes); } catch { return null; } })();
  const dbg = (() => { try { return peDebug(bytes); } catch { return []; } })();
  const ex = dbg.find((d) => d.typeId === 20);
  const flag = (b: number) => (dc & b) !== 0;
  return [
    { name: 'ASLR (DYNAMIC_BASE)', value: flag(0x40), evidence: `DllCharacteristics 0x${dc.toString(16)}` },
    { name: 'High entropy VA', value: flag(0x20), evidence: 'IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA' },
    { name: 'DEP (NX_COMPAT)', value: flag(0x100), evidence: 'IMAGE_DLLCHARACTERISTICS_NX_COMPAT' },
    { name: 'CFG', value: flag(0x4000) && !!lc?.cfgEnabled, evidence: `GUARD_CF flag ${flag(0x4000)}, load config guard flags ${lc?.guardFlagNames.join(' ') || 'none'}` },
    { name: 'GS (security cookie)', value: !!lc?.securityCookie, evidence: lc ? `SecurityCookie 0x${lc.securityCookie.toString(16)}` : 'no load config' },
    { name: 'SEH', value: flag(0x400) ? 'NO_SEH' : h.bits === 32 ? (lc?.seHandlerCount ? `SafeSEH (${lc.seHandlerCount} handlers)` : 'no SafeSEH') : 'table based (x64)', evidence: 'NO_SEH flag and load config SEHandlerTable' },
    { name: 'Force integrity', value: flag(0x80), evidence: 'IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY' },
    { name: 'AppContainer', value: flag(0x1000), evidence: 'IMAGE_DLLCHARACTERISTICS_APPCONTAINER' },
    { name: 'CET shadow stack compatible', value: !!ex?.features?.includes('CET_COMPAT'), evidence: ex ? `debug EX_DLLCHARACTERISTICS 0x${(ex.exDllCharacteristics ?? 0).toString(16)}` : 'no EX_DLLCHARACTERISTICS debug entry' },
    { name: 'Authenticode present', value: h.dataDirectories.some((d) => d.index === 4 && d.size > 0), evidence: 'security data directory' },
    { name: 'Checksum valid', value: h.checksum === 0 ? 'not set' : h.checksumValid, evidence: `stored 0x${h.checksum.toString(16)}, computed 0x${h.computedChecksum.toString(16)}` },
  ];
}

function machoChecks(bytes: Uint8Array): Check[] {
  const info = machoInfo(bytes);
  let syms = new Set<string>();
  try { syms = new Set(machoSymbols(bytes).filter((s) => s.undefined).map((s) => s.name)); } catch { syms = new Set(); }
  let sig: CodeSignature | null = null;
  try { sig = machoCodeSignature(bytes); } catch { sig = null; }
  const restrict = info.loadCommands.some(() => false) || new TextDecoder().decode(bytes.subarray(0, Math.min(bytes.length, 65536))).includes('__RESTRICT');
  return [
    { name: 'PIE', value: info.flagNames.includes('PIE'), evidence: `mach header flags 0x${info.flags.toString(16)}` },
    { name: 'NX heap', value: info.flagNames.includes('NO_HEAP_EXECUTION'), evidence: 'MH_NO_HEAP_EXECUTION' },
    { name: 'Executable stack', value: info.flagNames.includes('ALLOW_STACK_EXECUTION'), evidence: 'MH_ALLOW_STACK_EXECUTION' },
    { name: 'Stack canary', value: syms.has('___stack_chk_fail') || syms.has('___stack_chk_guard'), evidence: 'imports ___stack_chk_fail' },
    { name: 'ARC', value: syms.has('_objc_release') || syms.has('_objc_autoreleaseReturnValue'), evidence: 'imports _objc_release' },
    { name: 'Encrypted', value: info.encryption ? info.encryption.cryptid !== 0 : false, evidence: info.encryption ? `cryptid ${info.encryption.cryptid}` : 'no LC_ENCRYPTION_INFO' },
    { name: 'Code signature', value: sig ? (sig.adhoc ? 'ad hoc' : sig.cms?.signer ? 'signed' : 'present') : false, evidence: sig ? `${sig.codeDirectories[0]?.identifier ?? ''} cdhash ${sig.codeDirectories[0]?.cdhash ?? ''}` : 'no LC_CODE_SIGNATURE' },
    { name: 'Hardened runtime', value: !!sig?.hardenedRuntime, evidence: 'CodeDirectory flag CS_RUNTIME' },
    { name: 'Restrict segment', value: restrict, evidence: '__RESTRICT segment' },
  ];
}

const GOOD = new Set(['RELRO', 'NX', 'PIE', 'Stack canary', 'FORTIFY_SOURCE', 'ASLR (DYNAMIC_BASE)', 'High entropy VA', 'DEP (NX_COMPAT)', 'CFG', 'GS (security cookie)', 'NX heap', 'Hardened runtime', 'CET IBT', 'CET SHSTK', 'BTI', 'PAC', 'CET shadow stack compatible']);

/** Hardening checks with evidence. Works on ELF, PE and Mach-O. */
export function checksec(bytes: Uint8Array): Checksec {
  const img = parseBin(bytes);
  const checks = img.format === 'elf' ? elfChecks(img) : img.format === 'pe' ? peChecks(bytes) : machoChecks(bytes);
  let score = 0, max = 0;
  for (const c of checks) {
    if (!GOOD.has(c.name)) continue;
    max++;
    if (c.value === true || c.value === 'full') score++;
    else if (c.value === 'partial') score += 0.5;
  }
  return { format: img.format, arch: img.machine, bits: img.bits, checks, score, max };
}
