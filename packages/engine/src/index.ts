// @revlens/engine: one entry point that runs the core analyzers and every RevLens package on the same
// Report. Safe for browsers and Web Workers. Node-only tools and CLI commands live in '@revlens/engine/node'.
import { analyze, ANALYZERS as CORE_ANALYZERS, type AnalyzeOptions, type Analyzer, type Report } from '@revlens/core';
import { ANALYZERS as MANAGED_ANALYZERS } from '@revlens/managed';
import { ANALYZERS as WEBRT_ANALYZERS } from '@revlens/webrt';
import { ANALYZERS as MOBILE_ANALYZERS } from '@revlens/mobile';
import { ANALYZERS as DISASM_ANALYZERS, loadDecoders, type DecoderOptions } from '@revlens/disasm';

/** A RevLens package that adds analyzers to the combined report. */
export interface PackageInfo {
  /** short id used for CLI namespaces and filters */
  id: string;
  /** npm package name */
  npm: string;
  title: string;
  summary: string;
  analyzers: Analyzer[];
}

export const PACKAGES: PackageInfo[] = [
  { id: 'mobile', npm: '@revlens/mobile', title: 'Android, Java and iOS', summary: 'APK manifests and signatures, DEX and smali, Java class files, IPA plists and entitlements, app frameworks, IL2CPP metadata.', analyzers: MOBILE_ANALYZERS as Analyzer[] },
  { id: 'managed', npm: '@revlens/managed', title: 'Managed and bytecode runtimes', summary: '.NET metadata and CIL, Python pyc and PyInstaller, Lua, Erlang BEAM and EVM bytecode.', analyzers: MANAGED_ANALYZERS as Analyzer[] },
  { id: 'web', npm: '@revlens/webrt', title: 'Web runtime', summary: 'JavaScript deobfuscation and bundles, endpoints, source maps, Electron ASAR audit, PCAP, SQLite and HAR.', analyzers: WEBRT_ANALYZERS as Analyzer[] },
  { id: 'disasm', npm: '@revlens/disasm', title: 'Native code', summary: 'x86, x86-64, AArch64 and ARM disassembly, functions, CFG, xrefs, call graph and pseudo code.', analyzers: DISASM_ANALYZERS as Analyzer[] },
];

/** Every package analyzer, in run order (disassembly last because it is the slowest). */
export const PACKAGE_ANALYZERS: Analyzer[] = PACKAGES.flatMap((p) => p.analyzers);

/** One line per analyzer across core and every package. */
export const ALL_ANALYZERS: { id: string; title: string; description: string; package: string }[] = [
  ...CORE_ANALYZERS.map((a) => ({ ...a, package: 'core' })),
  ...PACKAGES.flatMap((p) => p.analyzers.map((a) => ({ id: a.id, title: a.title, description: a.description, package: p.id }))),
];

export interface EngineOptions extends AnalyzeOptions {
  /** limit package analyzers to these package ids (core always runs). Default: all packages. */
  packages?: string[];
}

/**
 * Analyze bytes with the core analyzers plus every package analyzer, producing one combined Report.
 * Package output lands under report.meta.<package> and in the usual findings, imports and components.
 */
export async function analyzeAll(bytes: Uint8Array, opts: EngineOptions = {}): Promise<Report> {
  const { packages, ...rest } = opts;
  const extra = packages ? PACKAGES.filter((p) => packages.includes(p.id)).flatMap((p) => p.analyzers) : PACKAGE_ANALYZERS;
  return analyze(bytes, { ...rest, extraAnalyzers: [...(rest.extraAnalyzers ?? []), ...extra] });
}

/**
 * Load the disassembly engines ahead of time. In a browser, pass the Capstone wasm bytes
 * (fetched from a bundler asset URL) so ARM and AArch64 decoding works without a file system.
 */
export async function initDisasm(opts: DecoderOptions = {}): Promise<{ x86: boolean; arm: boolean; errors: string[] }> {
  const d = await loadDecoders(opts);
  return { x86: !!d.x86, arm: !!d.arm, errors: d.errors };
}

/** Short list of the package views present in a report, for summaries. */
export function packageViews(report: Report): string[] {
  const out: string[] = [];
  const m = report.meta as Record<string, any>;
  if (m.disasm && !m.disasm.error) out.push(`disasm: ${m.disasm.arch} ${m.disasm.functions} functions`);
  if (m.managed) out.push(`managed: ${Object.keys(m.managed).join(', ')}`);
  if (m.mobile) out.push(`mobile: ${Object.keys(m.mobile).join(', ')}`);
  if (m.webrt) out.push(`web: ${Object.keys(m.webrt).join(', ')}`);
  return out;
}

export type { Report, Analyzer } from '@revlens/core';
