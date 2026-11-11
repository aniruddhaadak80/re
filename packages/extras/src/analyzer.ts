// Analyzers that plug @revlens/extras into @revlens/core analyze(). Results go to
// report.meta.extras, with findings for facts that matter for triage.

import type { Analyzer, AnalyzerContext, Finding } from '@revlens/core';
import { checksec } from './bin/checksec.js';
import { goSymbols } from './go/pclntab.js';
import { rustInfo } from './rust/rust.js';
import { peAuthenticode, detectInstaller, peOverlay, peVersionInfo, richHeader } from './pe/pe.js';
import { machoCodeSignature } from './macho/machox.js';
import { elfNotes } from './elf/elfx.js';
import { scanFirmware } from './firmware/firmware.js';
import { inspectJsEngine } from './v8/v8.js';
import { inspectGpu } from './gpu/gpu.js';
import { inspectModel } from './model/model.js';
import { parseLnk } from './windows/lnk.js';
import { parseIps } from './apple/ips.js';
import { jsonSafe } from './tools.js';

function meta(ctx: AnalyzerContext): Record<string, unknown> {
  const m = (ctx.report.meta.extras ??= {}) as Record<string, unknown>;
  return m;
}
function add(ctx: AnalyzerContext, f: Omit<Finding, 'analyzer'>): void { ctx.report.findings.push({ analyzer: 'extras', ...f }); }
function safe<T>(f: () => T): T | undefined { try { return f(); } catch { return undefined; } }
async function safeAsync<T>(f: () => Promise<T>): Promise<T | undefined> { try { return await f(); } catch { return undefined; } }

/** Native executables: hardening, signatures, Go and Rust toolchain facts, installers. */
export const extrasNativeAnalyzer: Analyzer = {
  id: 'extras-native',
  title: 'Extras: hardening, signatures and toolchains',
  description: 'checksec style hardening, Authenticode and Mach-O code signature checks, Go pclntab and Rust toolchain facts, installer and overlay detection.',
  applies: (ctx) => ['elf', 'pe', 'macho', 'macho-fat'].includes(ctx.format),
  async run(ctx) {
    const m = meta(ctx);
    const b = ctx.bytes;
    const cs = safe(() => checksec(b));
    if (cs) {
      m.checksec = cs;
      const weak = cs.checks.filter((c) => (c.name === 'NX' || c.name === 'DEP') && c.value === false);
      for (const c of weak) add(ctx, { id: 'extras.no-nx', title: 'Executable stack or data (no NX/DEP)', severity: 'medium', detail: c.evidence, evidence: [{ snippet: c.evidence }], tags: ['hardening'] });
    }
    const go = safe(() => goSymbols(b, { maxFunctions: 50000 }));
    if (go) m.go = { version: go.version, goVersionRange: go.goVersionRange, functions: go.functionCount, files: go.fileCount, packages: go.packages.slice(0, 50), offset: go.offset, source: go.source };
    const rust = safe(() => rustInfo(b));
    if (rust?.isRust) m.rust = rust;
    if (ctx.format === 'pe') {
      const sigs = await safeAsync(() => peAuthenticode(b));
      if (sigs) {
        m.authenticode = jsonSafe(sigs.map((s) => ({ offset: s.offset, digestAlgorithm: s.digestAlgorithm, digestMatches: s.digestMatches, signatureVerified: s.signatureVerified, signer: s.signer.issuer, subject: s.signer.certificate?.subject, signingTime: s.signingTime, timestamped: s.timestamped })));
        for (const s of sigs) {
          if (!s.digestMatches) add(ctx, { id: 'extras.authenticode-digest-mismatch', title: 'Authenticode digest does not match the file', severity: 'high', detail: `Signed ${s.digestAlgorithm} digest ${s.signedDigest} but the image hashes to ${s.computedDigest}. The file was modified after signing.`, evidence: [{ offset: s.offset, length: s.length }], tags: ['signature'], attack: ['T1553.002'] });
          else if (s.signatureVerified === false) add(ctx, { id: 'extras.authenticode-bad-signature', title: 'Authenticode signer signature does not verify', severity: 'high', detail: 'The digest matches but the signature over the signed attributes is invalid.', evidence: [{ offset: s.offset, length: s.length }], tags: ['signature'] });
        }
        if (!sigs.length) add(ctx, { id: 'extras.pe-unsigned', title: 'PE file is not Authenticode signed', severity: 'info', detail: 'No WIN_CERTIFICATE entry in the security directory.', evidence: [], tags: ['signature'] });
      }
      const inst = safe(() => detectInstaller(b));
      if (inst?.length) { m.installers = inst; add(ctx, { id: 'extras.installer', title: `Installer or packer: ${inst.map((x) => x.kind).join(', ')}`, severity: 'info', detail: 'Payload is likely unpacked at run time; analyse the extracted files too.', evidence: inst.flatMap((x) => x.evidence.slice(0, 2).map((e) => ({ offset: e.offset, snippet: e.snippet }))), tags: ['installer'] }); }
      const ov = safe(() => peOverlay(b));
      if (ov) { m.overlay = ov; if (ov.entropy > 7.5 && ov.size > 4096) add(ctx, { id: 'extras.pe-overlay-high-entropy', title: 'Large high entropy overlay after the PE image', severity: 'low', detail: `${ov.size} bytes at ${ov.offset} with entropy ${ov.entropy.toFixed(2)}; often an appended archive or encrypted payload.`, evidence: [{ offset: ov.offset, length: Math.min(ov.size, 64) }], tags: ['overlay'], attack: ['T1027'] }); }
      const vi = safe(() => peVersionInfo(b));
      if (vi) m.versionInfo = vi;
      const rh = safe(() => richHeader(b));
      if (rh) m.richHeader = { checksumValid: rh.checksumValid, hash: rh.hash, entries: rh.entries.length };
      if (rh && !rh.checksumValid) add(ctx, { id: 'extras.rich-header-tampered', title: 'Rich header checksum does not match', severity: 'low', detail: 'The Rich header was edited after linking or copied from another file.', evidence: [{ offset: rh.offset }], tags: ['rich-header'] });
    }
    if (ctx.format === 'macho' || ctx.format === 'macho-fat') {
      const cs2 = safe(() => machoCodeSignature(b));
      if (cs2) {
        m.codeSignature = jsonSafe({ adhoc: cs2.adhoc, hardenedRuntime: cs2.hardenedRuntime, signer: cs2.cms?.signer, entitlementKeys: cs2.entitlementKeys, codeDirectories: cs2.codeDirectories.length });
        if (cs2.entitlementKeys.includes('com.apple.security.get-task-allow')) add(ctx, { id: 'extras.macho-get-task-allow', title: 'get-task-allow entitlement (debuggable build)', severity: 'medium', detail: 'Any process of the same user can attach a debugger and read memory.', evidence: [{ offset: cs2.offset }], tags: ['entitlements'] });
        if (cs2.entitlementKeys.includes('com.apple.security.cs.disable-library-validation')) add(ctx, { id: 'extras.macho-no-library-validation', title: 'Library validation disabled', severity: 'medium', detail: 'Unsigned dylibs can be loaded into the process (dylib hijacking).', evidence: [{ offset: cs2.offset }], tags: ['entitlements'], attack: ['T1574.004'] });
      }
    }
    if (ctx.format === 'elf') {
      const notes = safe(() => elfNotes(b));
      if (notes) m.elfNotes = notes.slice(0, 32);
    }
  },
};

/** Non native artifacts: JS engine caches, GPU code, model files, shortcuts, crash reports, firmware. */
export const extrasArtifactAnalyzer: Analyzer = {
  id: 'extras-artifacts',
  title: 'Extras: engine caches, GPU code, models, shortcuts, crash reports, firmware',
  description: 'Recognises V8 code cache and Hermes bytecode, CUDA/PTX/AMDGPU/SPIR-V, GGUF and safetensors, Windows .lnk, Apple .ips and scans unknown blobs for embedded firmware images.',
  applies: (ctx) => !['elf', 'pe', 'macho', 'macho-fat', 'zip', 'jar', 'apk', 'crx', 'xpi', 'vsix', 'npm-tgz', 'tar', 'asar', 'wasm', 'dex', 'class', 'pyc'].includes(ctx.format) || ctx.format === 'unknown',
  async run(ctx) {
    const b = ctx.bytes;
    const m = meta(ctx);
    const js = safe(() => inspectJsEngine(b));
    if (js) { m.jsEngine = js; add(ctx, { id: 'extras.js-engine-artifact', title: `Compiled JavaScript: ${js.kind}`, severity: 'info', detail: 'Source may be absent; bytecode needs an engine-matched decompiler.', evidence: [{ offset: 0, length: 8 }], tags: ['javascript'] }); return; }
    const gpu = safe(() => inspectGpu(b));
    if (gpu) { m.gpu = jsonSafe(gpu); return; }
    const model = safe(() => inspectModel(b, { maxTensors: 200 }));
    if (model) { m.model = model; if (model.format !== 'npy' && model.issues.length) add(ctx, { id: 'extras.model-inconsistent', title: 'Model file tensor table is inconsistent', severity: 'low', detail: model.issues.slice(0, 5).join('; '), evidence: [], tags: ['model'] }); return; }
    const lnk = safe(() => parseLnk(b));
    if (lnk) {
      m.lnk = lnk;
      const cmd = `${lnk.target ?? ''} ${lnk.arguments ?? ''}`.toLowerCase();
      if (/powershell|cmd\.exe|mshta|wscript|cscript|rundll32|regsvr32|certutil|bitsadmin/.test(cmd)) add(ctx, { id: 'extras.lnk-lolbin', title: 'Shortcut launches a script host or LOLBin', severity: 'high', detail: `Target ${lnk.target ?? '?'} with arguments ${(lnk.arguments ?? '').slice(0, 200)}`, evidence: [{ snippet: cmd.slice(0, 200) }], tags: ['lnk'], attack: ['T1204.002', 'T1218'] });
      return;
    }
    if (b[0] === 0x7b) {
      const ips = safe(() => parseIps(b, { maxThreads: 8, maxFrames: 32 }));
      if (ips) { m.ips = { kind: ips.kind, process: ips.process, exception: ips.exception, termination: ips.termination, crashedFrames: ips.crashedFrames.slice(0, 16) }; return; }
    }
    if (ctx.format === 'unknown' && b.length <= 256 << 20) {
      const hits = safe(() => scanFirmware(b, { maxHits: 500 }));
      const strong = hits?.filter((h) => h.confidence === 'high') ?? [];
      if (strong.length) { m.firmware = { hits: strong.slice(0, 200), total: hits?.length ?? 0 }; add(ctx, { id: 'extras.firmware-images', title: `Embedded images: ${[...new Set(strong.map((h) => h.type))].join(', ')}`, severity: 'info', detail: `${strong.length} validated headers found.`, evidence: strong.slice(0, 20).map((h) => ({ offset: h.offset, length: h.size, snippet: h.description })), tags: ['firmware'] }); }
    }
  },
};

export const ANALYZERS: Analyzer[] = [extrasNativeAnalyzer, extrasArtifactAnalyzer];
