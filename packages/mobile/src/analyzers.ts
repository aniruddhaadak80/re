// @revlens/core Analyzer objects. Rich output goes to report.meta.mobile.

import type { Analyzer, AnalyzerContext, Finding } from '@revlens/core';
import { analyzeApk } from './apk.js';
import { detectLibraries, nativeMethods, obfuscationHints, scanStrings, sensitiveApis, xrefIndex } from './dex/analysis.js';
import { isDex, openDex } from './dex/parse.js';
import { isClassFile, parseClass } from './jvm/classfile.js';
import { classDecl, methodDecl } from './jvm/disasm.js';
import { analyzeIpa, findAppRoot } from './ios/ipa.js';
import { isIl2cppMetadata, parseIl2cppMetadata } from './il2cpp.js';
import { isZip, openZip, readEntry } from './zip.js';

function meta(ctx: AnalyzerContext): Record<string, unknown> {
  const m = (ctx.report.meta.mobile ??= {}) as Record<string, unknown>;
  return m;
}

function looksLikeApk(ctx: AnalyzerContext): boolean {
  if (ctx.format === 'apk') return true;
  if (!isZip(ctx.bytes) || (ctx.format !== 'zip' && ctx.format !== 'jar')) return false;
  try { const z = openZip(ctx.bytes); return z.byName.has('AndroidManifest.xml') || z.byName.has('base/manifest/AndroidManifest.xml'); } catch { return false; }
}

export const mobileApkAnalyzer: Analyzer = {
  id: 'mobile-apk',
  title: 'Android APK',
  description: 'Decodes the binary manifest, APK signatures, DEX code, native libraries and app frameworks, and reports exported components, risky flags, sensitive API calls and hardcoded secrets.',
  applies: looksLikeApk,
  async run(ctx) {
    const rep = await analyzeApk(ctx.bytes, { deep: true });
    ctx.report.findings.push(...rep.findings);
    const m = rep.manifest;
    meta(ctx).apk = {
      kind: rep.kind,
      package: m?.package, versionName: m?.versionName, versionCode: m?.versionCode, minSdk: m?.minSdk, targetSdk: m?.targetSdk,
      label: m?.application.label, launcher: m?.launcherActivity,
      flags: m ? { debuggable: m.application.debuggable, allowBackup: m.application.allowBackup, usesCleartextTraffic: m.application.usesCleartextTraffic, networkSecurityConfig: m.application.networkSecurityConfigPath } : undefined,
      permissions: m?.permissions,
      components: m?.components.map((c) => ({ kind: c.kind, name: c.name, exported: c.exported, permission: c.permission })),
      deepLinks: m?.deepLinks,
      networkSecurityConfig: rep.networkSecurityConfig,
      signing: rep.signing ? {
        v1: rep.signing.v1.present, v2: rep.signing.v2.present, v3: rep.signing.v3.present, v31: rep.signing.v31.present,
        certificates: [...rep.signing.v1.certificates, ...rep.signing.v2.signers.flatMap((s) => s.certificates), ...rep.signing.v3.signers.flatMap((s) => s.certificates)]
          .filter((c, i, a) => a.findIndex((x) => x.sha256 === c.sha256) === i).map((c) => ({ subject: c.subject, issuer: c.issuer, serial: c.serial, sha256: c.sha256, notAfter: c.notAfter })),
      } : undefined,
      dex: rep.dex, abis: rep.abis,
      nativeLibs: rep.nativeLibs.map((l) => ({ path: l.path, size: l.size, jniOnLoad: l.elf?.jniOnLoad, jniExports: l.elf?.jniExports.length })),
      frameworks: rep.frameworks, libraries: rep.libraries, obfuscation: rep.obfuscation,
      apis: rep.apis.slice(0, 200), urls: rep.urls.slice(0, 300).map((u) => u.value), secrets: rep.secrets.slice(0, 50).map((s) => ({ kind: s.kind, value: s.value })),
      warnings: rep.warnings, manifestError: rep.manifestError,
    };
    for (const lib of rep.libraries) {
      ctx.report.components.push({ name: lib.name, ecosystem: 'maven', confidence: 0.6, evidence: [{ snippet: `${lib.classes} classes under ${lib.prefix}` }] });
    }
    for (const a of rep.apis) {
      const cap: { name: string; namespace: string; evidence: { snippet: string }[]; attack?: string } = { name: a.title, namespace: `android/${a.category}`, evidence: a.callers.slice(0, 3).map((c) => ({ snippet: c })) };
      ctx.report.capabilities.push(cap);
    }
  },
};

export const mobileDexAnalyzer: Analyzer = {
  id: 'mobile-dex',
  title: 'Android DEX',
  description: 'Parses DEX files: classes, methods, strings, libraries, obfuscation, sensitive API calls, URLs and keys.',
  applies: (ctx) => ctx.format === 'dex' || isDex(ctx.bytes),
  run(ctx) {
    const dexes = openDex(ctx.bytes, ctx.name);
    const classes = dexes.flatMap((d) => d.classes.map((c) => c.name));
    const findings: Finding[] = [];
    const apis: { id: string; target: string; callers: string[] }[] = [];
    const urls: string[] = [];
    const secrets: { kind: string; value: string }[] = [];
    for (const d of dexes) {
      const idx = xrefIndex(d);
      for (const h of sensitiveApis(idx)) {
        apis.push({ id: h.rule.id, target: h.target, callers: h.callers.map((c) => c.ref) });
        if (h.rule.severity !== 'info') findings.push({ id: `mobile.api.${h.rule.id}`, analyzer: 'mobile-dex', title: h.rule.title, severity: h.rule.severity, detail: `${h.target} called from ${h.callers.slice(0, 5).map((c) => c.ref).join(', ')}`, evidence: [], tags: ['android', 'dex', h.rule.category] });
      }
      const s = scanStrings(d, idx, 300);
      urls.push(...s.urls.map((u) => u.value));
      for (const x of s.secrets) {
        secrets.push({ kind: x.kind, value: x.value });
        findings.push({ id: `mobile.secret.${x.kind}`, analyzer: 'mobile-dex', title: `Hardcoded ${x.title}`, severity: x.severity as Finding['severity'], detail: `${x.value.slice(0, 12)}...`, evidence: [], tags: ['android', 'dex', 'secret'] });
      }
    }
    ctx.report.findings.push(...findings);
    meta(ctx).dex = {
      files: dexes.map((d) => ({ name: d.name, version: d.version, classes: d.classCount, methods: d.methodCount, strings: d.stringCount })),
      libraries: detectLibraries(classes), obfuscation: obfuscationHints(classes),
      nativeMethods: dexes.flatMap((d) => nativeMethods(d, 500)), apis, urls: urls.slice(0, 300), secrets,
    };
  },
};

export const mobileClassAnalyzer: Analyzer = {
  id: 'mobile-class',
  title: 'Java class file',
  description: 'Parses Java .class files: version, declaration, fields and methods.',
  applies: (ctx) => ctx.format === 'class' || isClassFile(ctx.bytes),
  run(ctx) {
    const cf = parseClass(ctx.bytes);
    meta(ctx).javaClass = {
      javaVersion: cf.javaVersion, major: cf.major, declaration: classDecl(cf), sourceFile: cf.sourceFile,
      methods: cf.methods.slice(0, 500).map((m) => methodDecl(cf, m)), fieldCount: cf.fields.length,
    };
  },
};

export const mobileIpaAnalyzer: Analyzer = {
  id: 'mobile-ipa',
  title: 'iOS IPA',
  description: 'Reads Info.plist, URL schemes, ATS, entitlements, embedded frameworks, extensions and the app framework of an IPA.',
  applies: (ctx) => {
    if (!isZip(ctx.bytes)) return false;
    try { return findAppRoot(openZip(ctx.bytes)) !== undefined; } catch { return false; }
  },
  async run(ctx) {
    const info = await analyzeIpa(ctx.bytes);
    const { infoPlist, ...rest } = info;
    void infoPlist;
    meta(ctx).ipa = rest;
    const P = `${info.appPath}Info.plist`;
    const add = (id: string, title: string, severity: Finding['severity'], detail: string): void => {
      ctx.report.findings.push({ id: `mobile.ios.${id}`, analyzer: 'mobile-ipa', title, severity, detail, evidence: [{ path: P }], tags: ['ios'] });
    };
    if (info.ats?.allowsArbitraryLoads) add('ats-arbitrary-loads', 'App Transport Security allows arbitrary loads', 'medium', 'NSAllowsArbitraryLoads is true, so plain HTTP is allowed everywhere.');
    for (const d of info.ats?.exceptionDomains ?? []) if (d.insecureHttp) add('ats-exception', `ATS exception allows HTTP to ${d.domain}`, 'low', `NSExceptionAllowsInsecureHTTPLoads for ${d.domain}${d.includesSubdomains ? ' and subdomains' : ''}.`);
    const ents = info.executableInfo?.entitlements as Record<string, unknown> | undefined;
    if (ents?.['get-task-allow'] === true) add('get-task-allow', 'Executable has get-task-allow (debuggable)', 'medium', 'The get-task-allow entitlement lets debuggers attach; it should be false in App Store builds.');
    if (info.executableInfo?.encrypted) add('encrypted', 'Main executable is FairPlay encrypted', 'info', 'cryptid is non-zero; static analysis of code needs a decrypted binary.');
    if (info.urlSchemes.length) add('url-schemes', `${info.urlSchemes.reduce((n, u) => n + u.schemes.length, 0)} custom URL scheme(s)`, 'info', info.urlSchemes.flatMap((u) => u.schemes).join(', '));
    // hand the main executable to core's Mach-O analyzer as a child report
    if (info.executablePath && ctx.analyzeChild && ctx.depth < 2) {
      try {
        const zip = openZip(ctx.bytes);
        const exe = await readEntry(zip, info.executablePath, 256 * 1024 * 1024);
        const child = await ctx.analyzeChild(exe, info.executablePath);
        (ctx.report.children ??= []).push(child);
      } catch { /* optional */ }
    }
  },
};

export const mobileIl2cppAnalyzer: Analyzer = {
  id: 'mobile-il2cpp',
  title: 'Unity IL2CPP metadata',
  description: 'Reads global-metadata.dat: version, images, type, method and string literal counts.',
  applies: (ctx) => isIl2cppMetadata(ctx.bytes),
  run(ctx) {
    const m = parseIl2cppMetadata(ctx.bytes);
    meta(ctx).il2cpp = { version: m.version, images: m.images, types: m.typeCount, methods: m.methodCount, literals: m.literalCount, warnings: m.warnings, sampleTypes: m.types(0, 50).items.map((t) => t.fullName) };
  },
};

export const ANALYZERS: Analyzer[] = [mobileApkAnalyzer, mobileDexAnalyzer, mobileClassAnalyzer, mobileIpaAnalyzer, mobileIl2cppAnalyzer];
