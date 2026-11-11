// Agent tool functions (mobile_*) and the TOOLS registry. Every output is JSON with evidence
// (archive paths, file offsets, DEX names) and paging so it stays small.

import { clampInt, ParseError } from './bytes.js';
import { analyzeApk, dexEntries, loadDexes, manifestXml, readManifest, readResources, type ApkReport } from './apk.js';
import { parseAxml, isAxml, axmlToXml } from './axml.js';
import { interpretManifest, interpretNetworkSecurityConfig } from './manifest.js';
import { apkSigning } from './signing.js';
import { allMethods, detectLibraries, findMethod, locOf, obfuscationHints, searchDex, xrefIndex, type MemberMatch } from './dex/analysis.js';
import { accessString, decodeCode, renderClass, renderMethod } from './dex/disasm.js';
import { isDex, openDex, toDescriptor, toJavaName, type DexFile } from './dex/parse.js';
import { isClassFile, parseClass, type ClassFile } from './jvm/classfile.js';
import { classDecl, decodeJvm, fieldDecl, javap, methodDecl, renderJvmCode } from './jvm/disasm.js';
import { analyzeIpa, findAppRoot, machoEntitlements } from './ios/ipa.js';
import { isMacho } from './ios/macho.js';
import { isBinaryPlist, parsePlist } from './ios/plist.js';
import { detectFrameworks, dartSnapshotInfo, reactNativeBundleInfo } from './framework.js';
import { isIl2cppMetadata, parseIl2cppMetadata, type Il2cppParsed } from './il2cpp.js';
import { isElf, parseElfDynamic } from './native.js';
import { loadInput, Lru, type LoadedInput } from './input.js';
import { isZip, openZip, readEntry, type ZipArchive } from './zip.js';
import { androidAppGraph, iosAppGraph, graphToMermaid, type AppGraph } from './graph.js';
import { scanJniLibrary, mapJni, type JniLibScan } from './jni.js';
import { compareDex } from './dex/compare.js';
import { nativeMethods } from './dex/analysis.js';
import { ABIS } from './native.js';

export interface ToolInputSpec { type: 'string' | 'number' | 'boolean' | 'array' | 'object'; description: string; optional?: boolean }
export interface Tool { name: string; description: string; inputSchema: Record<string, ToolInputSpec>; run: (input: any) => Promise<unknown> }

const MAX_LIMIT = 1000;

const zipCache = new Lru<ZipArchive>(4);
const dexCache = new Lru<DexFile[]>(4);
const il2cppCache = new Lru<Il2cppParsed>(2);

interface Opened { input: LoadedInput; zip?: ZipArchive }

async function open(input: { path?: unknown; base64?: unknown; bytes?: unknown }): Promise<Opened> {
  const li = await loadInput(input);
  if (isZip(li.bytes)) {
    let zip = zipCache.get(li.key);
    if (!zip) { zip = openZip(li.bytes); zipCache.set(li.key, zip); }
    return { input: li, zip };
  }
  return { input: li };
}

/** DEX files from an APK, AAB, JAR, ZIP of dex files, or a raw .dex. */
export async function dexesOf(input: { path?: unknown; base64?: unknown; bytes?: unknown }): Promise<DexFile[]> {
  const o = await open(input);
  const cached = dexCache.get(o.input.key);
  if (cached) return cached;
  let dexes: DexFile[];
  if (o.zip) dexes = await loadDexes(o.zip);
  else if (isDex(o.input.bytes)) dexes = openDex(o.input.bytes, o.input.name);
  else throw new ParseError('input is not an APK, AAB, JAR or DEX file');
  if (!dexes.length) throw new ParseError('no classes*.dex found in the archive');
  dexCache.set(o.input.key, dexes);
  return dexes;
}

function page<T>(items: T[], offset: unknown, limit: unknown, def = 100): { total: number; offset: number; limit: number; items: T[] } {
  const off = clampInt(offset, 0, 0, Number.MAX_SAFE_INTEGER);
  const lim = clampInt(limit, def, 1, MAX_LIMIT);
  return { total: items.length, offset: off, limit: lim, items: items.slice(off, off + lim) };
}

function capText(s: string, maxChars: number): { text: string; truncated: boolean } {
  return s.length > maxChars ? { text: `${s.slice(0, maxChars)}\n... truncated`, truncated: true } : { text: s, truncated: false };
}

// ------------------------------------------------------------------ tool functions

/** Decode AndroidManifest.xml from an APK (or a bare binary manifest) into structured data. */
export async function mobileManifest(input: { path?: string; base64?: string; xml?: boolean; maxXmlChars?: number }) {
  const o = await open(input);
  if (o.zip) {
    const table = await readResources(o.zip);
    const manifest = await readManifest(o.zip, table);
    let nsc;
    const p = manifest.application.networkSecurityConfigPath;
    if (p && o.zip.byName.has(p)) {
      try { nsc = interpretNetworkSecurityConfig(parseAxml(await readEntry(o.zip, p, 4 * 1024 * 1024))); } catch { /* optional */ }
    }
    const out: Record<string, unknown> = { file: o.input.name, evidence: { path: 'AndroidManifest.xml' }, manifest };
    if (nsc) out.networkSecurityConfig = { path: p, ...nsc };
    if (input.xml) out.xml = capText(await manifestXml(o.zip), clampInt(input.maxXmlChars, 200_000, 1000, 4_000_000));
    return out;
  }
  if (isAxml(o.input.bytes)) {
    const doc = parseAxml(o.input.bytes);
    const out: Record<string, unknown> = { file: o.input.name, manifest: interpretManifest(doc) };
    if (input.xml) out.xml = capText(axmlToXml(doc), clampInt(input.maxXmlChars, 200_000, 1000, 4_000_000));
    return out;
  }
  throw new ParseError('input is not an APK or a binary AndroidManifest.xml');
}

/** APK signature schemes (v1, v2, v3, v3.1) with signer certificate subject, issuer, serial and SHA-256. */
export async function mobileSigning(input: { path?: string; base64?: string }) {
  const o = await open(input);
  if (!o.zip) throw new ParseError('input is not an APK or JAR');
  return { file: o.input.name, ...(await apkSigning(o.zip)) };
}

/** List DEX files and classes with paging and a name filter. */
export async function mobileDexClasses(input: { path?: string; base64?: string; filter?: string; offset?: number; limit?: number }) {
  const dexes = await dexesOf(input);
  const f = input.filter?.toLowerCase();
  const rows: { dex: string; class: string; java: string; access: string; super?: string; interfaces: string[]; source?: string; methods: number; fields: number; offset: number }[] = [];
  for (const d of dexes) {
    for (const c of d.classes) {
      if (f && !c.name.toLowerCase().includes(f) && !toJavaName(c.name).toLowerCase().includes(f)) continue;
      let methods = 0, fields = 0;
      try { const cd = d.classData(c); methods = cd.directMethods.length + cd.virtualMethods.length; fields = cd.staticFields.length + cd.instanceFields.length; } catch { /* broken */ }
      const row: (typeof rows)[number] = { dex: d.name, class: c.name, java: toJavaName(c.name), access: accessString(c.access, 'c'), interfaces: c.interfaces, methods, fields, offset: c.offset };
      if (c.superclass) row.super = c.superclass;
      if (c.sourceFile) row.source = c.sourceFile;
      rows.push(row);
    }
  }
  const all = dexes.flatMap((d) => d.classes.map((c) => c.name));
  return {
    dexFiles: dexes.map((d) => ({ name: d.name, version: `0${d.version}`, size: d.header.fileSize, classes: d.classCount, methods: d.methodCount, fields: d.fieldCount, strings: d.stringCount, types: d.typeCount })),
    totalClasses: all.length,
    libraries: detectLibraries(all).slice(0, 50),
    obfuscation: obfuscationHints(all),
    classes: page(rows, input.offset, input.limit, 200),
  };
}

/** Disassemble a method (or a whole class when method is omitted) to smali text. */
export async function mobileDexMethod(input: { path?: string; base64?: string; class: string; method?: string; lines?: boolean; maxLines?: number }) {
  if (!input.class) throw new Error('class is required');
  const dexes = await dexesOf(input);
  const maxLines = clampInt(input.maxLines, 3000, 10, 50_000);
  if (!input.method) {
    for (const d of dexes) {
      const cd = d.classByName(input.class);
      if (cd) {
        const text = renderClass(d, cd, { lines: input.lines === true, maxLines });
        const lines = text.split('\n');
        return { dex: d.name, class: cd.name, classDefOffset: cd.offset, smali: lines.slice(0, maxLines).join('\n'), truncated: lines.length > maxLines };
      }
    }
    throw new Error(`class ${toDescriptor(input.class)} not found`);
  }
  const hits = findMethod(dexes, input.class, input.method);
  if (!hits.length) throw new Error(`method ${input.method} not found in ${toDescriptor(input.class)}`);
  return {
    methods: hits.slice(0, 20).map((h) => {
      const loc = locOf(h.dex, h.cd, h.m);
      const smali = renderMethod(h.dex, { classDef: h.cd, method: h.m, direct: h.direct }, { lines: input.lines === true, maxLines });
      const ci = h.dex.code(h.m.codeOff);
      return {
        dex: h.dex.name, ref: loc.ref, access: accessString(h.m.access, 'm'), codeOffset: h.m.codeOff || undefined,
        registers: ci?.registers, insnsUnits: ci?.insnsSize, smali,
      };
    }),
  };
}

/** Search class, method and field names and string constants (case-insensitive substring). */
export async function mobileDexSearch(input: { path?: string; base64?: string; query: string; kinds?: MemberMatch['kind'][]; limit?: number }) {
  if (!input.query || input.query.length > 512) throw new Error('query is required (max 512 chars)');
  const dexes = await dexesOf(input);
  const kinds = Array.isArray(input.kinds) && input.kinds.length ? input.kinds.filter((k) => ['class', 'method', 'field', 'string'].includes(k)) : undefined;
  const results = searchDex(dexes, input.query, kinds, clampInt(input.limit, 200, 1, MAX_LIMIT));
  return { query: input.query, count: results.length, results };
}

/**
 * Cross references. direction "to" (default) finds who calls a method, touches a field, uses a string or a type;
 * direction "from" lists what one method calls and touches.
 */
export async function mobileDexXrefs(input: { path?: string; base64?: string; target: string; kind?: 'method' | 'field' | 'string' | 'type'; direction?: 'to' | 'from'; class?: string; limit?: number }) {
  const dexes = await dexesOf(input);
  const limit = clampInt(input.limit, 200, 1, MAX_LIMIT);
  if (input.direction === 'from') {
    if (!input.class) throw new Error('class is required for direction "from" (target is the method name or name(sig))');
    const hits = findMethod(dexes, input.class, input.target);
    return {
      methods: hits.slice(0, 10).map((h) => {
        const ci = h.dex.code(h.m.codeOff);
        const calls: { addr: number; op: string; ref: string }[] = [];
        if (ci) for (const i of decodeCode(h.dex, ci)) {
          if (i.idx === undefined || i.op.ref === 'none') continue;
          const ref = i.op.ref === 'method' ? h.dex.methodRef(i.idx) : i.op.ref === 'field' ? h.dex.fieldRef(i.idx) : i.op.ref === 'string' ? JSON.stringify(h.dex.string(i.idx)) : i.op.ref === 'type' ? h.dex.type(i.idx) : `${i.op.ref}#${i.idx}`;
          calls.push({ addr: i.addr, op: i.op.name, ref });
          if (calls.length >= limit) break;
        }
        return { ref: locOf(h.dex, h.cd, h.m).ref, dex: h.dex.name, references: calls };
      }),
    };
  }
  if (!input.target) throw new Error('target is required');
  const kind = input.kind ?? (input.target.includes('->') && input.target.includes('(') ? 'method' : input.target.includes('->') ? 'field' : 'string');
  const out: { target: string; dex: string; users: { ref: string; write?: boolean }[] }[] = [];
  let total = 0;
  for (const d of dexes) {
    const idx = xrefIndex(d);
    if (kind === 'method') {
      for (const [ref, callers] of idx.calls) if (ref.includes(input.target)) { out.push({ target: ref, dex: d.name, users: callers.slice(0, limit).map((c) => ({ ref: c.ref })) }); total += callers.length; }
    } else if (kind === 'field') {
      for (const [ref, users] of idx.fields) if (ref.includes(input.target)) { out.push({ target: ref, dex: d.name, users: users.slice(0, limit).map((u) => ({ ref: u.loc.ref, write: u.write })) }); total += users.length; }
    } else if (kind === 'type') {
      const desc = input.target.includes('/') || input.target.startsWith('L') ? input.target : toDescriptor(input.target);
      for (const [t, users] of idx.types) if (t.includes(desc)) { out.push({ target: t, dex: d.name, users: users.slice(0, limit).map((u) => ({ ref: u.ref })) }); total += users.length; }
    } else {
      for (const [s, users] of idx.strings) if (s.includes(input.target)) { out.push({ target: s, dex: d.name, users: users.slice(0, limit).map((u) => ({ ref: u.ref })) }); total += users.length; }
    }
    if (out.length >= limit) break;
  }
  return { kind, query: input.target, matches: out.slice(0, limit), totalReferences: total };
}

/** Parse a Java .class (or a class inside a JAR) and disassemble it javap -c -p style. */
export async function mobileJavaClass(input: { path?: string; base64?: string; class?: string; method?: string; offset?: number; limit?: number; maxLines?: number }) {
  const o = await open(input);
  let cf: ClassFile;
  let member: string | undefined;
  if (o.zip) {
    const classes = o.zip.entries.filter((e) => e.name.endsWith('.class'));
    if (!input.class) {
      const mf = o.zip.byName.get('META-INF/MANIFEST.MF');
      let mainClass: string | undefined;
      if (mf) { try { const t = new TextDecoder().decode(await readEntry(o.zip, mf, 1 << 20)); mainClass = /^Main-Class:\s*(\S+)/m.exec(t)?.[1]; } catch { /* ignore */ } }
      return { file: o.input.name, mainClass, classCount: classes.length, classes: page(classes.map((e) => ({ path: e.name, size: e.size })), input.offset, input.limit, 200) };
    }
    const want = input.class.replace(/\./g, '/').replace(/\.class$/, '');
    const e = o.zip.byName.get(`${want}.class`) ?? classes.find((x) => x.name.endsWith(`/${want}.class`));
    if (!e) throw new Error(`class ${input.class} not found in archive`);
    member = e.name;
    cf = parseClass(await readEntry(o.zip, e, 64 * 1024 * 1024));
  } else if (isClassFile(o.input.bytes)) cf = parseClass(o.input.bytes);
  else throw new ParseError('input is not a .class file or a JAR');
  const maxLines = clampInt(input.maxLines, 4000, 10, 100_000);
  const info = {
    file: o.input.name, member, javaVersion: cf.javaVersion, major: cf.major, minor: cf.minor, declaration: classDecl(cf), sourceFile: cf.sourceFile,
    fields: cf.fields.map((f) => fieldDecl(cf, f)),
    methods: cf.methods.map((m) => ({ declaration: methodDecl(cf, m), name: m.name, descriptor: m.descriptor, codeLength: m.code?.codeLen, maxStack: m.code?.maxStack, maxLocals: m.code?.maxLocals, codeOffset: m.code?.codeOff })),
  };
  if (input.method) {
    const ms = cf.methods.filter((m) => m.name === input.method || `${m.name}${m.descriptor}` === input.method);
    if (!ms.length) throw new Error(`method ${input.method} not found`);
    return { ...info, disassembly: ms.map((m) => [`  ${methodDecl(cf, m)}`, ...renderJvmCode(cf, m)].join('\n')), calls: ms.flatMap((m) => decodeJvm(cf, m).filter((i) => i.comment?.startsWith('Method') || i.comment?.startsWith('InterfaceMethod')).map((i) => ({ pc: i.pc, op: i.name, ref: i.comment }))).slice(0, 500) };
  }
  const text = javap(cf);
  const lines = text.split('\n');
  return { ...info, javap: lines.slice(0, maxLines).join('\n'), truncated: lines.length > maxLines };
}

/** iOS IPA summary: Info.plist essentials, URL schemes, ATS, entitlements, frameworks, extensions. */
export async function mobileIpaInfo(input: { path?: string; base64?: string; includeInfoPlist?: boolean }) {
  const o = await open(input);
  if (o.zip) {
    const info = await analyzeIpa(o.zip);
    const { infoPlist, ...rest } = info;
    return input.includeInfoPlist ? { file: o.input.name, ...rest, infoPlist } : { file: o.input.name, ...rest };
  }
  if (isMacho(o.input.bytes)) return { file: o.input.name, slices: machoEntitlements(o.input.bytes) };
  if (isBinaryPlist(o.input.bytes) || /^\s*<\?xml|^\s*<plist/.test(new TextDecoder().decode(o.input.bytes.subarray(0, 256)))) return { file: o.input.name, plist: parsePlist(o.input.bytes) };
  throw new ParseError('input is not an IPA, Mach-O or plist');
}

/** Detect Flutter, React Native, Xamarin/.NET, Unity, Cordova and other app frameworks in an APK or IPA. */
export async function mobileAppFramework(input: { path?: string; base64?: string }) {
  const o = await open(input);
  if (!o.zip) throw new ParseError('input is not an APK, AAB or IPA archive');
  const root = findAppRoot(o.zip);
  if (root) {
    const names = o.zip.entries.map((e) => e.name).filter((n) => n.startsWith(root));
    const hits = detectFrameworks(names);
    const fl = hits.find((h) => h.id === 'flutter');
    const appBin = `${root}Frameworks/App.framework/App`;
    if (fl && o.zip.byName.has(appBin)) { try { fl.details = { ...dartSnapshotInfo(await readEntry(o.zip, appBin, 256 * 1024 * 1024)), binary: appBin }; } catch { /* optional */ } }
    const rn = hits.find((h) => h.id === 'react-native');
    if (rn && o.zip.byName.has(`${root}main.jsbundle`)) { try { rn.details = { bundle: `${root}main.jsbundle`, ...reactNativeBundleInfo(await readEntry(o.zip, `${root}main.jsbundle`, 256 * 1024 * 1024)) }; } catch { /* optional */ } }
    return { file: o.input.name, platform: 'ios', frameworks: hits };
  }
  const rep = await analyzeApk(o.zip, { deep: false, nativeExports: false });
  return { file: o.input.name, platform: 'android', kind: rep.kind, frameworks: rep.frameworks, abis: rep.abis, libraries: rep.libraries.slice(0, 40) };
}

/** List IL2CPP images, types, methods or string literals from global-metadata.dat (bare or inside an APK/IPA). */
export async function mobileIl2cppTypes(input: { path?: string; base64?: string; what?: 'summary' | 'types' | 'methods' | 'literals' | 'images'; filter?: string; offset?: number; limit?: number }) {
  const o = await open(input);
  let meta = il2cppCache.get(o.input.key);
  let member: string | undefined;
  if (!meta) {
    let bytes: Uint8Array | undefined;
    if (o.zip) {
      const e = o.zip.entries.find((x) => x.name.endsWith('Managed/Metadata/global-metadata.dat'));
      if (!e) throw new Error('no global-metadata.dat in this archive (not a Unity IL2CPP app, or metadata is encrypted or renamed)');
      member = e.name;
      bytes = await readEntry(o.zip, e, 512 * 1024 * 1024);
    } else bytes = o.input.bytes;
    if (!isIl2cppMetadata(bytes)) throw new ParseError('global-metadata.dat has a bad magic, it may be encrypted');
    meta = parseIl2cppMetadata(bytes);
    il2cppCache.set(o.input.key, meta);
  }
  const off = clampInt(input.offset, 0, 0, Number.MAX_SAFE_INTEGER);
  const lim = clampInt(input.limit, 200, 1, MAX_LIMIT);
  const summary = { file: o.input.name, member, version: meta.version, images: meta.images.length, types: meta.typeCount, methods: meta.methodCount, literals: meta.literalCount, strides: meta.strides, warnings: meta.warnings };
  switch (input.what ?? 'types') {
    case 'summary': return { ...summary, sections: meta.sections };
    case 'images': return { ...summary, items: meta.images.slice(off, off + lim) };
    case 'methods': return { ...summary, ...meta.methods(off, lim, input.filter) };
    case 'literals': return { ...summary, ...meta.literals(off, lim, input.filter) };
    default: return { ...summary, ...meta.types(off, lim, input.filter) };
  }
}

/** Native libraries per ABI with JNI_OnLoad and Java_* exports, or one .so file. */
export async function mobileNativeLibs(input: { path?: string; base64?: string; exports?: boolean; limit?: number }) {
  const o = await open(input);
  if (!o.zip) {
    if (!isElf(o.input.bytes)) throw new ParseError('input is not an APK or ELF file');
    const e = parseElfDynamic(o.input.bytes);
    return { file: o.input.name, ...e, exports: input.exports ? e.exports.slice(0, clampInt(input.limit, 500, 1, 20_000)) : undefined, exportCount: e.exports.length, imports: e.imports.slice(0, 200) };
  }
  const rep = await analyzeApk(o.zip, { deep: false });
  const byAbi: Record<string, typeof rep.nativeLibs> = {};
  for (const l of rep.nativeLibs) (byAbi[l.abi] ??= []).push(l);
  return { file: o.input.name, abis: rep.abis, libraries: byAbi, nativeMethods: rep.nativeMethods.slice(0, 500), unresolvedNativeMethods: rep.unresolvedNativeMethods };
}

/** One-shot APK triage: manifest, signing, DEX stats, libraries, frameworks, sensitive APIs, URLs, secrets and findings. */
export async function mobileApkReport(input: { path?: string; base64?: string; deep?: boolean; limit?: number }): Promise<Omit<ApkReport, 'urls' | 'secrets' | 'apis'> & { urls: unknown[]; secrets: unknown[]; apis: unknown[] }> {
  const o = await open(input);
  if (!o.zip) throw new ParseError('input is not an APK archive');
  const rep = await analyzeApk(o.zip, { deep: input.deep !== false });
  const lim = clampInt(input.limit, 100, 1, MAX_LIMIT);
  return {
    ...rep,
    urls: rep.urls.slice(0, lim).map((u) => ({ value: u.value, users: u.users.slice(0, 3).map((x) => x.ref) })),
    secrets: rep.secrets.slice(0, lim).map((s) => ({ kind: s.kind, title: s.title, severity: s.severity, value: s.value, users: s.users.slice(0, 3).map((x) => x.ref) })),
    apis: rep.apis.slice(0, lim),
  };
}

function pageGraph(g: AppGraph, input: { mermaid?: boolean; offset?: number; limit?: number; maxMermaidNodes?: number }) {
  return {
    platform: g.platform, app: g.app, stats: g.stats, truncated: g.truncated,
    nodes: page(g.nodes, input.offset, input.limit, 500), edges: page(g.edges, input.offset, input.limit, 500),
    mermaid: input.mermaid === false ? undefined : graphToMermaid(g, { maxNodes: clampInt(input.maxMermaidNodes, 300, 10, 5000) }),
  };
}

/** Android application graph: components, intent filters, exported state, deep links, providers and permissions as nodes and edges, plus Mermaid. */
export async function mobileAppGraph(input: { path?: string; base64?: string; mermaid?: boolean; dex?: boolean; offset?: number; limit?: number; maxMermaidNodes?: number }) {
  const o = await open(input);
  if (!o.zip) throw new ParseError('input is not an APK archive');
  const table = await readResources(o.zip);
  const manifest = await readManifest(o.zip, table);
  let dexes: DexFile[] = [];
  if (input.dex !== false && dexEntries(o.zip).length) { try { dexes = await dexesOf(input); } catch { dexes = []; } }
  return { file: o.input.name, ...pageGraph(androidAppGraph(manifest, dexes), input) };
}

/** iOS bundle graph: app, executables, extensions, frameworks, linked libraries, entitlements, URL schemes and associated domains, plus Mermaid. */
export async function mobileIpaGraph(input: { path?: string; base64?: string; mermaid?: boolean; offset?: number; limit?: number; maxMermaidNodes?: number }) {
  const o = await open(input);
  if (!o.zip || !findAppRoot(o.zip)) throw new ParseError('input is not an IPA archive');
  return { file: o.input.name, ...pageGraph(await iosAppGraph(o.zip), input) };
}

/** JNI map: DEX native methods to Java_* exports, RegisterNatives JNINativeMethod tables and string hints in each lib/<abi>/*.so. */
export async function mobileJniMap(input: { path?: string; base64?: string; abi?: string; limit?: number; offset?: number }) {
  const o = await open(input);
  if (!o.zip) {
    if (!isElf(o.input.bytes)) throw new ParseError('input is not an APK or ELF file');
    const scan = scanJniLibrary(o.input.bytes);
    return { file: o.input.name, library: { ...scan, tables: scan.tables.slice(0, 200), classHints: scan.classHints.slice(0, 500), signatureHints: scan.signatureHints.slice(0, 500) } };
  }
  const methods = dexEntries(o.zip).length ? (await dexesOf(input)).flatMap((d) => nativeMethods(d, 20000)) : [];
  const libs: { abi: string; path: string; scan: JniLibScan }[] = [];
  const errors: { path: string; error: string }[] = [];
  for (const e of o.zip.entries) {
    const m = /^lib\/([^/]+)\/([^/]+\.so)$/.exec(e.name);
    if (!m || (input.abi && m[1] !== input.abi) || !ABIS.includes(m[1]!) || libs.length >= 400) continue;
    try { libs.push({ abi: m[1]!, path: e.name, scan: scanJniLibrary(await readEntry(o.zip, e, 256 * 1024 * 1024)) }); } catch (err) { errors.push({ path: e.name, error: (err as Error).message }); }
  }
  const map = mapJni(methods, libs);
  return {
    file: o.input.name, nativeMethods: methods.length, libraries: libs.map((l) => ({ abi: l.abi, path: l.path, machine: l.scan.machine, bits: l.scan.bits, jniOnLoad: l.scan.jniOnLoad, javaExports: l.scan.javaExports.length, tables: l.scan.tables.slice(0, 50), classHints: l.scan.classHints.slice(0, 100), signatureHints: l.scan.signatureHints.slice(0, 100) })),
    methods: page(map.methods, input.offset, input.limit, 200), unresolved: map.unresolved.map((x) => `${x.class}.${x.method}${x.signature}`), orphanExports: map.orphanExports.slice(0, 500), errors,
  };
}

/** Member diff between two DEX sets (APK, JAR or .dex): classes, methods, fields, access flags, hierarchy, optional smali body changes. */
export async function mobileCompareMembers(input: { path?: string; base64?: string; otherPath?: string; otherBase64?: string; bodies?: boolean; filter?: string; offset?: number; limit?: number }) {
  if (!input.otherPath && !input.otherBase64) throw new ParseError('otherPath or otherBase64 is required');
  const a = await dexesOf(input);
  const b = await dexesOf({ path: input.otherPath, base64: input.otherBase64 });
  const d = compareDex(a, b, { bodies: input.bodies, filter: input.filter });
  return { ...d, changes: page(d.changes, input.offset, input.limit, 100) };
}

const PATH: ToolInputSpec = { type: 'string', description: 'File path (Node only). Use base64 instead in a browser.', optional: true };
const B64: ToolInputSpec = { type: 'string', description: 'File bytes as base64, instead of path.', optional: true };
const OFFSET: ToolInputSpec = { type: 'number', description: 'Paging offset, default 0.', optional: true };
const LIMIT: ToolInputSpec = { type: 'number', description: 'Max items, default 100 to 200, max 1000.', optional: true };

export const TOOLS: Tool[] = [
  { name: 'mobile_manifest', description: 'Decode AndroidManifest.xml (binary AXML) from an APK: package, versions, SDK levels, permissions with risk notes, activities, services, receivers and providers with exported state and intent filters, deep links, debuggable, allowBackup, cleartext and network security config. Set xml=true for the decoded XML text.', inputSchema: { path: PATH, base64: B64, xml: { type: 'boolean', description: 'Also return the decoded XML text.', optional: true }, maxXmlChars: { type: 'number', description: 'Cap for the XML text, default 200000.', optional: true } }, run: mobileManifest },
  { name: 'mobile_signing', description: 'APK signing: v1 JAR signature files and certificates (subject, issuer, serial, SHA-256), APK Signing Block ids, v2/v3/v3.1 signers with certificate digests, min/max SDK and algorithms. Reports presence, does not verify.', inputSchema: { path: PATH, base64: B64 }, run: mobileSigning },
  { name: 'mobile_dex_classes', description: 'List DEX files (all versions 035 to 041, multidex) and their classes with access flags, superclass, interfaces, method and field counts, detected libraries and obfuscation hints. Works on APK, AAB, JAR or raw .dex.', inputSchema: { path: PATH, base64: B64, filter: { type: 'string', description: 'Case-insensitive class name filter.', optional: true }, offset: OFFSET, limit: LIMIT }, run: mobileDexClasses },
  { name: 'mobile_dex_method', description: 'Disassemble a DEX method to smali (baksmali compatible). Give class (com.a.B or Lcom/a/B;) and method name, optionally with signature like add(II)I. Omit method to get the whole class.', inputSchema: { path: PATH, base64: B64, class: { type: 'string', description: 'Class name, Java or descriptor form.' }, method: { type: 'string', description: 'Method name or name(sig)ret.', optional: true }, lines: { type: 'boolean', description: 'Include .line directives from debug info.', optional: true }, maxLines: { type: 'number', description: 'Output line cap, default 3000.', optional: true } }, run: mobileDexMethod },
  { name: 'mobile_dex_search', description: 'Search DEX class, method and field names and string constants (case-insensitive substring). String hits include the methods that use them.', inputSchema: { path: PATH, base64: B64, query: { type: 'string', description: 'Text to find.' }, kinds: { type: 'array', description: 'Subset of class, method, field, string.', optional: true }, limit: LIMIT }, run: mobileDexSearch },
  { name: 'mobile_dex_xrefs', description: 'DEX cross references. direction "to": who calls a method (target like Ljava/lang/Class;->forName or just forName with kind=method), touches a field, uses a string or type. direction "from": what a method (class + target name) calls and references.', inputSchema: { path: PATH, base64: B64, target: { type: 'string', description: 'Method, field, string or type to look up (substring), or the method name for direction from.' }, kind: { type: 'string', description: 'method, field, string or type. Guessed when omitted.', optional: true }, direction: { type: 'string', description: 'to (default) or from.', optional: true }, class: { type: 'string', description: 'Class of the method, for direction from.', optional: true }, limit: LIMIT }, run: mobileDexXrefs },
  { name: 'mobile_java_class', description: 'Parse a Java .class file or a class inside a JAR and disassemble it like javap -c -p. Without class on a JAR, lists members and Main-Class.', inputSchema: { path: PATH, base64: B64, class: { type: 'string', description: 'Class inside a JAR, like com/a/B or com.a.B.', optional: true }, method: { type: 'string', description: 'Only this method (name or name+descriptor).', optional: true }, offset: OFFSET, limit: LIMIT, maxLines: { type: 'number', description: 'Line cap for javap text.', optional: true } }, run: mobileJavaClass },
  { name: 'mobile_ipa_info', description: 'iOS IPA: Info.plist (binary or XML) essentials, URL schemes, ATS settings, privacy usage strings, embedded frameworks and app extensions, provisioning profile, main executable path, encryption state, code signing identifier, team id and entitlements. Also accepts a bare Mach-O or plist.', inputSchema: { path: PATH, base64: B64, includeInfoPlist: { type: 'boolean', description: 'Return the full Info.plist too.', optional: true } }, run: mobileIpaInfo },
  { name: 'mobile_app_framework', description: 'Detect the app framework of an APK or IPA: Flutter (with Dart snapshot hash), React Native (Hermes or JS bundle), Xamarin/.NET MAUI, Unity IL2CPP or Mono, Cordova, Capacitor, Godot, Qt, Cocos2d-x, Unreal, libGDX, NativeActivity.', inputSchema: { path: PATH, base64: B64 }, run: mobileAppFramework },
  { name: 'mobile_il2cpp_types', description: 'Unity IL2CPP global-metadata.dat (bare file or inside an APK/IPA): metadata version, images, and paged type names, method names (with declaring type) or string literals. what = summary, images, types, methods or literals.', inputSchema: { path: PATH, base64: B64, what: { type: 'string', description: 'summary, images, types (default), methods or literals.', optional: true }, filter: { type: 'string', description: 'Case-insensitive substring filter.', optional: true }, offset: OFFSET, limit: LIMIT }, run: mobileIl2cppTypes },
  { name: 'mobile_native_libs', description: 'Native libraries in an APK per ABI (lib/<abi>/*.so) with soname, needed libraries, JNI_OnLoad and Java_* exports, plus DEX native methods and how many lack a static JNI export. Also accepts a single .so.', inputSchema: { path: PATH, base64: B64, exports: { type: 'boolean', description: 'For a single .so, list all exported symbols.', optional: true }, limit: LIMIT }, run: mobileNativeLibs },
  { name: 'mobile_app_graph', description: 'Android application graph from an APK: the app, activities, aliases, services, receivers and providers with exported state and why, intent filter actions, deep links, provider authorities, used, defined and required permissions, and an external caller node for the exported attack surface. Nodes and edges (paged) plus a Mermaid flowchart.', inputSchema: { path: PATH, base64: B64, mermaid: { type: 'boolean', description: 'Include Mermaid text (default true).', optional: true }, dex: { type: 'boolean', description: 'Check that component classes exist in DEX (default true).', optional: true }, maxMermaidNodes: { type: 'number', description: 'Node cap for the Mermaid text, default 300.', optional: true }, offset: OFFSET, limit: LIMIT }, run: mobileAppGraph },
  { name: 'mobile_ipa_graph', description: 'iOS bundle graph from an IPA: app, main and nested executables (CPU, team id), app extensions with extension points, embedded frameworks and dylibs with link edges from load commands, system libraries, entitlements per executable, URL schemes, queried schemes, associated domains, privacy usage keys and ATS exceptions. Nodes and edges plus Mermaid.', inputSchema: { path: PATH, base64: B64, mermaid: { type: 'boolean', description: 'Include Mermaid text (default true).', optional: true }, maxMermaidNodes: { type: 'number', description: 'Node cap for the Mermaid text, default 300.', optional: true }, offset: OFFSET, limit: LIMIT }, run: mobileIpaGraph },
  { name: 'mobile_jni_map', description: 'Map DEX native methods to native code: Java_* exports (short and overloaded long names), JNINativeMethod tables recovered from .so data through RELATIVE, ABS and RELR relocations (what JNI_OnLoad passes to RegisterNatives) with function addresses, and FindClass class path and JNI signature string hints. Lists unresolved methods and Java_* exports with no Java declaration. Accepts an APK or one .so.', inputSchema: { path: PATH, base64: B64, abi: { type: 'string', description: 'Only this ABI, like arm64-v8a.', optional: true }, offset: OFFSET, limit: LIMIT }, run: mobileJniMap },
  { name: 'mobile_compare_members', description: 'Diff classes, methods and fields between two DEX sets (two APK versions, JARs or .dex files): added and removed classes and members, access flag changes, superclass and interface changes, and with bodies=true methods whose smali changed (index renumbering ignored).', inputSchema: { path: PATH, base64: B64, otherPath: { type: 'string', description: 'Second file path (the newer version).', optional: true }, otherBase64: { type: 'string', description: 'Second file as base64.', optional: true }, bodies: { type: 'boolean', description: 'Also compare method bodies as rendered smali.', optional: true }, filter: { type: 'string', description: 'Only classes whose name contains this text.', optional: true }, offset: OFFSET, limit: LIMIT }, run: mobileCompareMembers },
  { name: 'mobile_apk_report', description: 'One-shot APK triage: manifest, signing, DEX stats, libraries, frameworks, native libs, sensitive API calls with callers, hardcoded URLs and keys, and security findings.', inputSchema: { path: PATH, base64: B64, deep: { type: 'boolean', description: 'Build DEX cross references for API, URL and key findings (default true).', optional: true }, limit: LIMIT }, run: mobileApkReport },
];

void allMethods;
void dexEntries;
