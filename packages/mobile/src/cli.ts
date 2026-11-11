// CLI commands. Each prints human text by default and JSON with --json.

import { mobileApkReport, mobileAppFramework, mobileDexClasses, mobileDexMethod, mobileDexSearch, mobileDexXrefs, mobileIl2cppTypes, mobileIpaInfo, mobileJavaClass, mobileManifest, mobileNativeLibs, mobileSigning } from './tools.js';

export interface CliCommand { name: string; usage: string; summary: string; run(argv: string[]): Promise<number> }

interface Parsed { file?: string; json: boolean; flags: Record<string, string | true> }

function parse(argv: string[]): Parsed {
  const out: Parsed = { json: false, flags: {} };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i] as string;
    if (a === '--json') out.json = true;
    else if (a.startsWith('--')) {
      const eq = a.indexOf('=');
      if (eq > 0) out.flags[a.slice(2, eq)] = a.slice(eq + 1);
      else {
        const next = argv[i + 1];
        if (next !== undefined && !next.startsWith('--')) { out.flags[a.slice(2)] = next; i++; } else out.flags[a.slice(2)] = true;
      }
    } else if (!out.file) out.file = a;
  }
  return out;
}

const str = (v: string | true | undefined): string | undefined => (typeof v === 'string' ? v : undefined);
const num = (v: string | true | undefined): number | undefined => (typeof v === 'string' && /^\d+$/.test(v) ? Number(v) : undefined);

type Out = (s: string) => void;
let write: Out = (s) => { (globalThis as { console: Console }).console.log(s); };
let writeErr: Out = (s) => { (globalThis as { console: Console }).console.error(s); };

/** Redirect CLI output (used by tests and embedding hosts). */
export function setCliOutput(out: Out, err?: Out): void { write = out; if (err) writeErr = err; }

function cmd(name: string, usage: string, summary: string, body: (p: Parsed & { file: string }) => Promise<{ data: unknown; text: () => string }>): CliCommand {
  return {
    name, usage, summary,
    async run(argv) {
      const p = parse(argv);
      if (!p.file || p.flags.help) { writeErr(`usage: ${usage}\n${summary}`); return p.flags.help ? 0 : 2; }
      try {
        const r = await body(p as Parsed & { file: string });
        write(p.json ? JSON.stringify(r.data, (_k, v) => (typeof v === 'bigint' ? v.toString() : v), 2) : r.text());
        return 0;
      } catch (err) {
        writeErr(`${name}: ${(err as Error).message}`);
        return 1;
      }
    },
  };
}

function table(rows: string[][]): string {
  const w: number[] = [];
  for (const r of rows) r.forEach((c, i) => { w[i] = Math.max(w[i] ?? 0, c.length); });
  return rows.map((r) => r.map((c, i) => (i === r.length - 1 ? c : c.padEnd(w[i] ?? 0))).join('  ')).join('\n');
}

export const CLI_COMMANDS: CliCommand[] = [
  cmd('apk', 'apk <file.apk> [--json] [--no-deep]', 'Triage an APK: manifest, signing, DEX, libraries, frameworks, APIs, URLs, secrets and findings.', async (p) => {
    const r = await mobileApkReport({ path: p.file, deep: !p.flags['no-deep'] });
    return {
      data: r,
      text: () => {
        const m = r.manifest;
        const lines = [
          `${m?.package ?? '?'} ${m?.versionName ?? ''} (${m?.versionCode ?? '?'})  minSdk ${m?.minSdk ?? '?'}  targetSdk ${m?.targetSdk ?? '?'}  ${r.kind}`,
          `label: ${m?.application.label ?? '?'}   launcher: ${m?.launcherActivity ?? '-'}`,
          `signing: v1=${r.signing?.v1.present} v2=${r.signing?.v2.present} v3=${r.signing?.v3.present}  cert sha256 ${r.signing?.certificateSha256[0] ?? '-'}`,
          `dex: ${r.dex.map((d) => `${d.name} v0${d.version} ${d.classes} classes`).join(', ') || 'none'}`,
          `abis: ${r.abis.join(', ') || 'none'}   frameworks: ${r.frameworks.map((f) => f.name).join(', ') || 'none detected'}`,
          `libraries: ${r.libraries.slice(0, 12).map((l) => l.name).join(', ') || 'none detected'}`,
          `permissions (${m?.permissions.length ?? 0}): ${m?.permissions.map((x) => `${x.name.replace('android.permission.', '')}${x.level === 'dangerous' ? '*' : ''}`).join(', ') ?? ''}`,
          '', `findings (${r.findings.length}):`,
          ...r.findings.map((f) => `  [${f.severity}] ${f.title}`),
        ];
        return lines.join('\n');
      },
    };
  }),
  cmd('manifest', 'manifest <file.apk|AndroidManifest.xml> [--xml] [--json]', 'Decode the binary AndroidManifest.xml.', async (p) => {
    const r = await mobileManifest({ path: p.file, xml: !!p.flags.xml });
    return {
      data: r,
      text: () => {
        if (p.flags.xml && r.xml) return (r.xml as { text: string }).text;
        const m = r.manifest as import('./manifest.js').ManifestInfo;
        const rows = m.components.map((c) => [c.kind, c.exported ? 'exported' : '-', c.permission ?? '', c.name]);
        return [`package ${m.package}  version ${m.versionName} (${m.versionCode})  sdk ${m.minSdk}..${m.targetSdk}`,
          `debuggable=${m.application.debuggable} allowBackup=${m.application.allowBackup} cleartext=${m.application.usesCleartextTraffic ?? 'default'}`,
          '', 'permissions:', ...m.permissions.map((x) => `  ${x.name}  [${x.level}] ${x.note}`),
          '', 'components:', table(rows.map((r2) => ['  ' + r2[0], ...r2.slice(1)] as string[])),
          ...(m.deepLinks.length ? ['', 'deep links:', ...m.deepLinks.map((d) => `  ${d.url}  -> ${d.component}`)] : [])].join('\n');
      },
    };
  }),
  cmd('apksig', 'apksig <file.apk> [--json]', 'Show APK signature schemes and signer certificates.', async (p) => {
    const r = await mobileSigning({ path: p.file });
    return {
      data: r,
      text: () => [`v1: ${r.v1.present}  v2: ${r.v2.present}  v3: ${r.v3.present}  v3.1: ${r.v31.present}  source stamp: ${r.sourceStamp}`,
        ...r.v1.certificates.map((c) => `v1 ${c.file}\n  subject ${c.subject}\n  issuer  ${c.issuer}\n  serial  ${c.serial}\n  sha256  ${c.sha256}\n  valid   ${c.notBefore} .. ${c.notAfter}`),
        ...r.v2.signers.flatMap((s) => s.certificates.map((c) => `v2 signer sha256 ${c.sha256}`)),
        ...r.v3.signers.flatMap((s) => s.certificates.map((c) => `v3 signer sha256 ${c.sha256} sdk ${s.minSdk}..${s.maxSdk}`)),
        ...(r.warnings.length ? ['warnings:', ...r.warnings] : [])].join('\n'),
    };
  }),
  cmd('dex', 'dex <file.apk|.dex> [--filter X] [--offset N] [--limit N] [--json]', 'List DEX files and classes.', async (p) => {
    const r = await mobileDexClasses({ path: p.file, filter: str(p.flags.filter), offset: num(p.flags.offset), limit: num(p.flags.limit) });
    return {
      data: r,
      text: () => [...r.dexFiles.map((d) => `${d.name}  dex ${d.version}  ${d.classes} classes  ${d.methods} methods  ${d.strings} strings`),
        `libraries: ${r.libraries.map((l) => `${l.name}(${l.classes})`).join(', ') || 'none'}`,
        `obfuscation: ${r.obfuscation.likelyObfuscated ? 'likely' : 'unlikely'} ${r.obfuscation.notes.join('; ')}`,
        '', ...r.classes.items.map((c) => `${c.java}  ${c.methods}m ${c.fields}f${c.super ? `  extends ${c.super}` : ''}`),
        `(${r.classes.offset}..${r.classes.offset + r.classes.items.length} of ${r.classes.total})`].join('\n'),
    };
  }),
  cmd('smali', 'smali <file.apk|.dex> --class C [--method M] [--lines] [--json]', 'Disassemble a class or method to smali.', async (p) => {
    const cls = str(p.flags.class);
    if (!cls) throw new Error('--class is required');
    const r = await mobileDexMethod({ path: p.file, class: cls, method: str(p.flags.method), lines: !!p.flags.lines });
    return { data: r, text: () => (typeof r.smali === 'string' ? r.smali : (r.methods ?? []).map((m) => `# ${m.dex}\n${m.smali}`).join('\n\n')) };
  }),
  cmd('dex-search', 'dex-search <file.apk|.dex> --query Q [--kinds class,method,field,string] [--json]', 'Search names and strings in DEX code.', async (p) => {
    const q = str(p.flags.query);
    if (!q) throw new Error('--query is required');
    const kinds = str(p.flags.kinds)?.split(',') as ('class' | 'method' | 'field' | 'string')[] | undefined;
    const r = await mobileDexSearch({ path: p.file, query: q, kinds, limit: num(p.flags.limit) });
    return { data: r, text: () => r.results.map((m) => `${m.kind.padEnd(6)} ${m.class}${m.name ? `->${m.name}${m.signature ?? ''}` : ''}${m.value !== undefined ? `  ${JSON.stringify(m.value)}` : ''}`).join('\n') || 'no matches' };
  }),
  cmd('xrefs', 'xrefs <file.apk|.dex> --target T [--kind method|field|string|type] [--direction to|from --class C] [--json]', 'Cross references in DEX code.', async (p) => {
    const t = str(p.flags.target);
    if (!t) throw new Error('--target is required');
    const r = await mobileDexXrefs({ path: p.file, target: t, kind: str(p.flags.kind) as 'method' | undefined, direction: str(p.flags.direction) as 'to' | undefined, class: str(p.flags.class), limit: num(p.flags.limit) });
    return {
      data: r,
      text: () => (r.methods ? r.methods.map((m) => [m.ref, ...m.references.map((x) => `  ${x.addr.toString(16).padStart(4, '0')} ${x.op} ${x.ref}`)].join('\n')).join('\n\n')
        : (r.matches ?? []).map((m) => [`${m.target}`, ...m.users.map((u) => `  <- ${u.ref}${u.write ? ' (write)' : ''}`)].join('\n')).join('\n') || 'no references'),
    };
  }),
  cmd('javap', 'javap <file.class|file.jar> [--class C] [--method M] [--json]', 'Disassemble Java bytecode like javap -c -p.', async (p) => {
    const r = await mobileJavaClass({ path: p.file, class: str(p.flags.class), method: str(p.flags.method), offset: num(p.flags.offset), limit: num(p.flags.limit) });
    return {
      data: r,
      text: () => {
        if ('javap' in r && typeof r.javap === 'string') return r.javap;
        if ('disassembly' in r && Array.isArray(r.disassembly)) return r.disassembly.join('\n\n');
        if (r.classes) return [`${r.classCount} classes${r.mainClass ? `, Main-Class ${r.mainClass}` : ''}`, ...r.classes.items.map((c) => `  ${c.path}`)].join('\n');
        return JSON.stringify(r, null, 2);
      },
    };
  }),
  cmd('ipa', 'ipa <file.ipa|Mach-O|plist> [--plist] [--json]', 'Summarize an iOS IPA.', async (p) => {
    const r = await mobileIpaInfo({ path: p.file, includeInfoPlist: !!p.flags.plist });
    return {
      data: r,
      text: () => {
        if (!('appPath' in r)) return JSON.stringify(r, null, 2);
        return [`${r.bundleId} ${r.version} (${r.build})  min iOS ${r.minimumOSVersion ?? '?'}  ${r.deviceFamily.join(', ')}`,
          `executable: ${r.executablePath ?? '?'}${r.executableInfo ? `  ${r.executableInfo.slices.map((s) => s.cpu).join(',')}  encrypted=${r.executableInfo.encrypted}` : ''}`,
          `url schemes: ${r.urlSchemes.flatMap((u) => u.schemes).join(', ') || 'none'}`,
          `ATS: ${r.ats ? `arbitraryLoads=${r.ats.allowsArbitraryLoads} exceptions=${r.ats.exceptionDomains.map((d) => d.domain).join(',') || 'none'}` : 'default'}`,
          `frameworks: ${r.frameworks.map((f) => f.name).join(', ') || 'none'}`,
          `app framework: ${r.appFrameworks.map((f) => f.name).join(', ') || 'native'}`,
          `privacy strings: ${r.privacyUsage.map((u) => u.key).join(', ') || 'none'}`,
          ...(r.warnings.length ? ['warnings:', ...r.warnings.map((w) => `  ${w}`)] : [])].join('\n');
      },
    };
  }),
  cmd('app-framework', 'app-framework <file.apk|file.ipa> [--json]', 'Detect Flutter, React Native, Xamarin, Unity and other frameworks.', async (p) => {
    const r = await mobileAppFramework({ path: p.file });
    return { data: r, text: () => r.frameworks.map((f) => `${f.name}  confidence ${f.confidence}\n${f.evidence.map((e) => `  ${e}`).join('\n')}${f.details ? `\n  ${JSON.stringify(f.details)}` : ''}`).join('\n') || 'no cross-platform framework detected' };
  }),
  cmd('il2cpp', 'il2cpp <global-metadata.dat|app.apk> [--what types|methods|literals|images|summary] [--filter X] [--json]', 'List IL2CPP metadata names.', async (p) => {
    const r = await mobileIl2cppTypes({ path: p.file, what: str(p.flags.what) as 'types' | undefined, filter: str(p.flags.filter), offset: num(p.flags.offset), limit: num(p.flags.limit) });
    return {
      data: r,
      text: () => {
        const head = `metadata v${r.version}  ${r.images} images  ${r.types} types  ${r.methods} methods  ${r.literals} literals`;
        const items = (r as { items?: unknown[] }).items ?? [];
        return [head, ...items.map((i) => {
          const x = i as { fullName?: string; name?: string; typeName?: string; value?: string };
          return `  ${x.fullName ?? (x.typeName ? `${x.typeName}::${x.name}` : x.value !== undefined ? JSON.stringify(x.value) : x.name)}`;
        })].join('\n');
      },
    };
  }),
  cmd('native-libs', 'native-libs <file.apk|lib.so> [--json]', 'List native libraries and JNI entry points.', async (p) => {
    const r = await mobileNativeLibs({ path: p.file });
    return {
      data: r,
      text: () => {
        if (!r.libraries) return JSON.stringify(r, null, 2);
        const out: string[] = [];
        for (const [abi, libs] of Object.entries(r.libraries)) {
          out.push(`${abi}:`);
          for (const l of libs) out.push(`  ${l.name}  ${l.size} bytes  JNI_OnLoad=${l.elf?.jniOnLoad ?? '?'}  Java_* exports=${l.elf?.jniExports.length ?? '?'}`);
        }
        out.push(`native methods in DEX: ${r.nativeMethods?.length ?? 0}, without static export: ${r.unresolvedNativeMethods}`);
        return out.join('\n');
      },
    };
  }),
];
