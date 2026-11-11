// The tool pages ("labs") for each RevLens package. Each lab lists its real sample files and the
// package tools it offers, with the few inputs each tool needs. Everything runs in the analysis worker.

export interface LabSample { id: string; file: string; label: string; note: string; tool?: string }
export interface LabField { key: string; label: string; placeholder?: string; kind?: 'text' | 'number' | 'bool' | 'select'; options?: string[]; def?: string }
export interface LabTool { tool: string; label: string; help: string; fields?: LabField[]; auto?: boolean }
export interface Lab {
  slug: string;
  title: string;
  eyebrow: string;
  summary: string;
  accepts: string;
  pkg: string;
  icon: 'cpu' | 'smartphone' | 'boxes' | 'braces' | 'atom' | 'network' | 'database';
  samples: LabSample[];
  tools: LabTool[];
}

const LIMIT: LabField = { key: 'limit', label: 'Limit', kind: 'number', def: '100' };

export const LABS: Lab[] = [
  {
    slug: 'disassembler', title: 'Disassembler', eyebrow: 'Native code', pkg: '@revlens/disasm', icon: 'cpu',
    summary: 'Open an ELF, PE or Mach-O file and read its functions, control flow graph and pseudo code. x86, x86-64, AArch64 and ARM decode in your browser with Capstone.',
    accepts: 'ELF, PE (.exe, .dll), Mach-O',
    samples: [
      { id: 'hello-x64-elf', file: 'disasm/hello-x64.elf', label: 'hello (x86-64 ELF)', note: 'A small C program built with clang for Linux.' },
      { id: 'hello-arm64-elf', file: 'disasm/hello-arm64.elf', label: 'hello (AArch64 ELF)', note: 'The same program for 64-bit ARM Linux.' },
      { id: 'hello-x64-exe', file: 'disasm/hello-x64.exe', label: 'hello.exe (x86-64 PE)', note: 'The same program as a Windows executable.' },
    ],
    tools: [],
  },
  {
    slug: 'mobile', title: 'Android, Java and iOS', eyebrow: 'Mobile apps', pkg: '@revlens/mobile', icon: 'smartphone',
    summary: 'Decode APK manifests and signatures, list DEX classes, read methods as smali, disassemble Java class files and read IPA plists and entitlements.',
    accepts: 'APK, DEX, JAR, .class, IPA',
    samples: [
      { id: 'apk', file: 'mobile/com.angrydoughnuts.android.alarmclock_27.apk', tool: 'mobile_apk_report', label: 'Alarm Clock APK', note: 'A small open source Android app from F-Droid.' },
      { id: 'dex', file: 'mobile/hello-035.dex', tool: 'mobile_dex_classes', label: 'hello.dex', note: 'A DEX file built with d8 from Hello.java.' },
      { id: 'class', file: 'mobile/Hello.class', tool: 'mobile_java_class', label: 'Hello.class', note: 'A Java class file built with javac.' },
      { id: 'ipa', file: 'mobile/Wikipedia-fixture.ipa', tool: 'mobile_ipa_info', label: 'Wikipedia IPA (trimmed)', note: 'Info.plist and signing data from the Wikipedia iOS app.' },
    ],
    tools: [
      { tool: 'mobile_apk_report', label: 'APK report', help: 'Manifest, signing, DEX, libraries, frameworks and findings.', auto: true },
      { tool: 'mobile_manifest', label: 'Manifest', help: 'The binary AndroidManifest.xml decoded to XML.', fields: [{ key: 'xml', label: 'Include XML', kind: 'bool', def: 'true' }] },
      { tool: 'mobile_signing', label: 'Signatures', help: 'APK signature schemes and signer certificates.' },
      { tool: 'mobile_dex_classes', label: 'DEX classes', help: 'Classes in every DEX file, filtered by name.', fields: [{ key: 'filter', label: 'Filter', placeholder: 'alarmclock' }, LIMIT] },
      { tool: 'mobile_dex_method', label: 'Smali', help: 'A class or one method as smali.', fields: [{ key: 'class', label: 'Class', placeholder: 'com.revlens.demo.Hello' }, { key: 'method', label: 'Method (optional)', placeholder: 'main' }] },
      { tool: 'mobile_dex_search', label: 'Search DEX', help: 'Find classes, methods, fields and strings.', fields: [{ key: 'query', label: 'Text', placeholder: 'http' }] },
      { tool: 'mobile_java_class', label: 'javap', help: 'A Java .class file as declarations and bytecode.' },
      { tool: 'mobile_ipa_info', label: 'IPA info', help: 'Info.plist, URL schemes, ATS, entitlements and frameworks.' },
      { tool: 'mobile_app_framework', label: 'App framework', help: 'Flutter, React Native, Unity, Xamarin and more.' },
    ],
  },
  {
    slug: 'managed', title: '.NET, Python, Lua, BEAM and EVM', eyebrow: 'Managed runtimes', pkg: '@revlens/managed', icon: 'boxes',
    summary: 'Read .NET metadata and CIL, Python bytecode and PyInstaller archives, Lua and LuaJIT chunks, Erlang and Elixir BEAM modules and EVM contract bytecode.',
    accepts: '.dll, .exe, .pyc, .luac, .beam, EVM hex',
    samples: [
      { id: 'dotnet', file: 'managed/System.IO.Compression.Brotli.dll', tool: 'managed_dotnet_info', label: '.NET Brotli assembly', note: 'System.IO.Compression.Brotli from .NET 8.' },
      { id: 'pyc', file: 'managed/sample_mod.3.12.pyc', tool: 'managed_pyc_disasm', label: 'Python 3.12 .pyc', note: 'A module compiled by CPython 3.12.' },
      { id: 'lua', file: 'managed/sample.5.4.luac', tool: 'managed_lua_info', label: 'Lua 5.4 chunk', note: 'Compiled by luac 5.4.' },
      { id: 'beam', file: 'managed/elixir_sup.beam', tool: 'managed_beam_info', label: 'elixir_sup.beam', note: 'A module from the Elixir standard library.' },
      { id: 'evm', file: 'managed/RevToken.runtime.hex', tool: 'managed_evm_selectors', label: 'ERC-20 runtime (EVM)', note: 'Runtime bytecode of a token contract built with solc.' },
    ],
    tools: [
      { tool: 'managed_dotnet_info', label: '.NET info', help: 'Assembly identity, framework, references, P/Invoke and resources.', auto: true },
      { tool: 'managed_dotnet_types', label: '.NET types', help: 'Types with their methods and fields.', fields: [{ key: 'filter', label: 'Filter', placeholder: 'Brotli' }, LIMIT] },
      { tool: 'managed_dotnet_method_il', label: 'CIL of a method', help: 'One method decoded to CIL with tokens resolved.', fields: [{ key: 'method', label: 'Method', placeholder: 'BrotliUtils.GetQualityFromCompressionLevel', def: 'BrotliUtils.GetQualityFromCompressionLevel' }] },
      { tool: 'managed_pyc_disasm', label: 'Python bytecode', help: 'Disassembly of every code object.', auto: true, fields: [LIMIT] },
      { tool: 'managed_lua_info', label: 'Lua chunk', help: 'Header, functions, constants and a listing.', auto: true, fields: [{ key: 'listing', label: 'Listing', kind: 'bool', def: 'true' }] },
      { tool: 'managed_beam_info', label: 'BEAM module', help: 'Chunks, atoms, exports and imports.', auto: true },
      { tool: 'managed_evm_selectors', label: 'EVM selectors', help: 'Function selectors with known signatures, proxies and metadata.', auto: true },
      { tool: 'managed_evm_disasm', label: 'EVM disassembly', help: 'Opcodes with offsets.', fields: [LIMIT] },
    ],
  },
  {
    slug: 'javascript', title: 'JavaScript', eyebrow: 'Web runtime', pkg: '@revlens/webrt', icon: 'braces',
    summary: 'Deobfuscate string arrays and proxies, split webpack and other bundles into modules, find API endpoints and recover sources from source maps.',
    accepts: '.js, .mjs, .map',
    samples: [
      { id: 'obfuscated', file: 'webrt/obfuscated.js', tool: 'web_js_deobfuscate', label: 'Obfuscated script', note: 'Output of javascript-obfuscator with a rotated string array.' },
      { id: 'bundle', file: 'webrt/bundle.prod.js', tool: 'web_bundle_modules', label: 'webpack 5 bundle', note: 'A production webpack build of a small app.' },
      { id: 'map', file: 'webrt/bundle.prod.js.map', tool: 'web_sourcemap_recover', label: 'Its source map', note: 'The map that names every module.' },
    ],
    tools: [
      { tool: 'web_js_deobfuscate', label: 'Deobfuscate', help: 'Decodes string arrays, inlines proxies and removes helpers.', auto: true },
      { tool: 'web_bundle_modules', label: 'Bundle modules', help: 'Bundler, modules, their ids, paths and imports.', fields: [{ key: 'includeCode', label: 'Include code', kind: 'bool' }] },
      { tool: 'web_js_endpoints', label: 'Endpoints', help: 'fetch, XHR, axios and WebSocket calls, hosts, env names and feature flags.' },
      { tool: 'web_js_beautify', label: 'Beautify', help: 'Readable formatting.' },
      { tool: 'web_sourcemap_recover', label: 'Source map', help: 'The original source tree and coverage from a .map file.', fields: [{ key: 'includeContent', label: 'Include sources', kind: 'bool' }] },
    ],
  },
  {
    slug: 'electron', title: 'Electron apps', eyebrow: 'Desktop apps', pkg: '@revlens/webrt', icon: 'atom',
    summary: 'List and read ASAR archives and audit Electron apps: web preferences, IPC handlers, preload scripts, navigation guards and fuses.',
    accepts: 'app.asar',
    samples: [{ id: 'asar', file: 'webrt/app.asar', tool: 'web_electron_audit', label: 'Demo app.asar', note: 'A small Electron app packed with @electron/asar.' }],
    tools: [
      { tool: 'web_electron_audit', label: 'Security audit', help: 'Findings with file paths and code snippets.', auto: true },
      { tool: 'web_asar_list', label: 'List files', help: 'Every entry with size, offset and integrity.', fields: [{ key: 'filter', label: 'Filter', placeholder: '.js' }] },
      { tool: 'web_asar_extract', label: 'Read a file', help: 'Show one file from the archive.', fields: [{ key: 'file', label: 'File', placeholder: 'main.js', def: 'main.js' }] },
    ],
  },
  {
    slug: 'network', title: 'PCAP and HAR', eyebrow: 'Network captures', pkg: '@revlens/webrt', icon: 'network',
    summary: 'Read packet captures and browser HAR files: flows, DNS, HTTP, TLS client hellos with JA3, hosts, API endpoints and missing security headers.',
    accepts: '.pcap, .pcapng, .har',
    samples: [
      { id: 'dns', file: 'webrt/dns_udp.pcap', tool: 'web_pcap_summary', label: 'DNS lookup (pcap)', note: 'A DNS query and answer from the tcpdump test suite.' },
      { id: 'tls', file: 'webrt/chrome-34-google.pcap', tool: 'web_pcap_summary', label: 'TLS to google.com (pcap)', note: 'A Chrome 34 client hello with a known JA3.' },
      { id: 'har', file: 'webrt/har-redirect.har', tool: 'web_har_summary', label: 'Redirect chain (HAR)', note: 'A HAR recorded by Playwright.' },
    ],
    tools: [
      { tool: 'web_pcap_summary', label: 'PCAP summary', help: 'Packets, protocols, DNS, HTTP and TLS with packet numbers.', auto: true },
      { tool: 'web_pcap_flows', label: 'PCAP flows', help: 'TCP and UDP conversations.', fields: [{ key: 'proto', label: 'Protocol', kind: 'select', options: ['', 'tcp', 'udp'] }] },
      { tool: 'web_har_summary', label: 'HAR summary', help: 'Hosts, endpoints, redirects and missing security headers.', auto: true },
    ],
  },
  {
    slug: 'sqlite', title: 'SQLite', eyebrow: 'App data', pkg: '@revlens/webrt', icon: 'database',
    summary: 'Open a SQLite database read only, see every table with its columns and row count, and run SELECT queries. The file is parsed in your browser.',
    accepts: '.sqlite, .db',
    samples: [{ id: 'db', file: 'webrt/fixture.sqlite', tool: 'web_sqlite_tables', label: 'Demo database', note: 'Built with Python sqlite3: users, notes and an index.' }],
    tools: [
      { tool: 'web_sqlite_tables', label: 'Tables', help: 'Tables, views and indexes with sample rows.', auto: true, fields: [{ key: 'samples', label: 'Sample rows', kind: 'number', def: '3' }] },
      { tool: 'web_sqlite_query', label: 'Query', help: 'Run one SELECT statement.', fields: [{ key: 'sql', label: 'SELECT', placeholder: 'SELECT * FROM users', def: 'SELECT * FROM users' }] },
    ],
  },
];

export const labBySlug = (slug: string | undefined): Lab | undefined => LABS.find((l) => l.slug === slug);

/** Turn form strings into tool arguments using each field's kind. */
export function argsFrom(fields: LabField[] | undefined, values: Record<string, string>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const f of fields ?? []) {
    const v = values[f.key] ?? f.def ?? '';
    if (f.kind === 'bool') { if (v === 'true') out[f.key] = true; continue; }
    if (v === '') continue;
    out[f.key] = f.kind === 'number' ? Number(v) : v;
  }
  return out;
}

export async function loadLabSample(s: LabSample): Promise<Uint8Array> {
  const r = await fetch(`${import.meta.env.BASE_URL}samples/${s.file}`);
  if (!r.ok) throw new Error(`Could not load the sample ${s.file} (HTTP ${r.status}).`);
  return new Uint8Array(await r.arrayBuffer());
}
