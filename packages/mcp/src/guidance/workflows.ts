// Guided workflows: ordered tool plans for common reverse engineering jobs. Rendering one fills in the
// caller's arguments and returns guidance only; it never reads a target or starts analysis.

export interface WorkflowArgument { name: string; description: string; required: boolean }
export interface WorkflowStep { tool: string; why: string; input?: Record<string, string> }
export interface GuidedWorkflow {
  id: string;
  title: string;
  description: string;
  /** formats this workflow fits, as analyze_file reports them */
  formats: string[];
  /** playbook to read alongside, relative to docs/ */
  playbook?: string;
  arguments: WorkflowArgument[];
  steps: WorkflowStep[];
  /** what a good final answer contains */
  deliverable: string;
}

const PATH: WorkflowArgument = { name: 'path', description: 'path to the file under study', required: true };

export const WORKFLOWS: GuidedWorkflow[] = [
  {
    id: 'triage_unknown_file', title: 'Triage an unknown file', formats: ['*'],
    description: 'First look at any file: what it is, how risky it is, and which deep tools to use next.',
    arguments: [PATH], deliverable: 'Format, hashes, top risks with evidence offsets, and the next tools to run.',
    steps: [
      { tool: 'analyze_file', why: 'format, hashes, hardening, components and top findings', input: { path: '{path}' } },
      { tool: 'discover_tools', why: 'the small set of tools that fit this format', input: { format: '<format from analyze_file>' } },
      { tool: 'guidance', why: 'the playbook for the format', input: { format: '<format from analyze_file>' } },
      { tool: 'list_findings', why: 'every finding at medium or above', input: { path: '{path}', minSeverity: 'medium' } },
      { tool: 'verify_claim', why: 'check each claim before reporting it', input: { path: '{path}' } },
    ],
  },
  {
    id: 'native_function_deep_dive', title: 'Explain a native function', formats: ['elf', 'pe', 'macho', 'macho-fat'], playbook: 'playbooks/elf.md',
    description: 'Read one function in a native binary: disassembly, pseudo code, callers, callees and constant arguments.',
    arguments: [PATH, { name: 'function', description: 'function name or 0x address', required: true }],
    deliverable: 'What the function does, its inputs and outputs, side effects, and the addresses that show each point.',
    steps: [
      { tool: 'disasm_info', why: 'architecture, entry point and function count', input: { path: '{path}' } },
      { tool: 'disasm_pseudocode', why: 'readable C like view', input: { path: '{path}', function: '{function}' } },
      { tool: 'disasm_function', why: 'exact instructions and basic blocks', input: { path: '{path}', function: '{function}' } },
      { tool: 'disasm_xrefs', why: 'who calls it and what it calls', input: { path: '{path}', target: '{function}' } },
      { tool: 'disasm_trace_values', why: 'constant arguments passed to calls inside it', input: { path: '{path}', function: '{function}' } },
    ],
  },
  {
    id: 'android_app_review', title: 'Review an Android app', formats: ['apk', 'dex'], playbook: 'playbooks/apk.md',
    description: 'Manifest, exported components, signing, frameworks, code hot spots and native libraries of an APK.',
    arguments: [PATH, { name: 'focus', description: 'optional feature or string to chase, for example login or an API host', required: false }],
    deliverable: 'Attack surface (exported components, permissions), signing facts, notable code with class and method evidence.',
    steps: [
      { tool: 'mobile_apk_report', why: 'one page summary of the app', input: { path: '{path}' } },
      { tool: 'mobile_manifest', why: 'exported components and permissions', input: { path: '{path}' } },
      { tool: 'mobile_signing', why: 'signature schemes and certificate digests', input: { path: '{path}' } },
      { tool: 'mobile_dex_search', why: 'find code that mentions the focus', input: { path: '{path}', query: '{focus}' } },
      { tool: 'mobile_dex_xrefs', why: 'callers of the methods found', input: { path: '{path}' } },
      { tool: 'mobile_jni_map', why: 'native methods and their library exports', input: { path: '{path}' } },
    ],
  },
  {
    id: 'ios_app_review', title: 'Review an iOS app', formats: ['ipa'], playbook: 'playbooks/ipa.md',
    description: 'Bundle metadata, entitlements, transport security, frameworks and the main executable of an IPA.',
    arguments: [PATH], deliverable: 'Bundle facts, entitlements and ATS exceptions with plist paths, encryption state, notable code.',
    steps: [
      { tool: 'mobile_ipa_info', why: 'bundle id, versions, entitlements, ATS and provisioning', input: { path: '{path}' } },
      { tool: 'mobile_app_framework', why: 'cross platform framework in use', input: { path: '{path}' } },
      { tool: 'mobile_ipa_graph', why: 'how the app and its frameworks link', input: { path: '{path}' } },
      { tool: 'get_imports', why: 'frameworks and sensitive APIs of the main executable', input: { path: '{path}' } },
    ],
  },
  {
    id: 'dotnet_assembly_review', title: 'Review a .NET assembly', formats: ['dotnet'], playbook: 'playbooks/dotnet.md',
    description: 'Types, P/Invoke, resources and IL of a .NET assembly.',
    arguments: [PATH, { name: 'namespace', description: 'optional namespace filter', required: false }],
    deliverable: 'Program structure, native calls, interesting methods with metadata tokens and IL offsets.',
    steps: [
      { tool: 'managed_dotnet_info', why: 'runtime, references and resources', input: { path: '{path}' } },
      { tool: 'managed_dotnet_types', why: 'types in the namespace', input: { path: '{path}', namespace: '{namespace}' } },
      { tool: 'managed_pinvoke_map', why: 'native functions it calls', input: { path: '{path}' } },
      { tool: 'managed_dotnet_method_il', why: 'IL of the methods that matter', input: { path: '{path}' } },
    ],
  },
  {
    id: 'python_app_review', title: 'Unpack a Python app', formats: ['pyc', 'pe', 'elf', 'macho'], playbook: 'playbooks/python.md',
    description: 'List and extract a PyInstaller archive and read the entry scripts as bytecode.',
    arguments: [PATH, { name: 'outDir', description: 'empty folder for extracted members', required: true }],
    deliverable: 'Entry scripts, imported modules of note, constants such as URLs and keys, with member names and offsets.',
    steps: [
      { tool: 'managed_pyinstaller_list', why: 'archive members and entry scripts', input: { path: '{path}' } },
      { tool: 'managed_pyinstaller_extract', why: 'write members out (writes files)', input: { path: '{path}', outDir: '{outDir}' } },
      { tool: 'managed_pyc_disasm', why: 'bytecode of each entry script', input: { path: '{outDir}/<entry>.pyc' } },
    ],
  },
  {
    id: 'js_bundle_review', title: 'Read a JavaScript bundle', formats: ['js', 'sourcemap'], playbook: 'playbooks/js-bundle.md',
    description: 'Modules, endpoints, source map recovery and deobfuscation of a web bundle.',
    arguments: [PATH], deliverable: 'Bundler, modules of interest, endpoints and secrets with module ids and offsets.',
    steps: [
      { tool: 'web_bundle_modules', why: 'split the bundle into modules', input: { path: '{path}' } },
      { tool: 'web_js_endpoints', why: 'URLs and API paths', input: { path: '{path}' } },
      { tool: 'web_js_deobfuscate', why: 'readable code for obfuscated parts', input: { path: '{path}' } },
      { tool: 'x_api_contracts', why: 'group endpoints into an API description', input: { path: '{path}' } },
    ],
  },
  {
    id: 'electron_app_review', title: 'Audit an Electron app', formats: ['asar'], playbook: 'playbooks/electron.md',
    description: 'ASAR contents, BrowserWindow options, preload scripts, IPC handlers and fuses.',
    arguments: [PATH], deliverable: 'Security settings, risky IPC handlers and dependencies, with paths inside the archive.',
    steps: [
      { tool: 'web_asar_list', why: 'what the archive holds', input: { path: '{path}' } },
      { tool: 'web_electron_audit', why: 'window options, IPC and fuses', input: { path: '{path}' } },
      { tool: 'sbom', why: 'bundled dependencies', input: { path: '{path}' } },
      { tool: 'check_vulns', why: 'known vulnerabilities (network lookup)', input: { path: '{path}' } },
    ],
  },
  {
    id: 'firmware_image_review', title: 'Map a firmware image', formats: ['firmware', 'bin', 'unknown'], playbook: 'playbooks/firmware.md',
    description: 'Find headers, file systems and compressed parts in a firmware image, then dig into each.',
    arguments: [PATH], deliverable: 'A map of the image with offsets, and the notable programs, credentials and servers inside.',
    steps: [
      { tool: 'x_firmware_scan', why: 'signatures at every offset', input: { path: '{path}' } },
      { tool: 'x_firmware_parse', why: 'decode the container header', input: { path: '{path}' } },
      { tool: 'x_container', why: 'embedded archives', input: { path: '{path}' } },
      { tool: 'get_strings', why: 'URLs, paths and credentials', input: { path: '{path}', tag: 'url' } },
    ],
  },
  {
    id: 'pcap_review', title: 'Read a packet capture', formats: ['pcap', 'pcapng'], playbook: 'playbooks/pcap.md',
    description: 'Hosts, DNS, flows and HTTP or TLS details in a capture.',
    arguments: [PATH], deliverable: 'Hosts and flows of interest with packet numbers and timestamps.',
    steps: [
      { tool: 'web_pcap_summary', why: 'protocols, hosts and DNS names', input: { path: '{path}' } },
      { tool: 'web_pcap_flows', why: 'conversations with byte counts', input: { path: '{path}' } },
    ],
  },
  {
    id: 'compare_versions', title: 'Compare two versions', formats: ['*'],
    description: 'What changed between two builds: dependencies, endpoints, imports, functions and findings.',
    arguments: [{ name: 'before', description: 'older file', required: true }, { name: 'after', description: 'newer file', required: true }],
    deliverable: 'Changes that matter for security or behavior, each tied to evidence in both files.',
    steps: [
      { tool: 'diff_files', why: 'report level differences', input: { before: '{before}', after: '{after}' } },
      { tool: 'disasm_match_functions', why: 'matched and changed native functions', input: { a: '{before}', b: '{after}' } },
    ],
  },
  {
    id: 'cutter_live_session', title: 'Work with an open Cutter window', formats: ['elf', 'pe', 'macho'], playbook: 'playbooks/elf.md',
    description: 'Find a running Cutter, then run rizin commands on the same file and project from the agent.',
    arguments: [{ name: 'command', description: 'rizin command, for example afl or pdf @ main', required: true }],
    deliverable: 'Command output tied to the file Cutter has open.',
    steps: [
      { tool: 'list_cutter_sessions', why: 'running Cutter processes and their open files', input: {} },
      { tool: 'cutter_command', why: 'run the command on that file (needs allowExecution)', input: { session: '<pid from list_cutter_sessions>', command: '{command}', allowExecution: 'true' } },
    ],
  },
];

/** Replace {name} placeholders with the given arguments. Unknown placeholders are left in place. */
export function renderWorkflow(id: string, args: Record<string, unknown> = {}): { ok: true; workflow: GuidedWorkflow & { missing: string[] } } | { ok: false; error: string; known: string[] } {
  const w = WORKFLOWS.find((x) => x.id === id);
  if (!w) return { ok: false, error: `unknown workflow "${String(id).slice(0, 80)}"`, known: WORKFLOWS.map((x) => x.id) };
  const vals = new Map<string, string>();
  for (const a of w.arguments) {
    const v = args[a.name];
    if (typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean') vals.set(a.name, String(v).slice(0, 2000));
  }
  const missing = w.arguments.filter((a) => a.required && !vals.has(a.name)).map((a) => a.name);
  const fill = (s: string) => s.replace(/\{([a-zA-Z]{1,40})\}/g, (m, k: string) => vals.get(k) ?? (w.arguments.some((a) => a.name === k && !a.required) ? '' : m));
  return {
    ok: true,
    workflow: {
      ...w, missing,
      description: fill(w.description),
      steps: w.steps.map((s) => ({ ...s, input: s.input && Object.fromEntries(Object.entries(s.input).map(([k, v]) => [k, fill(v)])) })),
    },
  };
}
