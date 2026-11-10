import type { Analyzer, Capability } from '../types.js';

/**
 * capa-lite: derive capabilities from imported symbols and strings, each mapped
 * to a MITRE ATT&CK technique. This is a lightweight take on Mandiant capa: no
 * disassembly, just symbol and string evidence, which is enough for triage.
 */
interface Rule { name: string; namespace: string; attack?: string; any: (string | RegExp)[]; need?: number }

const RULES: Rule[] = [
  { name: 'create a process', namespace: 'host/process', attack: 'T1106', any: ['CreateProcess', 'ShellExecute', 'WinExec', 'posix_spawn', 'execve', 'fork', 'system'] },
  { name: 'inject into another process', namespace: 'host/process/inject', attack: 'T1055', need: 2, any: ['VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread', 'NtMapViewOfSection', 'QueueUserAPC', 'SetThreadContext'] },
  { name: 'access the network', namespace: 'communication/network', attack: 'T1071', any: ['connect', 'WSASocket', 'InternetOpen', 'HttpSendRequest', 'send', 'recv', 'getaddrinfo', 'curl_easy', 'fetch(', 'XMLHttpRequest', 'WinHttp'] },
  { name: 'resolve DNS', namespace: 'communication/dns', any: ['DnsQuery', 'gethostbyname', 'getaddrinfo', 'res_query', 'dns.lookup'] },
  { name: 'read or write the registry', namespace: 'host/registry', attack: 'T1112', any: ['RegOpenKey', 'RegSetValue', 'RegQueryValue', 'RegCreateKey', 'RegDeleteKey'] },
  { name: 'persist via run key or service', namespace: 'persistence', attack: 'T1547', any: ['CurrentVersion\\\\Run', 'CreateService', 'schtasks', 'crontab', 'LaunchAgents', 'systemctl enable'] },
  { name: 'encrypt or decrypt data', namespace: 'data/encryption', any: ['CryptEncrypt', 'CryptAcquireContext', 'BCryptEncrypt', 'AES_set_encrypt', 'EVP_EncryptInit', 'crypto.createCipher'] },
  { name: 'capture the screen', namespace: 'collection/screen', attack: 'T1113', any: ['BitBlt', 'GetDC', 'CreateCompatibleBitmap', 'CGDisplayCreateImage', 'getDisplayMedia'] },
  { name: 'log keystrokes', namespace: 'collection/keylog', attack: 'T1056.001', need: 1, any: ['SetWindowsHookEx', 'GetAsyncKeyState', 'GetKeyboardState', 'addEventListener("keydown"'] },
  { name: 'enumerate files', namespace: 'host/filesystem', any: ['FindFirstFile', 'readdir', 'opendir', 'GetFileAttributes', 'fs.readdir'] },
  { name: 'detect a debugger', namespace: 'anti-analysis/anti-debug', attack: 'T1622', any: ['IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'PTRACE_TRACEME', 'TracerPid'] },
  { name: 'detect a virtual machine', namespace: 'anti-analysis/anti-vm', attack: 'T1497', any: ['VBoxGuest', 'vmware', 'QEMU', 'SbieDll', 'cpuid', 'hypervisor'] },
  { name: 'evaluate code at runtime', namespace: 'execution/eval', attack: 'T1059', any: [/\beval\s*\(/, 'new Function(', 'child_process', 'vm.runInNewContext'] },
  { name: 'read environment secrets', namespace: 'collection/credentials', attack: 'T1552', any: ['process.env', '.aws/credentials', '.npmrc', 'id_rsa', 'GetEnvironmentVariable'] },
  { name: 'contact a hardcoded host', namespace: 'communication/c2', attack: 'T1071', any: [/https?:\/\/\d{1,3}(\.\d{1,3}){3}/, '.onion'] },
];

export const capaAnalyzer: Analyzer = {
  id: 'capa',
  title: 'Capabilities',
  description: 'Maps imports and strings to capabilities and MITRE ATT&CK techniques, in the spirit of Mandiant capa.',
  applies: () => true,
  run(ctx) {
    const { report } = ctx;
    const symbols = report.imports.flatMap((i) => i.symbols).join('\n');
    const strings = report.strings.map((s) => s.value).join('\n');
    const hay = symbols + '\n' + strings + '\n' + (ctx.text ? ctx.text.slice(0, 2_000_000) : '');
    const symSet = new Set(report.imports.flatMap((i) => i.symbols.map((x) => x.replace(/\s*\(.*$/, ''))));
    const caps: Capability[] = [];
    for (const rule of RULES) {
      const matched: string[] = [];
      for (const pat of rule.any) {
        // Short or generic names only count as imported symbols, which keeps prose from matching.
        const hit = typeof pat === 'string'
          ? (pat.length < 9 && /^\w+$/.test(pat) ? [...symSet].some((x) => x === pat || x.startsWith(pat + 'A') || x.startsWith(pat + 'W') || x.startsWith(pat + 'Ex')) : hay.includes(pat))
          : pat.test(hay);
        if (hit) matched.push(typeof pat === 'string' ? pat : pat.source);
      }
      if (matched.length >= (rule.need ?? 1)) {
        caps.push({ name: rule.name, namespace: rule.namespace, attack: rule.attack, evidence: matched.slice(0, 4).map((snippet) => ({ snippet })) });
      }
    }
    report.capabilities.push(...caps);
    const attacks = [...new Set(caps.map((c) => c.attack).filter(Boolean))] as string[];
    if (attacks.length) report.meta.attack = attacks;

    // Raise a finding when a risky capability combination appears together.
    const names = new Set(caps.map((c) => c.name));
    if (names.has('inject into another process') && names.has('access the network')) {
      report.findings.push({ id: 'capa.injector', analyzer: 'capa', title: 'Networked process injector behavior', severity: 'high',
        detail: 'The file both injects into other processes and talks to the network. That pairing is common in loaders and implants, and rare in ordinary software.', evidence: [], tags: ['behavior'], attack: ['T1055', 'T1071'] });
    }
  },
};
