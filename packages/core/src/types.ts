// Shared types for RevLens core. Every analyzer and output format uses these.
// Keep this file free of runtime code other than constants.

export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';

export interface Evidence {
  offset?: number;
  length?: number;
  path?: string;
  snippet?: string;
}

export interface Finding {
  id: string;
  analyzer: string;
  title: string;
  severity: Severity;
  detail: string;
  evidence: Evidence[];
  tags?: string[];
  /** MITRE ATT&CK technique ids, for example T1027 */
  attack?: string[];
}

export interface Section {
  name: string;
  offset: number;
  size: number;
  vaddr?: number;
  entropy: number;
  flags?: string;
}

export type FormatId =
  | 'elf' | 'pe' | 'macho' | 'macho-fat' | 'wasm'
  | 'zip' | 'jar' | 'apk' | 'crx' | 'xpi' | 'vsix' | 'npm-tgz' | 'gzip' | 'tar' | 'asar'
  | 'js' | 'sourcemap' | 'json' | 'pdf' | 'pyc' | 'dex' | 'class' | 'text' | 'unknown';

export interface Hashes {
  md5: string;
  sha1: string;
  sha256: string;
  tlsh?: string;
  ctph?: string;
}

export interface FileInfo {
  name: string;
  size: number;
  format: FormatId;
  mime?: string;
  arch?: string;
  bits?: 32 | 64;
  endian?: 'le' | 'be';
  hashes: Hashes;
  entropy: number;
}

export type Ecosystem = 'npm' | 'go' | 'cargo' | 'pypi' | 'maven' | 'unknown';

export interface Component {
  name: string;
  version?: string;
  ecosystem: Ecosystem;
  purl?: string;
  /** 0..1 */
  confidence: number;
  evidence: Evidence[];
}

export interface ExtractedString {
  value: string;
  offset: number;
  kind: 'ascii' | 'utf16';
  /** url, path, ip, email, crypto, format, registry, command, secret-like, guid ... */
  tag?: string;
}

export interface ImportEntry {
  library: string;
  symbols: string[];
}

export interface Capability {
  name: string;
  namespace?: string;
  attack?: string;
  evidence: Evidence[];
}

export interface Report {
  schema: 'revlens/report@1';
  tool: { name: 'RevLens'; version: string };
  generatedAt: string;
  file: FileInfo;
  sections: Section[];
  imports: ImportEntry[];
  exports: string[];
  strings: ExtractedString[];
  components: Component[];
  findings: Finding[];
  capabilities: Capability[];
  hardening?: Record<string, boolean | string>;
  /** archive members analyzed recursively */
  children?: Report[];
  meta: Record<string, unknown>;
  timings: Record<string, number>;
}

export interface AnalyzeOptions {
  name?: string;
  maxStrings?: number;
  recurse?: boolean;
  maxDepth?: number;
  /** extra yara-lite rule text */
  rules?: string;
  /** run only these analyzer ids (format and hashes always run) */
  analyzers?: string[];
}

/**
 * Mutable working context handed to each analyzer in turn.
 * Analyzers read `bytes`, `format`, and anything earlier analyzers put on `report`,
 * then push into report arrays or `report.meta[<analyzerId>]`.
 */
export interface AnalyzerContext {
  bytes: Uint8Array;
  name: string;
  format: FormatId;
  options: Required<Pick<AnalyzeOptions, 'maxStrings' | 'recurse' | 'maxDepth'>> & AnalyzeOptions;
  depth: number;
  report: Report;
  /** decoded text when the file is text-like (js, json, sourcemap, text), else undefined */
  text?: string;
  /** recursive analyze for archive members */
  analyzeChild?: (bytes: Uint8Array, name: string) => Promise<Report>;
}

export interface Analyzer {
  id: string;
  title: string;
  description: string;
  /** return false to skip for this file */
  applies(ctx: AnalyzerContext): boolean;
  run(ctx: AnalyzerContext): void | Promise<void>;
}

export interface RuleMatch {
  rule: string;
  tags: string[];
  meta: Record<string, string>;
  strings: { id: string; offset: number; length: number; snippet: string }[];
}

export type Claim =
  | { kind: 'contains-string'; value: string }
  | { kind: 'imports-symbol'; library?: string; symbol: string }
  | { kind: 'has-section'; name: string }
  | { kind: 'format-is'; format: FormatId }
  | { kind: 'bytes-at'; offset: number; hex: string }
  | { kind: 'sha256-is'; value: string }
  | { kind: 'uses-component'; name: string; version?: string };

export interface ClaimResult {
  verdict: 'VERIFIED' | 'REFUTED' | 'UNKNOWN';
  claim: Claim;
  reason: string;
  evidence: Evidence[];
}

export interface ChangeSet<T> {
  added: T[];
  removed: T[];
  changed?: { before: T; after: T }[];
}

export interface DiffReport {
  schema: 'revlens/diff@1';
  a: { name: string; sha256: string; format: FormatId };
  b: { name: string; sha256: string; format: FormatId };
  components: ChangeSet<Component>;
  imports: ChangeSet<string>;
  exports: ChangeSet<string>;
  endpoints: ChangeSet<string>;
  strings: ChangeSet<string>;
  sections: ChangeSet<Section>;
  findings: ChangeSet<Finding>;
  capabilities: ChangeSet<string>;
  summary: string;
}

export const REVLENS_VERSION = '0.1.1';
