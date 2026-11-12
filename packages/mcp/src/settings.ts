// Analysis settings for one MCP session: limits, budgets, which analyzers run, the execution policy and
// output caps. Each server instance (one per stdio process, one per HTTP session) owns its own copy.
// Launch values come from defaults, then an optional JSON config file, then environment variables.
// update_analysis_settings changes the session copy, and with persist: true also writes the config file.
import { existsSync, readFileSync, renameSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';

export type SettingId =
  | 'maxFileMB' | 'maxOutputChars' | 'maxStrings' | 'analyzeTimeoutMs' | 'toolTimeoutMs'
  | 'recurse' | 'packages' | 'disabledAnalyzers' | 'allowExecution' | 'denyExecution' | 'allowNetwork' | 'cacheEntries';

interface Def {
  id: SettingId;
  type: 'number' | 'boolean' | 'string[]';
  def: number | boolean | string[];
  min?: number;
  max?: number;
  unit?: string;
  env?: string;
  description: string;
  appliesAt: 'next_call' | 'next_analysis';
}

export const SETTING_DEFS: Def[] = [
  { id: 'maxFileMB', type: 'number', def: 256, min: 1, max: 4096, unit: 'MiB', env: 'REVLENS_MAX_FILE_MB', appliesAt: 'next_call', description: 'Largest input file a tool will read.' },
  { id: 'maxOutputChars', type: 'number', def: 60_000, min: 4_000, max: 2_000_000, unit: 'characters', env: 'REVLENS_MCP_MAX_CHARS', appliesAt: 'next_call', description: 'Largest text a single tool answer may carry; longer answers are cut with a paging hint.' },
  { id: 'maxStrings', type: 'number', def: 400, min: 10, max: 100_000, unit: 'strings', appliesAt: 'next_analysis', description: 'Strings kept in a report by analyze_file and friends.' },
  { id: 'analyzeTimeoutMs', type: 'number', def: 300_000, min: 1_000, max: 3_600_000, unit: 'ms', env: 'REVLENS_ANALYZE_TIMEOUT_MS', appliesAt: 'next_analysis', description: 'Time budget for one full analysis. The call fails with a clear message when it runs out.' },
  { id: 'toolTimeoutMs', type: 'number', def: 600_000, min: 1_000, max: 7_200_000, unit: 'ms', appliesAt: 'next_call', description: 'Time budget for any one package or bridge tool call.' },
  { id: 'cacheEntries', type: 'number', def: 32, min: 1, max: 512, unit: 'reports', appliesAt: 'next_analysis', description: 'Analysis reports kept in memory for this session.' },
  { id: 'recurse', type: 'boolean', def: true, appliesAt: 'next_analysis', description: 'Analyze members of archives (ZIP, APK, IPA, tgz) as children.' },
  { id: 'packages', type: 'string[]', def: [], appliesAt: 'next_analysis', description: 'Package analyzers to run (mobile, managed, web, extras, desktop, disasm). Empty means all. Core always runs.' },
  { id: 'disabledAnalyzers', type: 'string[]', def: [], appliesAt: 'next_analysis', description: 'Analyzer ids to skip, from list_analyzers.' },
  { id: 'allowExecution', type: 'boolean', def: false, env: 'REVLENS_ALLOW_EXECUTION', appliesAt: 'next_call', description: 'When true, tools that run or instrument code get allowExecution: true by default. When false each such call must pass allowExecution: true itself.' },
  { id: 'denyExecution', type: 'boolean', def: false, env: 'REVLENS_DENY_EXECUTION', appliesAt: 'next_call', description: 'Hard lock for shared hosts: refuse every tool that starts a program, whatever the call says.' },
  { id: 'allowNetwork', type: 'boolean', def: true, env: 'REVLENS_ALLOW_NETWORK', appliesAt: 'next_call', description: 'Allow tools that reach the network (check_vulns, browser capture). Set false for offline work.' },
];

export type SettingsValues = { [K in SettingId]: K extends 'packages' | 'disabledAnalyzers' ? string[] : K extends 'recurse' | 'allowExecution' | 'denyExecution' | 'allowNetwork' ? boolean : number };

export class SettingsError extends Error {}

function coerce(d: Def, v: unknown, from: string): number | boolean | string[] {
  if (d.type === 'number') {
    const n = typeof v === 'number' ? v : typeof v === 'string' && v.trim() !== '' ? Number(v) : NaN;
    if (!Number.isFinite(n)) throw new SettingsError(`${d.id} from ${from} must be a number`);
    if (n < d.min! || n > d.max!) throw new SettingsError(`${d.id} from ${from} must be between ${d.min} and ${d.max} ${d.unit ?? ''}`.trim());
    return Math.floor(n);
  }
  if (d.type === 'boolean') {
    if (typeof v === 'boolean') return v;
    if (v === '1' || v === 'true') return true;
    if (v === '0' || v === 'false' || v === '') return false;
    throw new SettingsError(`${d.id} from ${from} must be true or false`);
  }
  const arr = typeof v === 'string' ? v.split(',') : v;
  if (!Array.isArray(arr) || arr.length > 200 || !arr.every((x) => typeof x === 'string' && x.length <= 80)) throw new SettingsError(`${d.id} from ${from} must be a list of short names`);
  return [...new Set(arr.map((x) => x.trim()).filter(Boolean))];
}

export interface SettingsOptions {
  /** JSON config file with launch values; REVLENS_SETTINGS_FILE when not given */
  file?: string;
  env?: NodeJS.ProcessEnv;
}

/** Read launch values: defaults, then the config file, then environment. Bad values are reported, not fatal. */
export function launchSettings(opts: SettingsOptions = {}): { values: SettingsValues; sources: Record<SettingId, string>; problems: string[]; file?: string } {
  const env = opts.env ?? process.env;
  const file = opts.file ?? (env.REVLENS_SETTINGS_FILE || undefined);
  const values = Object.fromEntries(SETTING_DEFS.map((d) => [d.id, Array.isArray(d.def) ? [...d.def] : d.def])) as SettingsValues;
  const sources = Object.fromEntries(SETTING_DEFS.map((d) => [d.id, 'default'])) as Record<SettingId, string>;
  const problems: string[] = [];
  if (file && existsSync(file)) {
    try {
      const raw = readFileSync(file, 'utf8');
      if (raw.length > 1_000_000) throw new SettingsError('settings file is larger than 1 MB');
      const json = JSON.parse(raw) as Record<string, unknown>;
      for (const d of SETTING_DEFS) if (json && Object.prototype.hasOwnProperty.call(json, d.id)) {
        try { (values as Record<string, unknown>)[d.id] = coerce(d, json[d.id], 'settings file'); sources[d.id] = 'file'; } catch (e) { problems.push((e as Error).message); }
      }
    } catch (e) { problems.push(`could not read settings file: ${(e as Error).message}`); }
  }
  for (const d of SETTING_DEFS) if (d.env && env[d.env] !== undefined && env[d.env] !== '') {
    try { (values as Record<string, unknown>)[d.id] = coerce(d, env[d.env], d.env); sources[d.id] = `env:${d.env}`; } catch (e) { problems.push((e as Error).message); }
  }
  return { values, sources, problems, file };
}

export interface SettingChange { setting: string; action?: 'set' | 'reset'; value?: unknown }

/** One session's settings with a revision counter for optimistic updates. */
export class AnalysisSettings {
  private launch: ReturnType<typeof launchSettings>;
  private cur: SettingsValues;
  private src: Record<SettingId, string>;
  revision = 0;
  private listeners: (() => void)[] = [];

  constructor(private readonly opts: SettingsOptions = {}) {
    this.launch = launchSettings(opts);
    this.cur = structuredClone(this.launch.values);
    this.src = { ...this.launch.sources };
  }

  get values(): Readonly<SettingsValues> { return this.cur; }
  get<K extends SettingId>(k: K): SettingsValues[K] { return this.cur[k]; }
  onChange(fn: () => void): void { this.listeners.push(fn); }

  inspect(input: { settings?: string[] } = {}) {
    const want = Array.isArray(input.settings) && input.settings.length ? new Set(input.settings) : undefined;
    return {
      scope: 'mcp-session', revision: this.revision,
      configFile: this.launch.file ?? null, launchProblems: this.launch.problems,
      settings: SETTING_DEFS.filter((d) => !want || want.has(d.id)).map((d) => ({
        setting: d.id, value: this.cur[d.id], launchValue: this.launch.values[d.id], defaultValue: d.def, source: this.src[d.id],
        type: d.type, ...(d.min !== undefined ? { minimum: d.min, maximum: d.max, unit: d.unit } : {}),
        appliesAt: d.appliesAt, ...(d.env ? { environment: d.env } : {}), description: d.description,
      })),
      unknown: want ? [...want].filter((x) => !SETTING_DEFS.some((d) => d.id === x)) : [],
    };
  }

  /**
   * Apply changes atomically: all are checked first, then all are applied. expectedRevision guards
   * against two agents changing the same session at once. persist writes the result to the config file.
   */
  update(input: { changes?: SettingChange[]; expectedRevision?: number; persist?: boolean }) {
    const changes = Array.isArray(input.changes) ? input.changes : [];
    if (!changes.length) throw new SettingsError('changes must list at least one { setting, action, value }');
    if (changes.length > SETTING_DEFS.length * 2) throw new SettingsError('too many changes');
    if (input.expectedRevision !== undefined && input.expectedRevision !== this.revision) throw new SettingsError(`settings changed meanwhile: revision is ${this.revision}, expected ${input.expectedRevision}. Inspect and try again.`);
    const next = structuredClone(this.cur);
    const src = { ...this.src };
    const applied: { setting: SettingId; oldValue: unknown; newValue: unknown }[] = [];
    for (const c of changes) {
      const d = SETTING_DEFS.find((x) => x.id === c?.setting);
      if (!d) throw new SettingsError(`unknown setting "${String(c?.setting).slice(0, 60)}". Known: ${SETTING_DEFS.map((x) => x.id).join(', ')}`);
      const old = next[d.id];
      if (c.action === 'reset') { (next as Record<string, unknown>)[d.id] = structuredClone(this.launch.values[d.id]); src[d.id] = this.launch.sources[d.id]; }
      else { (next as Record<string, unknown>)[d.id] = coerce(d, c.value, 'update'); src[d.id] = 'session'; }
      applied.push({ setting: d.id, oldValue: old, newValue: next[d.id] });
    }
    const changed = applied.some((a) => JSON.stringify(a.oldValue) !== JSON.stringify(a.newValue));
    this.cur = next;
    this.src = src;
    if (changed) { this.revision++; for (const l of this.listeners) l(); }
    let persisted: string | null = null;
    if (input.persist) persisted = this.persist();
    return { changed, changes: applied, persisted, ...this.inspect() };
  }

  /** Write the current values to the config file (temp file then rename). */
  persist(): string {
    const file = this.launch.file ?? this.opts.file;
    if (!file) throw new SettingsError('no settings file is configured. Start the server with --settings-file <path> or REVLENS_SETTINGS_FILE.');
    const abs = resolve(file);
    mkdirSync(dirname(abs), { recursive: true });
    const tmp = `${abs}.${process.pid}.tmp`;
    writeFileSync(tmp, JSON.stringify(this.cur, null, 2) + '\n', { mode: 0o600 });
    renameSync(tmp, abs);
    return abs;
  }
}
