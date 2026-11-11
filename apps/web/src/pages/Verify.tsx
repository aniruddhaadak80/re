import { useState } from 'react';
import { BadgeCheck, CheckCircle2, HelpCircle, Loader2, XCircle } from 'lucide-react';
import type { Claim, ClaimResult, FormatId, Report } from '@revlens/core';
import { DropZone } from '../components/DropZone';
import { PageHeader } from '../components/ui';
import { analyzeInWorker, forgetInWorker, newId, verifyInWorker } from '../lib/engine';
import { SAMPLES, loadSample } from '../lib/samples';
import { useRouteSeo } from '../lib/seo';
import { FORMAT_LABEL, cx, formatBytes, hex } from '../lib/util';

type Kind = Claim['kind'];
const KINDS: { id: Kind; label: string; help: string }[] = [
  { id: 'contains-string', label: 'Contains a string', help: 'Searches the bytes as ASCII and UTF-16.' },
  { id: 'imports-symbol', label: 'Imports a symbol', help: 'Checks the parsed import table, optionally for one library.' },
  { id: 'has-section', label: 'Has a section', help: 'Checks the section table by exact name.' },
  { id: 'format-is', label: 'Format is', help: 'Checks the magic bytes.' },
  { id: 'bytes-at', label: 'Bytes at offset', help: 'Compares exact bytes at an offset. Hex like 7F454C46.' },
  { id: 'sha256-is', label: 'SHA-256 is', help: 'Compares the full file hash.' },
  { id: 'uses-component', label: 'Uses a component', help: 'Checks detected components, optionally at a version.' },
];
const FORMATS: FormatId[] = ['elf', 'pe', 'macho', 'macho-fat', 'wasm', 'zip', 'jar', 'apk', 'crx', 'xpi', 'vsix', 'npm-tgz', 'gzip', 'tar', 'asar', 'js', 'sourcemap', 'json', 'pdf', 'pyc', 'dex', 'class', 'text', 'dotnet', 'ipa', 'pcap', 'pcapng', 'sqlite', 'har', 'lua', 'beam', 'il2cpp-metadata', 'unknown'];

interface Loaded { id: string; name: string; report?: Report; status: 'running' | 'done' | 'error'; error?: string }

export default function Verify() {
  useRouteSeo('/verify');
  const [file, setFile] = useState<Loaded | null>(null);
  const [kind, setKind] = useState<Kind>('contains-string');
  const [f, setF] = useState<Record<string, string>>({ value: '', library: '', symbol: '', name: '', format: 'elf', offset: '0', hex: '', version: '' });
  const [result, setResult] = useState<ClaimResult | null>(null);
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);

  const load = (name: string, bytes: Uint8Array) => {
    if (file) forgetInWorker(file.id);
    const id = newId('v');
    setFile({ id, name, status: 'running' }); setResult(null);
    analyzeInWorker(id, name, bytes).then((report) => setFile({ id, name, report, status: 'done' })).catch((e: Error) => setFile({ id, name, status: 'error', error: e.message }));
  };
  const claim = (): Claim => {
    switch (kind) {
      case 'contains-string': return { kind, value: f.value! };
      case 'imports-symbol': return f.library ? { kind, symbol: f.symbol!, library: f.library } : { kind, symbol: f.symbol! };
      case 'has-section': return { kind, name: f.name! };
      case 'format-is': return { kind, format: f.format as FormatId };
      case 'bytes-at': return { kind, offset: Number(f.offset!.startsWith('0x') ? parseInt(f.offset!, 16) : f.offset), hex: f.hex!.replace(/\s+/g, '') };
      case 'sha256-is': return { kind, value: f.value!.trim() };
      case 'uses-component': return f.version ? { kind, name: f.name!, version: f.version } : { kind, name: f.name! };
    }
  };
  const submit = async () => {
    if (!file || file.status !== 'done') return;
    setBusy(true); setErr('');
    try { setResult(await verifyInWorker(file.id, claim())); } catch (e) { setErr((e as Error).message); } finally { setBusy(false); }
  };
  const input = (key: string, label: string, ph: string, mono = true) => (
    <label className="block min-w-0 flex-1"><span className="label">{label}</span><input className={cx('input', mono && 'font-mono')} value={f[key] ?? ''} placeholder={ph} data-testid={`claim-${key}`} onChange={(e) => setF((o) => ({ ...o, [key]: e.target.value }))} /></label>
  );
  const V = result ? { VERIFIED: { icon: CheckCircle2, cls: 'border-teal/60 bg-teal/10 text-teal-700 dark:text-teal-300' }, REFUTED: { icon: XCircle, cls: 'border-red-500/50 bg-red-500/10 text-red-600 dark:text-red-300' }, UNKNOWN: { icon: HelpCircle, cls: 'border-accent/50 bg-accent/10 text-ink' } }[result.verdict] : null;

  return (
    <div>
      <PageHeader eyebrow="Verify" title="Check a claim against the bytes">
        Agents and reports make claims about files. Paste one here and RevLens answers VERIFIED, REFUTED or UNKNOWN, with the exact evidence so you can check it yourself.
      </PageHeader>
      <div className="container-x grid grid-cols-1 gap-6 lg:grid-cols-[1fr_1.2fr]">
        <div className="card p-4">
          <p className="mb-3 text-xs font-semibold uppercase tracking-widest text-ink">1. The file</p>
          {file && (
            <div className="mb-3 flex items-center gap-3 rounded-xl border border-line bg-surface2/60 p-3">
              {file.status === 'running' ? <Loader2 size={18} className="animate-spin text-ink" /> : <BadgeCheck size={18} className="text-teal" />}
              <div className="min-w-0"><p className="truncate font-medium" data-testid="verify-file">{file.name}</p><p className="text-xs text-muted">{file.report ? `${FORMAT_LABEL[file.report.file.format] ?? file.report.file.format}, ${formatBytes(file.report.file.size)}` : file.error ?? 'Analyzing'}</p></div>
            </div>
          )}
          <DropZone compact multiple={false} testId="verify-input" onFiles={async (fl) => { const x = fl[0]!; load(x.name, new Uint8Array(await x.arrayBuffer())); }} />
          <div className="mt-3 flex flex-wrap gap-1.5">
            {SAMPLES.map((s) => <button key={s.id} type="button" className="chip transition hover:border-accent/60 hover:text-fg" data-testid={`verify-sample-${s.id}`} onClick={async () => load(s.file, await loadSample(s))}>{s.label}</button>)}
          </div>
        </div>
        <div className="card p-4">
          <p className="mb-3 text-xs font-semibold uppercase tracking-widest text-ink">2. The claim</p>
          <label className="block"><span className="label">Kind of claim</span>
            <select className="input" value={kind} onChange={(e) => { setKind(e.target.value as Kind); setResult(null); }} data-testid="claim-kind">
              {KINDS.map((k) => <option key={k.id} value={k.id}>{k.label}</option>)}
            </select>
          </label>
          <p className="mt-1 text-xs text-muted">{KINDS.find((k) => k.id === kind)!.help}</p>
          <div className="mt-4 flex flex-wrap gap-3">
            {kind === 'contains-string' && input('value', 'String', 'GLIBC_2.17', false)}
            {kind === 'imports-symbol' && <>{input('symbol', 'Symbol', 'getenv')}{input('library', 'Library (optional)', 'libc.so.6')}</>}
            {kind === 'has-section' && input('name', 'Section name', '.text')}
            {kind === 'format-is' && (
              <label className="block flex-1"><span className="label">Format</span>
                <select className="input" value={f.format} onChange={(e) => setF((o) => ({ ...o, format: e.target.value }))} data-testid="claim-format">
                  {FORMATS.map((x) => <option key={x} value={x}>{FORMAT_LABEL[x] ?? x}</option>)}
                </select>
              </label>
            )}
            {kind === 'bytes-at' && <>{input('offset', 'Offset', '0 or 0x0')}{input('hex', 'Hex bytes', '7F454C46')}</>}
            {kind === 'sha256-is' && input('value', 'SHA-256', '64 hex characters')}
            {kind === 'uses-component' && <>{input('name', 'Component', 'react-dom')}{input('version', 'Version (optional)', '18.3.1')}</>}
          </div>
          <button type="button" className="btn-primary mt-4" onClick={submit} disabled={!file || file.status !== 'done' || busy} data-testid="verify-run">
            {busy ? <Loader2 size={16} className="animate-spin" /> : <BadgeCheck size={16} />}Verify the claim
          </button>
          {!file && <p className="mt-2 text-xs text-muted">Pick a file first.</p>}
          {err && <p className="mt-3 text-sm text-red-500">{err}</p>}
          {result && V && (
            <div className={cx('mt-5 rounded-xl border p-4', V.cls)} data-testid="verify-result" data-verdict={result.verdict}>
              <p className="flex items-center gap-2 text-lg font-semibold"><V.icon size={20} />{result.verdict}</p>
              <p className="mt-1 text-sm text-fg">{result.reason}</p>
              {result.evidence.length > 0 && (
                <ul className="mt-3 space-y-1">
                  {result.evidence.map((e, i) => <li key={i} className="break-all font-mono text-xs text-fg">{e.offset != null && <span className="mr-2 text-ink">{hex(e.offset, 6)}</span>}{e.snippet}{e.path && <span className="ml-2 text-muted">{e.path}</span>}</li>)}
                </ul>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
