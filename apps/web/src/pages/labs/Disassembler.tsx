import { useEffect, useMemo, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import { ArrowLeft, Cpu, GitBranch, GitCompare, ListTree, Loader2, Search, SquareCode } from 'lucide-react';
import { DropZone } from '../../components/DropZone';
import { PageHeader } from '../../components/ui';
import { CfgView, type CfgBlock } from '../../components/CfgView';
import { CodePanel, DataTable } from '../../components/ToolResult';
import { forgetInWorker, loadInWorker, newId, toolInWorker } from '../../lib/engine';
import { labBySlug, loadLabSample, MATCH_SAMPLES, type LabSample } from '../../lib/labs';
import { useSeo } from '../../lib/seo';
import { cx } from '../../lib/util';
import { FilePicker, useLabFile } from './shared';

interface Fn { addr: string; name: string; size?: number; source: string }
interface Info { format: string; arch: string; bits: number; entry?: string; decoder: string; functions: number; sections: { name: string; vaddr: string; size: number; exec?: boolean }[] }
interface FnDetail {
  summary: { instructions: number; blocks: number; edges: number; cyclomaticComplexity: number; loops: number; calls: { name: string; count: number }[]; strings: { value: string; at: string }[]; imports: string[] };
  blocks: CfgBlock[];
}
type View = 'pseudo' | 'graph' | 'listing';
interface MatchSide { addr: string; name: string; insns: number }
interface MatchResult {
  matched: number; identical: number; changed: number; unmatchedA: number; unmatchedB: number; byMethod: Record<string, number>;
  matches: { a: MatchSide; b: MatchSide; confidence: number; method: string; identical: boolean }[];
  onlyInA: MatchSide[]; onlyInB: MatchSide[];
}

/** Match the functions of the open binary with a second one, all in the worker. */
function MatchPanel({ fileId }: { fileId: string }) {
  const [name, setName] = useState('');
  const [res, setRes] = useState<MatchResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');
  const second = useRef<string | null>(null);
  useEffect(() => () => { if (second.current) forgetInWorker(second.current); }, []);
  useEffect(() => { setRes(null); setName(''); }, [fileId]);
  const run = async (n: string, bytes: Uint8Array) => {
    setBusy(true); setErr(''); setRes(null); setName(n);
    try {
      if (second.current) forgetInWorker(second.current);
      const id = newId('m');
      second.current = id;
      await loadInWorker(id, bytes);
      const r = await toolInWorker<MatchResult>(fileId, 'disasm_match_functions', { secondFileId: id, limit: 500, budgetMs: 30000 });
      setRes(r.result);
    } catch (e) { setErr((e as Error).message); } finally { setBusy(false); }
  };
  return (
    <div className="card p-4" data-testid="match-panel">
      <p className="mb-2 flex items-center gap-1.5 text-xs font-semibold uppercase tracking-widest text-ink"><GitCompare size={13} />Match functions with a second binary</p>
      <p className="mb-3 text-xs text-muted">Maps functions between two builds, for example two versions or a stripped and an unstripped build, by code, strings, calls and shape.</p>
      <DropZone compact multiple={false} testId="match-input" hint={<span>Second ELF, PE or Mach-O. It stays in your browser.</span>}
        onFiles={async (fl) => { const x = fl[0]; if (x) void run(x.name, new Uint8Array(await x.arrayBuffer())); }} />
      <div className="mt-3 flex flex-wrap gap-1.5">
        {MATCH_SAMPLES.map((s) => (
          <button key={s.id} type="button" className="chip transition hover:border-accent/60 hover:text-fg" title={s.note} data-testid={`match-sample-${s.id}`}
            onClick={() => void loadLabSample(s).then((b) => run(s.file.split('/').pop() ?? s.file, b), (e: Error) => setErr(e.message))}>{s.label}</button>
        ))}
      </div>
      {busy && <p className="mt-3 flex items-center gap-2 text-sm text-muted"><Loader2 size={14} className="animate-spin text-ink" />Matching against {name}</p>}
      {err && <p className="mt-3 text-sm text-red-500" role="alert">{err}</p>}
      {res && (
        <div className="mt-3 space-y-2 text-xs">
          <p className="text-sm" data-testid="match-summary">{res.matched} matched with {name}: {res.identical} identical, {res.changed} changed, {res.unmatchedA} only here, {res.unmatchedB} only there</p>
          <p className="text-muted">{Object.entries(res.byMethod).map(([k, v]) => `${k} ${v}`).join(', ')}</p>
          <div className="max-h-[22rem] overflow-auto">
            <table className="w-full font-mono" data-testid="match-table">
              <thead><tr className="text-left text-muted"><th className="pr-2">this file</th><th className="pr-2">second file</th><th className="pr-2">method</th><th>conf.</th></tr></thead>
              <tbody>
                {res.matches.map((m) => (
                  <tr key={m.a.addr + m.b.addr} className={m.identical ? '' : 'text-gold'}>
                    <td className="pr-2 break-all">{m.a.name}</td><td className="pr-2 break-all">{m.b.name}</td><td className="pr-2">{m.method}</td><td>{m.confidence.toFixed(2)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}

const lab = labBySlug('disassembler')!;

export default function Disassembler() {
  useSeo(`${lab.title} | RevLens`, lab.summary);
  const { file, loading, error, load, loadSample } = useLabFile();
  const [info, setInfo] = useState<Info | null>(null);
  const [fns, setFns] = useState<Fn[]>([]);
  const [filter, setFilter] = useState('');
  const [sel, setSel] = useState<Fn | null>(null);
  const [detail, setDetail] = useState<FnDetail | null>(null);
  const [pseudo, setPseudo] = useState('');
  const [view, setView] = useState<View>('pseudo');
  const [busy, setBusy] = useState('');
  const [err, setErr] = useState('');

  const openFn = async (fileId: string, f: Fn) => {
    setSel(f); setBusy(`Reading ${f.name}`); setErr('');
    try {
      const [d, p] = await Promise.all([
        toolInWorker<FnDetail>(fileId, 'disasm_function', { function: f.addr, limit: 2000 }),
        toolInWorker<{ pseudocode: string }>(fileId, 'disasm_pseudocode', { function: f.addr }),
      ]);
      setDetail(d.result); setPseudo(p.result.pseudocode);
    } catch (e) { setErr((e as Error).message); setDetail(null); setPseudo(''); } finally { setBusy(''); }
  };

  const openFile = async (name: string, bytes: Uint8Array | null, sample?: LabSample) => {
    setInfo(null); setFns([]); setSel(null); setDetail(null); setPseudo(''); setErr('');
    const f = sample ? await loadSample(sample) : bytes ? await load(name, bytes) : null;
    if (!f) return;
    setBusy('Finding functions');
    try {
      const [i, l] = await Promise.all([
        toolInWorker<Info>(f.id, 'disasm_info', {}),
        toolInWorker<{ functions: Fn[] }>(f.id, 'disasm_list_functions', { limit: 5000, sort: 'addr' }),
      ]);
      setInfo(i.result); setFns(l.result.functions);
      const start = l.result.functions.find((x) => x.name === 'main') ?? l.result.functions.find((x) => x.addr === i.result.entry) ?? l.result.functions[0];
      setBusy('');
      if (start) await openFn(f.id, start);
    } catch (e) { setErr((e as Error).message); setBusy(''); }
  };

  const shown = useMemo(() => { const q = filter.toLowerCase(); return fns.filter((f) => !q || f.name.toLowerCase().includes(q) || f.addr.includes(q)); }, [fns, filter]);
  const listing = useMemo(() => detail ? detail.blocks.map((b) => [`${b.start}:`, ...b.insns.map((i) => `  ${i.addr.padStart(10)}  ${i.text}${i.ref ? `    ; ${i.ref}` : ''}`)].join('\n')).join('\n\n') : '', [detail]);

  return (
    <div>
      <PageHeader eyebrow={lab.eyebrow} title={lab.title}>
        <p>{lab.summary}</p>
        <p className="mt-2 flex flex-wrap items-center gap-3 text-xs"><span className="chip"><Cpu size={12} />{lab.pkg}</span><Link to="/labs" className="inline-flex items-center gap-1 text-muted hover:text-ink"><ArrowLeft size={12} />All tools</Link></p>
      </PageHeader>
      <div className="container-x grid grid-cols-1 gap-6 pb-16 lg:grid-cols-[minmax(0,20rem)_minmax(0,1fr)]">
        <div className="min-w-0 space-y-4">
          <FilePicker lab={lab} file={file} loading={loading} error={error} onFile={(n, b) => void openFile(n, b)} onSample={(s) => void openFile(s.file, null, s)} />
          {info && (
            <div className="card p-4 text-sm" data-testid="disasm-info">
              <p className="font-medium">{info.format.toUpperCase()} {info.arch}, {info.bits}-bit</p>
              <p className="mt-1 text-xs text-muted">entry {info.entry ?? 'none'}, {info.functions} functions, decoder {info.decoder}</p>
            </div>
          )}
          {fns.length > 0 && (
            <div className="card p-3">
              <label className="relative block"><Search size={14} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-muted" />
                <input className="input pl-8" placeholder="Filter functions" value={filter} onChange={(e) => setFilter(e.target.value)} aria-label="Filter functions" />
              </label>
              <ul className="mt-2 max-h-[26rem] overflow-auto text-xs" data-testid="function-list">
                {shown.slice(0, 2000).map((f) => (
                  <li key={f.addr}>
                    <button type="button" onClick={() => file && void openFn(file.id, f)} data-testid="function-row"
                      className={cx('flex w-full min-w-0 items-center gap-2 rounded-lg px-2 py-1 text-left font-mono transition', sel?.addr === f.addr ? 'bg-accent/10 text-ink' : 'text-fg hover:bg-surface2')}>
                      <span className="shrink-0 text-muted">{f.addr}</span><span className="min-w-0 truncate">{f.name}</span>
                    </button>
                  </li>
                ))}
              </ul>
              <p className="mt-2 text-xs text-muted">{shown.length} of {fns.length} functions</p>
            </div>
          )}
        </div>
        <div className="min-w-0 space-y-4">
          {busy && <div className="card flex items-center gap-2 p-4 text-sm text-muted"><Loader2 size={16} className="animate-spin text-ink" />{busy}</div>}
          {err && <div className="card p-4 text-sm text-red-500" role="alert">{err}</div>}
          {!file && !busy && <div className="card p-8 text-center text-sm text-muted">Open a native binary or try a sample. Functions, a graph and pseudo code appear here.</div>}
          {sel && detail && (
            <div className="card p-4" data-testid="function-view">
              <div className="flex flex-wrap items-baseline justify-between gap-2">
                <h2 className="min-w-0 break-all font-mono text-lg font-semibold" data-testid="function-name">{sel.name}</h2>
                <p className="text-xs text-muted">{sel.addr}, {detail.summary.instructions} instructions, {detail.summary.blocks} blocks, complexity {detail.summary.cyclomaticComplexity}{detail.summary.loops ? `, ${detail.summary.loops} loops` : ''}</p>
              </div>
              <div className="mt-3 flex flex-wrap gap-1.5" role="tablist" aria-label="Function view">
                {([['pseudo', 'Pseudo code', SquareCode], ['graph', 'Graph', GitBranch], ['listing', 'Listing', ListTree]] as const).map(([id, label, I]) => (
                  <button key={id} type="button" role="tab" aria-selected={view === id} data-testid={`view-${id}`} onClick={() => setView(id)}
                    className={cx('inline-flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-sm transition', view === id ? 'border-accent/70 bg-accent/10 text-ink' : 'border-line text-muted hover:text-fg')}><I size={14} />{label}</button>
                ))}
              </div>
              <div className="mt-4">
                {view === 'pseudo' && <CodePanel text={pseudo} label="pseudo code (light lift)" testId="pseudocode" />}
                {view === 'graph' && <CfgView blocks={detail.blocks} />}
                {view === 'listing' && <CodePanel text={listing} label="disassembly" testId="listing" />}
              </div>
              {(detail.summary.calls.length > 0 || detail.summary.strings.length > 0) && (
                <div className="mt-4 grid grid-cols-1 gap-4 md:grid-cols-2">
                  {detail.summary.calls.length > 0 && <div><p className="mb-2 text-xs font-semibold uppercase tracking-widest text-ink">Calls</p><DataTable rows={detail.summary.calls as unknown as Record<string, unknown>[]} /></div>}
                  {detail.summary.strings.length > 0 && <div><p className="mb-2 text-xs font-semibold uppercase tracking-widest text-ink">Strings</p><DataTable rows={detail.summary.strings as unknown as Record<string, unknown>[]} /></div>}
                </div>
              )}
            </div>
          )}
          {file && info && <MatchPanel fileId={file.id} />}
        </div>
      </div>
    </div>
  );
}
