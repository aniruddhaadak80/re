import { useCallback, useEffect, useRef, useState } from 'react';
import { Atom, Boxes, Braces, Cpu, Database, FileCheck2, FlaskConical, Loader2, Network, Smartphone } from 'lucide-react';
import { DropZone } from '../../components/DropZone';
import { forgetInWorker, loadInWorker, newId, toolInWorker } from '../../lib/engine';
import { loadLabSample, type Lab, type LabSample } from '../../lib/labs';
import { formatBytes } from '../../lib/util';

export const LAB_ICONS = { cpu: Cpu, smartphone: Smartphone, boxes: Boxes, braces: Braces, atom: Atom, network: Network, database: Database } as const;

export interface LabFile { id: string; name: string; size: number; sample?: LabSample }

/** One file loaded into the worker for a lab. Swapping files forgets the old one. */
export function useLabFile() {
  const [file, setFile] = useState<LabFile | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const current = useRef<string | null>(null);
  useEffect(() => () => { if (current.current) forgetInWorker(current.current); }, []);
  const load = useCallback(async (name: string, bytes: Uint8Array, sample?: LabSample): Promise<LabFile | null> => {
    setLoading(true); setError('');
    try {
      if (current.current) forgetInWorker(current.current);
      const id = newId('lab');
      current.current = id;
      await loadInWorker(id, bytes);
      const f = { id, name, size: bytes.length, sample };
      setFile(f);
      return f;
    } catch (e) { setError((e as Error).message); return null; } finally { setLoading(false); }
  }, []);
  const loadSample = useCallback(async (s: LabSample) => {
    try { return await load(s.file.split('/').pop() ?? s.file, await loadLabSample(s), s); } catch (e) { setError((e as Error).message); return null; }
  }, [load]);
  return { file, loading, error, load, loadSample };
}

/** Runs package tools on the loaded file and keeps the latest result. */
export function useTool() {
  const [state, setState] = useState<{ tool?: string; result?: unknown; ms?: number; error?: string; busy: boolean }>({ busy: false });
  const seq = useRef(0);
  const run = useCallback(async (fileId: string, tool: string, args: Record<string, unknown> = {}) => {
    const my = ++seq.current;
    setState({ tool, busy: true });
    try {
      const r = await toolInWorker(fileId, tool, args);
      if (my === seq.current) setState({ tool, result: r.result, ms: r.ms, busy: false });
      return r.result;
    } catch (e) {
      if (my === seq.current) setState({ tool, error: (e as Error).message, busy: false });
      return undefined;
    }
  }, []);
  return { ...state, run };
}

export function FilePicker({ lab, file, loading, error, onFile, onSample }: {
  lab: Lab; file: LabFile | null; loading: boolean; error: string;
  onFile: (name: string, bytes: Uint8Array) => void; onSample: (s: LabSample) => void;
}) {
  return (
    <div className="card p-4">
      <p className="mb-3 text-xs font-semibold uppercase tracking-widest text-ink">The file</p>
      {file && (
        <div className="mb-3 flex items-center gap-3 rounded-xl border border-line bg-surface2/60 p-3">
          {loading ? <Loader2 size={18} className="animate-spin text-ink" /> : <FileCheck2 size={18} className="text-teal" />}
          <div className="min-w-0"><p className="truncate font-medium" data-testid="lab-file">{file.name}</p><p className="text-xs text-muted">{formatBytes(file.size)}{file.sample ? `, ${file.sample.note}` : ''}</p></div>
        </div>
      )}
      <DropZone compact multiple={false} testId="lab-input" hint={<span>{lab.accepts}. The file stays in your browser.</span>}
        onFiles={async (fl) => { const x = fl[0]; if (x) onFile(x.name, new Uint8Array(await x.arrayBuffer())); }} />
      <p className="mb-2 mt-4 flex items-center gap-1.5 text-xs font-medium uppercase tracking-wider text-muted"><FlaskConical size={13} />Try a sample</p>
      <div className="flex flex-wrap gap-1.5">
        {lab.samples.map((s) => (
          <button key={s.id} type="button" className="chip transition hover:border-accent/60 hover:text-fg" title={s.note} data-testid={`sample-${s.id}`} onClick={() => onSample(s)}>{s.label}</button>
        ))}
      </div>
      {error && <p className="mt-3 text-sm text-red-500" role="alert">{error}</p>}
    </div>
  );
}
