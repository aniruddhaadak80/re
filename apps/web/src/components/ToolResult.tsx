import { useMemo, useState } from 'react';
import { ChevronDown, ChevronRight } from 'lucide-react';
import { CopyButton } from './ui';
import { cx } from '../lib/util';

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => typeof v === 'object' && v !== null && !Array.isArray(v) && !(v instanceof Uint8Array);
const scalar = (v: unknown) => v === null || ['string', 'number', 'boolean', 'bigint'].includes(typeof v);

/** JSON text that never throws on bigint or byte arrays. */
export function safeJson(v: unknown, space = 2): string {
  return JSON.stringify(v, (_k, x) => (typeof x === 'bigint' ? x.toString() : x instanceof Uint8Array ? `<${x.length} bytes>` : x), space) ?? '';
}

const TEXT_KEYS = ['pseudocode', 'code', 'smali', 'text', 'xml', 'listing', 'disassembly', 'il', 'javap', 'source'];

/** The main block of text in a tool result (code, pseudo code, smali, XML), if there is one. */
function primaryText(r: unknown): { key: string; text: string } | undefined {
  if (!isObj(r)) return typeof r === 'string' ? { key: 'text', text: r } : undefined;
  for (const k of TEXT_KEYS) { const v = r[k]; if (typeof v === 'string' && v.length > 0) return { key: k, text: v }; }
  for (const v of Object.values(r)) if (isObj(v)) for (const k of TEXT_KEYS) { const t = v[k]; if (typeof t === 'string' && t.includes('\n')) return { key: k, text: t }; }
  return undefined;
}

/** The main table in a tool result: the first list of objects, also inside { items }. */
function primaryTable(r: unknown, depth = 0): { key: string; rows: Obj[] } | undefined {
  if (!isObj(r) || depth > 2) return undefined;
  for (const [k, v] of Object.entries(r)) {
    if (Array.isArray(v) && v.length && v.every(isObj)) return { key: k, rows: v as Obj[] };
    if (isObj(v) && Array.isArray(v.items) && v.items.length && v.items.every(isObj)) return { key: k, rows: v.items as Obj[] };
  }
  for (const [, v] of Object.entries(r)) { if (isObj(v)) { const t = primaryTable(v, depth + 1); if (t) return t; } }
  return undefined;
}

function cell(v: unknown): string {
  if (v === undefined || v === null) return '';
  if (scalar(v)) return String(v);
  if (Array.isArray(v)) return v.every(scalar) ? v.join(', ') : `${v.length} items`;
  return safeJson(v, 0).slice(0, 120);
}

export function DataTable({ rows, testId }: { rows: Obj[]; testId?: string }) {
  const cols = useMemo(() => {
    const c: string[] = [];
    for (const r of rows.slice(0, 50)) for (const k of Object.keys(r)) if (!c.includes(k) && c.length < 8) c.push(k);
    return c;
  }, [rows]);
  return (
    <div className="max-h-[28rem] overflow-auto rounded-xl border border-line" data-testid={testId}>
      <table className="w-full text-left text-xs">
        <thead className="sticky top-0 bg-surface2 text-muted"><tr>{cols.map((c) => <th key={c} className="whitespace-nowrap px-3 py-2 font-medium">{c}</th>)}</tr></thead>
        <tbody>
          {rows.slice(0, 500).map((r, i) => (
            <tr key={i} className="border-t border-line/70 align-top">
              {cols.map((c) => <td key={c} className="max-w-[22rem] break-words px-3 py-1.5 font-mono text-fg">{cell(r[c])}</td>)}
            </tr>
          ))}
        </tbody>
      </table>
      {rows.length > 500 && <p className="px-3 py-2 text-xs text-muted">Showing 500 of {rows.length} rows.</p>}
    </div>
  );
}

function Node({ name, value, depth }: { name: string; value: unknown; depth: number }) {
  const [open, setOpen] = useState(depth < 1);
  if (!isObj(value) && !Array.isArray(value)) {
    return (
      <div className="flex min-w-0 gap-2 py-0.5 font-mono text-xs">
        <span className="shrink-0 text-muted">{name}</span>
        <span className={cx('min-w-0 break-all', typeof value === 'string' ? 'text-fg' : 'text-ink')}>{typeof value === 'string' ? (value.length > 400 ? `${value.slice(0, 400)}...` : value) : value instanceof Uint8Array ? `<${value.length} bytes>` : String(value)}</span>
      </div>
    );
  }
  const entries = Array.isArray(value) ? value.slice(0, 200).map((v, i) => [String(i), v] as const) : Object.entries(value);
  const size = Array.isArray(value) ? value.length : entries.length;
  return (
    <div className="min-w-0">
      <button type="button" className="flex items-center gap-1 py-0.5 font-mono text-xs text-muted hover:text-fg" onClick={() => setOpen((o) => !o)} aria-expanded={open}>
        {open ? <ChevronDown size={12} /> : <ChevronRight size={12} />}<span>{name}</span><span className="text-muted/70">{Array.isArray(value) ? `[${size}]` : `{${size}}`}</span>
      </button>
      {open && <div className="ml-3 border-l border-line/70 pl-3">{entries.map(([k, v]) => <Node key={k} name={k} value={v} depth={depth + 1} />)}</div>}
    </div>
  );
}

export function JsonTree({ value }: { value: unknown }) {
  return <div className="min-w-0 overflow-x-auto" data-testid="json-tree"><Node name="result" value={value} depth={0} /></div>;
}

export function CodePanel({ text, label, testId }: { text: string; label: string; testId?: string }) {
  return (
    <div className="min-w-0 rounded-xl border border-line bg-surface2/60">
      <div className="flex items-center justify-between border-b border-line px-3 py-1.5 text-xs text-muted"><span>{label}</span><CopyButton text={text} /></div>
      <pre className="max-h-[32rem] overflow-auto p-3 font-mono text-xs leading-5 text-fg" data-testid={testId}>{text.length > 400_000 ? text.slice(0, 400_000) + '\n...' : text}</pre>
    </div>
  );
}

/** Shows any package tool result: its main text, its main table, then the full JSON. */
export function ToolResult({ result, ms }: { result: unknown; ms?: number }) {
  const text = primaryText(result);
  const table = primaryTable(result);
  const json = safeJson(result);
  return (
    <div className="space-y-4" data-testid="tool-result">
      {text && <CodePanel text={text.text} label={text.key} testId="tool-text" />}
      {table && (
        <div>
          <p className="mb-2 text-xs font-semibold uppercase tracking-widest text-ink">{table.key} <span className="font-normal normal-case tracking-normal text-muted">({table.rows.length})</span></p>
          <DataTable rows={table.rows} testId="tool-table" />
        </div>
      )}
      <div className="rounded-xl border border-line p-3">
        <div className="mb-2 flex items-center justify-between text-xs text-muted"><span>Full result{ms !== undefined ? `, ${ms} ms` : ''}</span><CopyButton text={json} label="Copy JSON" /></div>
        <JsonTree value={result} />
      </div>
    </div>
  );
}
