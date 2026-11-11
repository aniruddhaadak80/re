// Playwright trace reader (trace.zip from context.tracing). Lists actions with timing and errors,
// network requests, console messages, pages and screencast frames. Node only (uses zlib).
import { open } from 'node:fs/promises';
import { inflateRawSync } from 'node:zlib';
import { InputError } from './util.js';

interface ZipEntry { name: string; method: number; compSize: number; size: number; localOffset: number }

/** Read the central directory of a zip file. Bounds-checked; no zip64. */
export function listZip(buf: Uint8Array, maxEntries = 100_000): ZipEntry[] {
  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  let eocd = -1;
  for (let i = buf.length - 22; i >= Math.max(0, buf.length - 22 - 65_535); i--) if (dv.getUint32(i, true) === 0x06054b50) { eocd = i; break; }
  if (eocd < 0) throw new InputError('not a zip file (no end of central directory)');
  const count = dv.getUint16(eocd + 10, true);
  let off = dv.getUint32(eocd + 16, true);
  const out: ZipEntry[] = [];
  for (let n = 0; n < Math.min(count, maxEntries); n++) {
    if (off + 46 > buf.length || dv.getUint32(off, true) !== 0x02014b50) throw new InputError('corrupt zip central directory');
    const method = dv.getUint16(off + 10, true), compSize = dv.getUint32(off + 20, true), size = dv.getUint32(off + 24, true);
    const nl = dv.getUint16(off + 28, true), el = dv.getUint16(off + 30, true), cl = dv.getUint16(off + 32, true);
    const localOffset = dv.getUint32(off + 42, true);
    if (off + 46 + nl > buf.length) throw new InputError('corrupt zip name');
    out.push({ name: new TextDecoder().decode(buf.subarray(off + 46, off + 46 + nl)), method, compSize, size, localOffset });
    off += 46 + nl + el + cl;
  }
  return out;
}

/** Read one zip member, refusing members larger than maxBytes. */
export function readZipEntry(buf: Uint8Array, e: ZipEntry, maxBytes = 256 * 1024 * 1024): Uint8Array {
  if (e.size > maxBytes) throw new InputError(`${e.name} is ${e.size} bytes, over the limit`);
  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const o = e.localOffset;
  if (o + 30 > buf.length || dv.getUint32(o, true) !== 0x04034b50) throw new InputError(`bad local header for ${e.name}`);
  const start = o + 30 + dv.getUint16(o + 26, true) + dv.getUint16(o + 28, true);
  if (start + e.compSize > buf.length) throw new InputError(`truncated zip member ${e.name}`);
  const data = buf.subarray(start, start + e.compSize);
  if (e.method === 0) return data;
  if (e.method === 8) return new Uint8Array(inflateRawSync(data, { maxOutputLength: Math.max(1, Math.min(maxBytes, e.size || maxBytes)) }));
  throw new InputError(`unsupported zip method ${e.method} for ${e.name}`);
}

export interface TraceAction { callId: string; api: string; selector?: string; url?: string; startTime: number; endTime?: number; durationMs?: number; error?: string; pageId?: string }
export interface TraceSummary {
  path: string;
  files: number;
  version?: number;
  browserName?: string;
  platform?: string;
  title?: string;
  actions: { total: number; failed: number; items: TraceAction[] };
  network: { total: number; items: { method: string; url: string; status: number; mimeType?: string; durationMs?: number }[] };
  console: { total: number; items: { type: string; text: string }[] };
  pages: string[];
  screencastFrames: number;
  resources: number;
  errors: string[];
  warnings: string[];
}

function ndjson(text: string, cb: (o: any) => void, max = 500_000): number {
  let n = 0;
  for (const line of text.split('\n')) {
    if (!line || n >= max) continue;
    try { cb(JSON.parse(line)); n++; } catch { /* skip bad line */ }
  }
  return n;
}

/** Summarize a Playwright trace.zip: actions with timing and errors, network, console, pages and frames. */
export async function inspectPlaywrightTrace(path: string, opts: { limit?: number; maxBytes?: number } = {}): Promise<TraceSummary> {
  const maxBytes = opts.maxBytes ?? 512 * 1024 * 1024;
  // one descriptor for the size check and the read
  const fh = await open(path, 'r');
  let buf: Uint8Array;
  try {
    const st = await fh.stat();
    if (st.size > maxBytes) throw new InputError(`trace is ${st.size} bytes, over the limit`);
    buf = new Uint8Array(await fh.readFile());
  } finally { await fh.close(); }
  const entries = listZip(buf);
  const lim = Math.max(1, Math.min(opts.limit ?? 500, 10_000));
  const r: TraceSummary = { path, files: entries.length, actions: { total: 0, failed: 0, items: [] }, network: { total: 0, items: [] }, console: { total: 0, items: [] }, pages: [], screencastFrames: 0, resources: entries.filter((e) => e.name.startsWith('resources/')).length, errors: [], warnings: [] };
  const actions = new Map<string, TraceAction>();
  const pages = new Set<string>();
  for (const e of entries) {
    if (/\.trace$/.test(e.name)) {
      let text: string;
      try { text = new TextDecoder().decode(readZipEntry(buf, e)); } catch (err) { r.warnings.push(`${e.name}: ${(err as Error).message}`); continue; }
      ndjson(text, (o) => {
        switch (o.type) {
          case 'context-options': r.version = o.version; r.browserName = o.browserName; r.platform = o.platform; r.title = o.title ?? r.title; break;
          case 'before': {
            const p = o.params ?? {};
            if (actions.size < 100_000) actions.set(String(o.callId), { callId: String(o.callId), api: String(o.apiName ?? o.title ?? `${o.class}.${o.method}`).slice(0, 200), selector: typeof p.selector === 'string' ? p.selector.slice(0, 500) : undefined, url: typeof p.url === 'string' ? p.url.slice(0, 2000) : undefined, startTime: Number(o.startTime ?? 0), pageId: o.pageId });
            if (o.pageId) pages.add(String(o.pageId));
            break;
          }
          case 'after': {
            const a = actions.get(String(o.callId));
            if (a) { a.endTime = Number(o.endTime ?? 0); a.durationMs = Math.round((a.endTime - a.startTime) * 1000) / 1000; if (o.error) a.error = String(o.error.message ?? o.error.error?.message ?? JSON.stringify(o.error)).slice(0, 500); }
            break;
          }
          case 'console': r.console.total++; if (r.console.items.length < lim) r.console.items.push({ type: String(o.messageType ?? o.params?.type ?? 'log'), text: String(o.text ?? o.params?.text ?? '').slice(0, 1000) }); break;
          case 'screencast-frame': r.screencastFrames++; if (o.pageId) pages.add(String(o.pageId)); break;
          case 'error': if (r.errors.length < 200) r.errors.push(String(o.message ?? '').slice(0, 1000)); break;
          case 'event': if (o.method === 'pageError' || o.method === 'pageerror') { if (r.errors.length < 200) r.errors.push(String(o.params?.error?.error?.message ?? o.params?.error?.message ?? '').slice(0, 1000)); } break;
          default: break;
        }
      });
    } else if (/\.network$/.test(e.name)) {
      let text: string;
      try { text = new TextDecoder().decode(readZipEntry(buf, e)); } catch (err) { r.warnings.push(`${e.name}: ${(err as Error).message}`); continue; }
      ndjson(text, (o) => {
        if (o.type !== 'resource-snapshot') return;
        const s = o.snapshot ?? {};
        r.network.total++;
        if (r.network.items.length < lim) r.network.items.push({ method: String(s.request?.method ?? 'GET'), url: String(s.request?.url ?? '').slice(0, 2000), status: Number(s.response?.status ?? 0), mimeType: s.response?.content?.mimeType, durationMs: typeof s.time === 'number' ? Math.round(s.time) : undefined });
      });
    }
  }
  const all = [...actions.values()].sort((a, b) => a.startTime - b.startTime);
  r.actions.total = all.length;
  r.actions.failed = all.filter((a) => a.error).length;
  r.actions.items = all.slice(0, lim);
  r.pages = [...pages].slice(0, 100);
  return r;
}
