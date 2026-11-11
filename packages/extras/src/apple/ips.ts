// Apple .ips crash and diagnostic reports (macOS 12+, iOS 15+): a JSON metadata line
// followed by a JSON body. Frames are joined to the images they belong to, with addresses.

import { ParseError, utf8 } from '../util.js';

export interface IpsFrame { index: number; image?: string; imageOffset: number; address?: string; symbol?: string; symbolLocation?: number; sourceFile?: string; sourceLine?: number }
export interface IpsThread { index: number; id?: number; name?: string; queue?: string; triggered: boolean; frames: IpsFrame[]; framesTruncated: boolean }
export interface IpsImage { index: number; name?: string; path?: string; uuid?: string; base?: string; size?: number; arch?: string; source?: string }
export interface AppleIps {
  bugType: string;
  kind: string;
  header: Record<string, unknown>;
  process?: { name?: string; path?: string; pid?: number; parent?: string; bundleId?: string; version?: string; build?: string };
  os?: string;
  cpuType?: string;
  incident?: string;
  timestamp?: string;
  exception?: { type?: string; signal?: string; codes?: string; subtype?: string; message?: string };
  termination?: { namespace?: string; code?: number; indicator?: string; reasons?: string[] };
  faultingThread?: number;
  threads: IpsThread[];
  images: IpsImage[];
  crashedFrames: IpsFrame[];
}

const BUG_TYPES: Record<string, string> = { '109': 'legacy crash', '309': 'crash', '298': 'hang (stackshot)', '210': 'panic', '288': 'stackshot', '385': 'jetsam', '145': 'cpu resource', '142': 'wakeups resource', '202': 'disk writes resource', '211': 'analytics', '313': 'cpu resource' };

/** Parse an .ips report. Large reports are capped at `maxThreads` threads and `maxFrames` frames per thread. */
export function parseIps(input: Uint8Array | string, opts: { maxThreads?: number; maxFrames?: number } = {}): AppleIps {
  const text = typeof input === 'string' ? input : utf8(input);
  if (text.length > 64 << 20) throw new ParseError('report larger than 64 MiB');
  const nl = text.indexOf('\n');
  if (nl < 0) throw new ParseError('an .ips report has a JSON header line and a JSON body');
  let header: Record<string, unknown>;
  let body: Record<string, unknown>;
  try { header = JSON.parse(text.slice(0, nl)); } catch { throw new ParseError('first line is not JSON', 0); }
  try { body = JSON.parse(text.slice(nl + 1)); } catch { throw new ParseError('report body is not JSON', nl + 1); }
  if (typeof header !== 'object' || header === null || !('bug_type' in header)) throw new ParseError('header has no bug_type');
  const bt = String(header.bug_type);
  const s = (x: unknown): string | undefined => (typeof x === 'string' ? x : undefined);
  const n = (x: unknown): number | undefined => (typeof x === 'number' ? x : undefined);
  const imgsRaw = Array.isArray(body.usedImages) ? body.usedImages as Record<string, unknown>[] : [];
  const images: IpsImage[] = imgsRaw.slice(0, 5000).map((im, i) => ({
    index: i, name: s(im.name), path: s(im.path), uuid: s(im.uuid), base: typeof im.base === 'number' ? '0x' + im.base.toString(16) : undefined,
    size: n(im.size), arch: s(im.arch), source: s(im.source),
  }));
  const maxT = opts.maxThreads ?? 64, maxF = opts.maxFrames ?? 128;
  const thrRaw = Array.isArray(body.threads) ? body.threads as Record<string, unknown>[] : [];
  const threads: IpsThread[] = thrRaw.slice(0, maxT).map((t, ti) => {
    const fr = Array.isArray(t.frames) ? t.frames as Record<string, unknown>[] : [];
    return {
      index: ti, id: n(t.id), name: s(t.name), queue: s(t.queue), triggered: t.triggered === true, framesTruncated: fr.length > maxF,
      frames: fr.slice(0, maxF).map((f, fi) => {
        const ii = n(f.imageIndex);
        const im = ii !== undefined ? imgsRaw[ii] : undefined;
        const off = n(f.imageOffset) ?? 0;
        const base = im && typeof im.base === 'number' ? im.base : undefined;
        return {
          index: fi, image: ii !== undefined ? (s(im?.name) ?? `image ${ii}`) : undefined, imageOffset: off,
          address: base !== undefined ? '0x' + (base + off).toString(16) : undefined, symbol: s(f.symbol), symbolLocation: n(f.symbolLocation),
          sourceFile: s(f.sourceFile), sourceLine: n(f.sourceLine),
        };
      }),
    };
  });
  const ex = (body.exception ?? {}) as Record<string, unknown>;
  const term = (body.termination ?? undefined) as Record<string, unknown> | undefined;
  const osv = body.osVersion as Record<string, unknown> | undefined;
  const ft = n(body.faultingThread);
  const crashed = threads.find((t) => t.triggered) ?? (ft !== undefined ? threads[ft] : undefined);
  return {
    bugType: bt, kind: BUG_TYPES[bt] ?? 'unknown', header,
    process: { name: s(body.procName) ?? s(header.app_name) ?? s(header.name), path: s(body.procPath), pid: n(body.pid), parent: s(body.parentProc), bundleId: s(header.bundleID) ?? s((body.bundleInfo as Record<string, unknown> | undefined)?.CFBundleIdentifier), version: s(header.app_version), build: s(header.build_version) },
    os: s(header.os_version) ?? (osv ? `${s(osv.train) ?? ''} ${s(osv.build) ?? ''}`.trim() : undefined), cpuType: s(body.cpuType), incident: s(header.incident_id) ?? s(body.incident), timestamp: s(header.timestamp) ?? s(body.captureTime),
    exception: Object.keys(ex).length ? { type: s(ex.type), signal: s(ex.signal), codes: s(ex.codes), subtype: s(ex.subtype), message: s(ex.message) } : undefined,
    termination: term ? { namespace: s(term.namespace), code: n(term.code), indicator: s(term.indicator), reasons: Array.isArray(term.reasons) ? (term.reasons as unknown[]).map(String).slice(0, 32) : undefined } : undefined,
    faultingThread: ft, threads, images, crashedFrames: crashed?.frames ?? [],
  };
}
