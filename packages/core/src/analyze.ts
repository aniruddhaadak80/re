import type { AnalyzeOptions, AnalyzerContext, Report } from './types.js';
import { REVLENS_VERSION } from './types.js';
import { detectFormat, isTextFormat, mimeOf } from './format.js';
import { md5, sha1, sha256, tlshLike, ctph } from './hash.js';
import { entropy, decodeUtf8 } from './bytes.js';
import { ANALYZER_LIST } from './analyzers/index.js';

const now = (): number => (typeof performance !== 'undefined' ? performance.now() : Date.now());

/** Severity rank used for sorting findings, highest first. */
const RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 } as const;

/**
 * Analyze a file. Pure function of the bytes plus options. Works in the browser,
 * a Web Worker and Node. Network is never used here (see lookupOSV for that).
 */
export async function analyze(bytes: Uint8Array, opts: AnalyzeOptions = {}, depth = 0): Promise<Report> {
  const t0 = now();
  const name = opts.name ?? 'input.bin';
  const format = detectFormat(bytes, name);
  const timings: Record<string, number> = {};

  const th = now();
  const report: Report = {
    schema: 'revlens/report@1',
    tool: { name: 'RevLens', version: REVLENS_VERSION },
    generatedAt: new Date().toISOString(),
    file: {
      name,
      size: bytes.length,
      format,
      mime: mimeOf(format),
      hashes: { md5: md5(bytes), sha1: sha1(bytes), sha256: sha256(bytes), tlsh: tlshLike(bytes) || undefined, ctph: ctph(bytes) },
      entropy: Number(entropy(bytes).toFixed(4)),
    },
    sections: [], imports: [], exports: [], strings: [], components: [], findings: [], capabilities: [],
    meta: {}, timings,
  };
  timings.hashes = round(now() - th);

  const options = { maxStrings: 400, recurse: true, maxDepth: 2, ...opts, name };
  const ctx: AnalyzerContext = {
    bytes, name, format, options, depth, report,
    text: isTextFormat(format) ? decodeUtf8(bytes) : undefined,
    analyzeChild: (b, n) => analyze(b, { ...opts, name: n }, depth + 1),
  };

  for (const a of ANALYZER_LIST) {
    if (opts.analyzers && !opts.analyzers.includes(a.id)) continue;
    let applies = false;
    try { applies = a.applies(ctx); } catch { applies = false; }
    if (!applies) continue;
    const ta = now();
    try {
      await a.run(ctx);
    } catch (err) {
      report.findings.push({
        id: `${a.id}.error`, analyzer: a.id, title: `${a.title} could not finish`, severity: 'info',
        detail: `The ${a.title} analyzer stopped early: ${(err as Error).message}. The rest of the report is still valid.`,
        evidence: [],
      });
    }
    timings[a.id] = round(now() - ta);
  }

  report.findings.sort((x, y) => RANK[y.severity] - RANK[x.severity]);
  timings.total = round(now() - t0);
  return report;
}

function round(n: number): number { return Math.round(n * 100) / 100; }
