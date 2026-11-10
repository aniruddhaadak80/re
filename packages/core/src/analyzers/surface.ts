import type { Analyzer } from '../types.js';

const URL_RE = /\bhttps?:\/\/[A-Za-z0-9.-]+(?::\d+)?(?:\/[^\s"'`<>()\\]*)?/g;
const PATH_RE = /["'`](\/(?:api|v\d|graphql|rest|rpc|auth|oauth|admin|internal)[\w\/.{}:-]*)["'`]/g;
const GQL_RE = /\b(query|mutation|subscription)\s+([A-Z]\w{2,60})\s*[({]/g;
const IPC_RE = /\bipc(?:Renderer|Main)\.(?:on|once|send|invoke|handle|sendSync)\(\s*["'`]([\w:.\/-]{2,80})["'`]/g;
const FLAG_RE = /\b(?:isFeatureEnabled|featureFlag|getFlag|useFlag|feature_flag|flags?\.get)\(\s*["'`]([\w.:-]{3,80})["'`]/g;
const STORAGE_RE = /\b(?:localStorage|sessionStorage)\.(?:getItem|setItem)\(\s*["'`]([\w.:-]{2,80})["'`]/g;
const NOISE = /(w3\.org|schemas\.(?:openxmlformats|microsoft)|xmlns|purl\.org|example\.(?:com|org)|localhost:?\d*\/?$|mozilla\.org\/MPL|apache\.org\/licenses|opensource\.org|reactjs\.org\/docs\/error-decoder|fb\.me\/|github\.com\/[\w-]+\/[\w-]+\/(?:issues|blob))/;

export const surfaceAnalyzer: Analyzer = {
  id: 'surface',
  title: 'Attack surface',
  description: 'Maps network endpoints, API paths, GraphQL operations, Electron IPC channels, feature flags and storage keys.',
  applies: (ctx) => !!ctx.text || ctx.report.strings.length > 0,
  run(ctx) {
    const { report } = ctx;
    const text = ctx.text ? (ctx.text.length > 12_000_000 ? ctx.text.slice(0, 12_000_000) : ctx.text) : report.strings.map((s) => s.value).join('\n');
    const collect = (re: RegExp, group = 1, cap = 300) => {
      const set = new Set<string>();
      re.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = re.exec(text)) && set.size < cap) set.add(m[group] as string);
      return [...set];
    };
    const urls = collect(URL_RE, 0).map((u) => u.replace(/[.,;]+$/, '')).filter((u) => !NOISE.test(u));
    const hosts = [...new Set(urls.map((u) => { try { return new URL(u).host; } catch { return ''; } }).filter(Boolean))];
    const apiPaths = collect(PATH_RE);
    const graphql = collect(GQL_RE, 0).map((s) => s.replace(/\s*[({]$/, ''));
    const ipc = collect(IPC_RE);
    const flags = collect(FLAG_RE);
    const storage = collect(STORAGE_RE);
    report.meta.surface = { urls: urls.slice(0, 200), hosts, apiPaths, graphql, ipc, flags, storage };
    const insecure = urls.filter((u) => u.startsWith('http://') && !/^http:\/\/(localhost|127\.|0\.0\.0\.0|\[::1\])/.test(u));
    if (insecure.length) {
      report.findings.push({ id: 'surface.http', analyzer: 'surface', title: `${insecure.length} plain HTTP endpoints`, severity: 'low',
        detail: `Traffic to ${insecure.slice(0, 3).join(', ')} is not encrypted and can be read or changed on the network.`, evidence: insecure.slice(0, 5).map((u) => ({ snippet: u })), tags: ['network'] });
    }
    if (ipc.length) {
      report.findings.push({ id: 'surface.ipc', analyzer: 'surface', title: `${ipc.length} Electron IPC channels`, severity: 'info',
        detail: `IPC channels such as ${ipc.slice(0, 4).join(', ')} are the bridge between web content and Node. Check each handler validates its input.`, evidence: ipc.slice(0, 8).map((c) => ({ snippet: c })), tags: ['electron', 'ipc'] });
    }
  },
};
