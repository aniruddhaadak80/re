// WebMCP and MCP-over-web discovery, static part (no Node imports). Finds navigator.modelContext tool
// registrations in scripts, declarative tool forms and MCP links in HTML, agent hints in response headers,
// and classifies well-known discovery documents. Nothing found here is ever registered or invoked.
import { parseJs, walk, staticString, memberName, propKey, t } from './js/ast.js';

export interface WebMcpTool {
  name?: string;
  description?: string;
  /** property names of the inputSchema object literal, when written inline */
  inputProperties?: string[];
  required?: string[];
  api: string;
  line: number;
  column: number;
  offset: number;
  source?: string;
}

export interface WebMcpScriptScan {
  tools: WebMcpTool[];
  /** every navigator.modelContext member use, including reads and feature checks */
  uses: { api: string; line: number; offset: number }[];
  polyfills: { name: string; line: number }[];
  parserErrors: string[];
}

const MC_METHODS = new Set(['provideContext', 'registerTool', 'unregisterTool', 'clearContext', 'addTool', 'removeTool', 'tools']);

function objProps(n: t.Node | null | undefined): Map<string, t.Node> {
  const m = new Map<string, t.Node>();
  if (n && t.isObjectExpression(n)) for (const p of n.properties.slice(0, 500)) if (t.isObjectProperty(p) || t.isObjectMethod(p)) { const k = propKey(p); if (k) m.set(k, t.isObjectProperty(p) ? (p.value as t.Node) : p); }
  return m;
}

function toolFromObject(o: t.Node, api: string, site: { line: number; column: number; offset: number }, source?: string): WebMcpTool | undefined {
  if (!t.isObjectExpression(o)) return undefined;
  const props = objProps(o);
  const name = staticString(props.get('name') as t.Node);
  const description = staticString(props.get('description') as t.Node);
  const schema = props.get('inputSchema') ?? props.get('input_schema') ?? props.get('parameters');
  const sp = objProps(schema);
  const inputProperties = sp.has('properties') ? [...objProps(sp.get('properties')).keys()].slice(0, 100) : undefined;
  const reqNode = sp.get('required');
  const required = reqNode && t.isArrayExpression(reqNode) ? reqNode.elements.map((e) => staticString(e as t.Node)).filter((x): x is string => !!x).slice(0, 100) : undefined;
  if (!name && !description && !schema) return undefined;
  return { name: name?.slice(0, 200), description: description?.slice(0, 1000), inputProperties, required, api, ...site, source };
}

/** Scan one script for WebMCP tool registrations (navigator.modelContext provideContext and registerTool) without running it. */
export function scanWebMcpScript(code: string, opts: { source?: string; maxItems?: number } = {}): WebMcpScriptScan {
  const max = opts.maxItems ?? 500;
  const out: WebMcpScriptScan = { tools: [], uses: [], polyfills: [], parserErrors: [] };
  // cheap prefilter: skip parsing when no marker is present
  if (!/modelContext|webmcp|mcp-b|registerTool|provideContext/i.test(code)) return out;
  const { ast, errors } = parseJs(code);
  out.parserErrors = errors.slice(0, 20);
  if (!ast) return out;
  const site = (n: t.Node) => ({ line: n.loc?.start.line ?? 0, column: n.loc?.start.column ?? 0, offset: n.start ?? 0 });
  // names bound to navigator.modelContext, e.g. const mc = navigator.modelContext
  const aliases = new Set<string>(['modelContext']);
  walk(ast, ({ node }) => {
    if (t.isVariableDeclarator(node) && t.isIdentifier(node.id) && node.init) {
      const mn = memberName(node.init as t.Node);
      if (mn && /(?:^|\.)modelContext$/.test(mn)) aliases.add(node.id.name);
    }
    if (t.isAssignmentExpression(node) && t.isIdentifier(node.left)) {
      const mn = memberName(node.right as t.Node);
      if (mn && /(?:^|\.)modelContext$/.test(mn)) aliases.add(node.left.name);
    }
  });
  const isMc = (n: t.Node | null | undefined): boolean => {
    if (!n) return false;
    if (t.isIdentifier(n)) return aliases.has(n.name);
    const mn = memberName(n);
    return !!mn && /(?:^|\.)modelContext$/.test(mn);
  };
  walk(ast, ({ node }) => {
    if (out.tools.length >= max || out.uses.length >= max * 4) return 'stop';
    if ((t.isMemberExpression(node) || t.isOptionalMemberExpression(node)) && isMc(node.object as t.Node)) {
      const prop = !node.computed && t.isIdentifier(node.property) ? node.property.name : staticString(node.property as t.Node);
      if (prop) out.uses.push({ api: `modelContext.${prop}`, line: site(node).line, offset: site(node).offset });
    }
    if (t.isImportDeclaration(node) && isWebMcpPackage(node.source.value)) out.polyfills.push({ name: node.source.value.slice(0, 200), line: site(node).line });
    if (t.isCallExpression(node) || t.isOptionalCallExpression(node)) {
      const callee = node.callee as t.Node;
      if (t.isIdentifier(callee, { name: 'require' }) && node.arguments[0]) {
        const s = staticString(node.arguments[0] as t.Node);
        if (s && isWebMcpPackage(s)) out.polyfills.push({ name: s.slice(0, 200), line: site(node).line });
      }
      if (!(t.isMemberExpression(callee) || t.isOptionalMemberExpression(callee)) || !isMc(callee.object as t.Node)) return;
      const method = !callee.computed && t.isIdentifier(callee.property) ? callee.property.name : staticString(callee.property as t.Node);
      if (!method || !MC_METHODS.has(method)) return;
      const arg = node.arguments[0] as t.Node | undefined;
      const api = `modelContext.${method}`;
      if (method === 'provideContext') {
        const tools = objProps(arg).get('tools');
        if (tools && t.isArrayExpression(tools)) for (const el of tools.elements.slice(0, 200)) { const tt = el && toolFromObject(el as t.Node, api, site(el as t.Node), opts.source); if (tt) out.tools.push(tt); }
      } else if (method === 'registerTool' || method === 'addTool') {
        const tt = arg && toolFromObject(arg, api, site(node), opts.source);
        if (tt) out.tools.push(tt);
        else out.tools.push({ api, ...site(node), source: opts.source, name: undefined });
      } else if (method === 'unregisterTool' || method === 'removeTool') {
        out.tools.push({ api, name: arg ? staticString(arg)?.slice(0, 200) : undefined, ...site(node), source: opts.source });
      }
    }
  });
  return out;
}

export interface HtmlMcpHints {
  links: { rel: string; href: string; type?: string }[];
  meta: { name: string; content: string }[];
  /** declarative WebMCP forms (toolname / tooldescription attributes) */
  forms: { toolName: string; toolDescription?: string; action?: string; fields: string[] }[];
  scriptSrcs: string[];
  inlineScripts: string[];
}

const ATTR = /([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*(?:=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?/g;
function attrs(tag: string): Record<string, string> {
  const r: Record<string, string> = {};
  ATTR.lastIndex = 0;
  let m: RegExpExecArray | null; let n = 0;
  while ((m = ATTR.exec(tag)) && n++ < 100) r[m[1]!.toLowerCase()] = m[2] ?? m[3] ?? m[4] ?? '';
  return r;
}

/** Find MCP links, agent meta tags, declarative tool forms and script references in HTML. Linear scan, size capped. */
export function scanHtmlForMcp(html: string, opts: { maxBytes?: number } = {}): HtmlMcpHints {
  const src = html.slice(0, opts.maxBytes ?? 8 * 1024 * 1024);
  const out: HtmlMcpHints = { links: [], meta: [], forms: [], scriptSrcs: [], inlineScripts: [] };
  const lower = src.toLowerCase();
  let i = 0, guard = 0;
  let openForm: HtmlMcpHints['forms'][number] | undefined;
  while (i < src.length && guard++ < 500_000) {
    const lt = src.indexOf('<', i);
    if (lt < 0) break;
    const gt = src.indexOf('>', lt + 1);
    if (gt < 0) break;
    const tagText = src.slice(lt + 1, gt);
    const nameMatch = /^\/?([a-zA-Z][a-zA-Z0-9-]*)/.exec(tagText);
    i = gt + 1;
    if (!nameMatch) continue;
    const name = nameMatch[1]!.toLowerCase();
    const closing = tagText.startsWith('/');
    if (closing) { if (name === 'form') openForm = undefined; continue; }
    const a = attrs(tagText.slice(nameMatch[0].length, 4000));
    if (name === 'link' && a.rel && a.href !== undefined) {
      const rel = a.rel.toLowerCase();
      if (/\b(?:mcp|model-?context|webmcp|ai-plugin|llms|agent)\b/.test(rel) || /mcp|model-context/i.test(a.type ?? '') || /\.well-known\/(?:mcp|model-context|ai-plugin|agent)/i.test(a.href)) out.links.push({ rel: a.rel.slice(0, 100), href: a.href.slice(0, 2000), type: a.type });
    } else if (name === 'meta' && (a.name || a.property)) {
      const n = (a.name ?? a.property)!.toLowerCase();
      if (/mcp|model-?context|webmcp|ai-plugin|agent/.test(n)) out.meta.push({ name: n.slice(0, 100), content: (a.content ?? '').slice(0, 2000) });
    } else if (name === 'form') {
      const tn = a.toolname ?? a['tool-name'] ?? a['data-tool-name'];
      openForm = tn !== undefined ? { toolName: tn.slice(0, 200), toolDescription: (a.tooldescription ?? a['tool-description'] ?? a['data-tool-description'])?.slice(0, 1000), action: a.action?.slice(0, 2000), fields: [] } : undefined;
      if (openForm && out.forms.length < 200) out.forms.push(openForm);
    } else if ((name === 'input' || name === 'select' || name === 'textarea') && openForm && a.name && openForm.fields.length < 100) {
      openForm.fields.push(a.name.slice(0, 100));
    } else if (name === 'script') {
      if (a.src) { if (out.scriptSrcs.length < 500) out.scriptSrcs.push(a.src.slice(0, 2000)); }
      else {
        const end = lower.indexOf('</script', gt + 1);
        const body = src.slice(gt + 1, end < 0 ? src.length : end);
        if (body.trim() && out.inlineScripts.length < 200) out.inlineScripts.push(body.slice(0, 2 * 1024 * 1024));
        i = end < 0 ? src.length : end;
      }
    } else if (name === 'style') {
      const end = lower.indexOf('</style', gt + 1); i = end < 0 ? src.length : end;
    }
  }
  return out;
}

/** Well-known paths probed for MCP, agent and AI plugin discovery documents. */
export const WELL_KNOWN_PATHS = [
  '/.well-known/mcp',
  '/.well-known/mcp.json',
  '/.well-known/mcp/server-card.json',
  '/.well-known/model-context',
  '/.well-known/ai-plugin.json',
  '/.well-known/agent.json',
  '/.well-known/agent-card.json',
  '/.well-known/oauth-protected-resource',
  '/llms.txt',
] as const;

export const AGENT_HEADERS = ['x-model-context', 'x-webmcp', 'mcp-server', 'mcp-session-id', 'link'] as const;

export interface WellKnownDoc {
  path: string;
  status: number;
  contentType?: string;
  kind: 'mcp-server-card' | 'mcp-endpoint' | 'ai-plugin' | 'a2a-agent-card' | 'oauth-protected-resource' | 'llms-txt' | 'json' | 'other';
  name?: string;
  description?: string;
  endpoints: string[];
  tools: string[];
  size: number;
}

/** Classify a fetched well-known document and pull out names, endpoints and tool names. */
export function classifyWellKnown(path: string, status: number, contentType: string | undefined, body: string): WellKnownDoc {
  const doc: WellKnownDoc = { path, status, contentType, kind: 'other', endpoints: [], tools: [], size: body.length };
  if (path === '/llms.txt') {
    if (status === 200 && !/html/i.test(contentType ?? '') && /^#\s/m.test(body.slice(0, 4000))) {
      doc.kind = 'llms-txt';
      doc.name = /^#\s+(.{1,200})$/m.exec(body)?.[1]?.trim();
      const links = body.slice(0, 200_000).match(/\]\((https?:\/\/[^)\s]{1,500})\)/g) ?? [];
      doc.endpoints = links.slice(0, 50).map((l) => l.slice(2, -1));
    }
    return doc;
  }
  let j: any;
  try { j = JSON.parse(body.slice(0, 2 * 1024 * 1024)); } catch { return doc; }
  if (!j || typeof j !== 'object') return doc;
  doc.kind = 'json';
  const str = (v: unknown) => (typeof v === 'string' ? v.slice(0, 1000) : undefined);
  const push = (v: unknown) => { if (typeof v === 'string' && /^(?:https?|wss?):\/\//i.test(v) && doc.endpoints.length < 50) doc.endpoints.push(v.slice(0, 2000)); };
  const toolsFrom = (arr: unknown) => { if (Array.isArray(arr)) for (const x of arr.slice(0, 500)) { const n = typeof x === 'string' ? x : str(x?.name); if (n) doc.tools.push(n.slice(0, 200)); } };
  if (j.schema_version && (j.name_for_model || j.name_for_human)) {
    doc.kind = 'ai-plugin'; doc.name = str(j.name_for_human ?? j.name_for_model); doc.description = str(j.description_for_human ?? j.description_for_model); push(j.api?.url);
  } else if (Array.isArray(j.skills) && (j.url || j.capabilities)) {
    doc.kind = 'a2a-agent-card'; doc.name = str(j.name); doc.description = str(j.description); push(j.url); toolsFrom(j.skills.map((s: any) => s?.name ?? s?.id));
  } else if (j.resource && (j.authorization_servers || j.scopes_supported)) {
    doc.kind = 'oauth-protected-resource'; push(j.resource); for (const s of j.authorization_servers ?? []) push(s);
  } else if (j.serverInfo || j.mcp_version || j.protocolVersion || j.transport || j.endpoint || j.endpoints || j.mcpServers || j.servers) {
    doc.kind = j.serverInfo || j.tools || j.capabilities ? 'mcp-server-card' : 'mcp-endpoint';
    doc.name = str(j.serverInfo?.name ?? j.name); doc.description = str(j.description ?? j.serverInfo?.description);
    push(j.endpoint); push(j.url); push(j.transport?.url); push(j.transport?.endpoint);
    if (Array.isArray(j.endpoints)) for (const e of j.endpoints) push(typeof e === 'string' ? e : e?.url);
    if (j.mcpServers && typeof j.mcpServers === 'object') for (const s of Object.values(j.mcpServers).slice(0, 50)) push((s as any)?.url);
    if (Array.isArray(j.servers)) for (const s of j.servers.slice(0, 50)) push(s?.url ?? s?.endpoint);
    toolsFrom(j.tools);
  }
  return doc;
}

/** Pull agent hints out of response headers (MCP session ids, WebMCP headers and Link rel values). */
export function agentHeaderHints(headers: Record<string, string>): { name: string; value: string }[] {
  const out: { name: string; value: string }[] = [];
  for (const [k, v] of Object.entries(headers).slice(0, 300)) {
    const n = k.toLowerCase();
    if (n === 'link') { if (/rel="?[^";]*(?:mcp|model-context|ai-plugin|agent)/i.test(v) || /\.well-known\/(?:mcp|model-context)/i.test(v)) out.push({ name: n, value: v.slice(0, 2000) }); }
    else if ((AGENT_HEADERS as readonly string[]).includes(n)) out.push({ name: n, value: n === 'mcp-session-id' ? '[present]' : v.slice(0, 2000) });
  }
  return out;
}

/** A WebMCP polyfill or helper package: any @mcp-b/ package, or a name that mentions webmcp. */
function isWebMcpPackage(name: string): boolean {
  const n = name.toLowerCase();
  return n.startsWith('@mcp-b/') || n.includes('webmcp');
}
