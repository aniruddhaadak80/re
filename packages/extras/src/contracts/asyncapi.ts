// AsyncAPI 2.x and 3.x documents embedded in binaries (Go embed, resources) and JS bundles, found
// with the same scanner as OpenAPI (JSON, YAML, JS literals, JSON strings in JS). The summary
// lists servers, channels with their addresses and messages, and operations normalised across the
// two major versions (2.x publish/subscribe inside channels, 3.x send/receive at the top level).

import { scanSpecDocuments, type OpenApiSummary } from './openapi.js';
import type { JsValue } from './jsvalue.js';

type Obj = { [k: string]: JsValue };
const isObj = (v: unknown): v is Obj => typeof v === 'object' && v !== null && !Array.isArray(v);
const str = (v: unknown): string | undefined => (typeof v === 'string' ? v : typeof v === 'number' ? String(v) : undefined);

export interface AsyncApiServer { name: string; url: string; protocol?: string; protocolVersion?: string; description?: string; security: string[] }
export interface AsyncApiChannel { name: string; address: string | null; parameters: string[]; messages: string[]; bindings: string[]; description?: string }
export interface AsyncApiOperation { id: string; action: 'publish' | 'subscribe' | 'send' | 'receive'; channel: string; messages: string[]; summary?: string; operationId?: string; bindings: string[]; security: string[] }
export interface AsyncApiSummary {
  offset: number; length: number; format: OpenApiSummary['format'];
  spec: 'asyncapi'; version: string; major: 2 | 3; id?: string; title?: string; apiVersion?: string; defaultContentType?: string;
  servers: AsyncApiServer[]; channels: AsyncApiChannel[]; operations: AsyncApiOperation[];
  messages: string[]; schemas: string[]; securitySchemes: string[]; protocols: string[]; document: JsValue;
}

function isAsyncApi(v: unknown): v is Obj {
  if (!isObj(v)) return false;
  const ver = str(v.asyncapi);
  return !!ver && /^[23]\.\d+(\.\d+)?(-[\w.]+)?$/.test(ver) && (isObj(v.info) || isObj(v.channels) || isObj(v.operations));
}

/** Last path segment of a local $ref such as #/components/messages/lightMeasured. */
const refName = (v: unknown): string | undefined => {
  if (!isObj(v) || typeof v.$ref !== 'string') return undefined;
  const parts = v.$ref.split('/');
  return decodeURIComponent((parts[parts.length - 1] ?? v.$ref).replace(/~1/g, '/').replace(/~0/g, '~'));
};
/** Names for a v2 message field: a $ref, a named message, or oneOf of them. */
function v2Messages(m: unknown): string[] {
  if (!isObj(m)) return [];
  if (Array.isArray(m.oneOf)) return m.oneOf.flatMap((x) => v2Messages(x));
  const r = refName(m);
  return r ? [r] : [str(m.name) ?? str(m.messageId) ?? str(m.title) ?? '(inline)'];
}
const secNames = (s: unknown): string[] => {
  if (!Array.isArray(s)) return [];
  const out: string[] = [];
  for (const x of s) {
    if (!isObj(x)) continue;
    const r = refName(x);
    if (r) out.push(r); // 3.x reference to a security scheme
    else if (typeof x.type === 'string') out.push(`(${x.type})`); // 3.x inline scheme
    else out.push(...Object.keys(x)); // 2.x requirement map {scheme: [scopes]}
  }
  return [...new Set(out)];
};

/** Summarize a parsed AsyncAPI 2.x or 3.x document. */
export function summarizeAsyncApi(doc: Obj, where: { offset: number; length: number; format: OpenApiSummary['format'] }): AsyncApiSummary {
  const version = str(doc.asyncapi) ?? '';
  const major = version.startsWith('3') ? 3 : 2;
  const info = isObj(doc.info) ? doc.info : {};
  const servers: AsyncApiServer[] = [];
  if (isObj(doc.servers)) for (const [name, s0] of Object.entries(doc.servers)) {
    if (!isObj(s0)) continue;
    const url = major === 3 ? `${str(s0.protocol) ? str(s0.protocol) + '://' : ''}${str(s0.host) ?? ''}${str(s0.pathname) ?? ''}` : str(s0.url) ?? '';
    servers.push({ name, url, ...(str(s0.protocol) ? { protocol: str(s0.protocol) } : {}), ...(str(s0.protocolVersion) ? { protocolVersion: str(s0.protocolVersion) } : {}), ...(str(s0.description) ? { description: str(s0.description) } : {}), security: secNames(s0.security) });
  }
  const channels: AsyncApiChannel[] = [];
  const operations: AsyncApiOperation[] = [];
  const chs = isObj(doc.channels) ? doc.channels : {};
  for (const [name, c] of Object.entries(chs)) {
    if (!isObj(c)) continue;
    const params = isObj(c.parameters) ? Object.keys(c.parameters) : [];
    const bindings = isObj(c.bindings) ? Object.keys(c.bindings) : [];
    if (major === 3) {
      const address = c.address === null ? null : str(c.address) ?? null;
      const msgs = isObj(c.messages) ? Object.keys(c.messages) : [];
      channels.push({ name, address, parameters: params, messages: msgs, bindings, ...(str(c.description) ? { description: str(c.description) } : {}) });
    } else {
      const msgs: string[] = [];
      for (const action of ['publish', 'subscribe'] as const) {
        const op = c[action];
        if (!isObj(op)) continue;
        const m = v2Messages(op.message);
        msgs.push(...m);
        operations.push({ id: str(op.operationId) ?? `${action} ${name}`, action, channel: name, messages: m, ...(str(op.summary) ? { summary: str(op.summary) } : {}), ...(str(op.operationId) ? { operationId: str(op.operationId) } : {}), bindings: isObj(op.bindings) ? Object.keys(op.bindings) : [], security: secNames(op.security) });
      }
      channels.push({ name, address: name, parameters: params, messages: [...new Set(msgs)], bindings, ...(str(c.description) ? { description: str(c.description) } : {}) });
    }
    if (channels.length >= 20000) break;
  }
  if (major === 3 && isObj(doc.operations)) for (const [id, op] of Object.entries(doc.operations)) {
    if (!isObj(op)) continue;
    const action = op.action === 'send' ? 'send' : 'receive';
    const ch = refName(op.channel) ?? '';
    const msgs = Array.isArray(op.messages) ? op.messages.map((m) => refName(m) ?? '(inline)') : channels.find((c) => c.name === ch)?.messages ?? [];
    operations.push({ id, action, channel: ch, messages: msgs, ...(str(op.summary) ? { summary: str(op.summary) } : {}), bindings: isObj(op.bindings) ? Object.keys(op.bindings) : [], security: secNames(op.security) });
    if (operations.length >= 20000) break;
  }
  const comps = isObj(doc.components) ? doc.components : {};
  const keys = (v: unknown) => (isObj(v) ? Object.keys(v) : []);
  return {
    ...where, spec: 'asyncapi', version, major, ...(str(doc.id) ? { id: str(doc.id) } : {}), title: str(info.title), apiVersion: str(info.version),
    ...(str(doc.defaultContentType) ? { defaultContentType: str(doc.defaultContentType) } : {}),
    servers, channels, operations, messages: keys(comps.messages), schemas: keys(comps.schemas), securitySchemes: keys(comps.securitySchemes),
    protocols: [...new Set(servers.map((s) => s.protocol).filter((p): p is string => !!p))], document: doc,
  };
}

/** Find AsyncAPI 2.x and 3.x documents in text (latin1 decoded bytes or a JS bundle). */
export function findAsyncApi(text: string, opts: { max?: number; maxDocChars?: number } = {}): AsyncApiSummary[] {
  return scanSpecDocuments(text, 'asyncapi', isAsyncApi, (doc, where) => summarizeAsyncApi(doc as Obj, where), opts);
}
