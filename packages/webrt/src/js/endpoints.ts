// Finds network endpoints and risky dynamic code in JavaScript: fetch, XHR, axios, jQuery, WebSocket,
// EventSource, sendBeacon, socket.io, workers, eval and Function, env variable names and feature flags.
import { parseJs, walk, staticString, templateShape, memberName, propKey, t } from './ast.js';

export interface Site { line: number; column: number; offset: number }

export interface EndpointCall extends Site {
  api: string;
  /** literal url or a template with ${} placeholders, undefined when fully dynamic */
  url?: string;
  method?: string;
  kind: 'http' | 'websocket' | 'sse' | 'beacon' | 'worker' | 'script' | 'socketio' | 'grpc' | 'graphql';
}

export interface UrlLiteral extends Site { value: string; kind: 'absolute' | 'websocket' | 'api-path' | 'graphql' }

export interface DynamicCode extends Site { api: string; argument?: string }

export interface EndpointReport {
  calls: EndpointCall[];
  urls: UrlLiteral[];
  hosts: string[];
  dynamicCode: DynamicCode[];
  envNames: string[];
  featureFlags: { name: string; api: string; line: number }[];
  storageKeys: { key: string; api: string; line: number }[];
  postMessage: Site[];
  messageListeners: Site[];
  parserErrors: string[];
  counts: Record<string, number>;
}

const HTTP_METHODS = new Set(['get', 'post', 'put', 'patch', 'delete', 'head', 'options', 'request']);
const ABS_URL = /^(?:https?|wss?):\/\/[^\s"'<>`]{1,2000}$/i;
const API_PATH = /^\/(?:[\w.~%@:+-]+|\$\{\})(?:\/(?:[\w.~%@:+,-]+|\$\{\}|:\w+|\{\w+\}))*\/?(?:\?[\w=&%.${}-]*)?$/;
const ASSET_EXT = /\.(?:png|jpe?g|gif|svg|webp|ico|css|woff2?|ttf|eot|map|mp4|mp3|wav|avif)$/i;
const FLAG_CALLEE = /(?:^|\.)(?:isEnabled|isFeatureEnabled|featureEnabled|isOn|isOff|checkGate|getFeatureValue|getFeature|useFeature|useFeatureFlag|useFlag|useGate|getFlag|variation|boolVariation|stringVariation|getExperiment|useExperiment|getTreatment|isActive|hasFeature|feature|flag)$/i;
const STORAGE = /^(?:window\.)?(?:localStorage|sessionStorage)\.(?:getItem|setItem|removeItem)$/;

function apiPathLike(s: string): boolean {
  if (s.length < 3 || s.length > 300 || !API_PATH.test(s) || ASSET_EXT.test(s)) return false;
  // require a word that looks like an api route, or at least two segments
  return /\/(?:api|v\d+|graphql|rest|rpc|auth|oauth|login|logout|user|users|account|admin|internal|telemetry|track|collect|events?|upload|download|webhook|settings|config|search|query)(?:\/|$|\?)/i.test(s) || s.split('/').length >= 3;
}

function hostOf(u: string): string | undefined {
  const m = /^(?:https?|wss?):\/\/([^/?#:]+)/i.exec(u);
  return m?.[1]?.toLowerCase();
}

/** Static scan of a script for endpoints, network calls, eval and Function use, env names, feature flags and storage keys. */
export function findEndpoints(code: string, opts: { maxItems?: number } = {}): EndpointReport {
  const max = opts.maxItems ?? 5000;
  const { ast, errors } = parseJs(code);
  const r: EndpointReport = { calls: [], urls: [], hosts: [], dynamicCode: [], envNames: [], featureFlags: [], storageKeys: [], postMessage: [], messageListeners: [], parserErrors: errors, counts: {} };
  const env = new Set<string>();
  const site = (n: t.Node): Site => ({ line: n.loc?.start.line ?? 0, column: n.loc?.start.column ?? 0, offset: n.start ?? 0 });
  // names declared exactly once in the file with a constant string value: safe to substitute into URL templates
  const declCount = new Map<string, number>();
  const constStr = new Map<string, string>();
  walk(ast, ({ node }) => {
    if (node.type === 'VariableDeclarator' && node.id.type === 'Identifier') {
      declCount.set(node.id.name, (declCount.get(node.id.name) ?? 0) + 1);
      const v = staticString(node.init as t.Node);
      if (v !== undefined && v.length < 2048) constStr.set(node.id.name, v);
    } else if ((node.type === 'FunctionDeclaration' || node.type === 'FunctionExpression' || node.type === 'ArrowFunctionExpression' || node.type === 'ObjectMethod' || node.type === 'ClassMethod')) {
      for (const p of node.params) if (p.type === 'Identifier') declCount.set(p.name, (declCount.get(p.name) ?? 0) + 1);
      if ((node.type === 'FunctionDeclaration' || node.type === 'FunctionExpression') && node.id) declCount.set(node.id.name, (declCount.get(node.id.name) ?? 0) + 1);
    }
  });
  const resolve = (n: t.Node): string | undefined => (n.type === 'Identifier' && declCount.get(n.name) === 1 ? constStr.get(n.name) : undefined);
  const shape = (n: t.Node, depth = 0): string | undefined => {
    if (depth > 32) return undefined;
    const direct = resolve(n);
    if (direct !== undefined) return direct;
    if (n.type === 'TemplateLiteral') {
      let out = '';
      n.quasis.forEach((q, i) => { out += q.value.cooked ?? q.value.raw; const e = n.expressions[i]; if (e) out += resolve(e) ?? '${}'; });
      return out;
    }
    if (n.type === 'BinaryExpression' && n.operator === '+') {
      const a = shape(n.left as t.Node, depth + 1) ?? '${}', b = shape(n.right, depth + 1) ?? '${}';
      return a === '${}' && b === '${}' ? undefined : a + b;
    }
    return templateShape(n);
  };
  const urlArg = (n: t.Node | undefined): string | undefined => (n ? shape(n) : undefined);
  const optMethod = (n: t.Node | undefined): string | undefined => {
    if (n?.type !== 'ObjectExpression') return undefined;
    for (const p of n.properties) if (p.type === 'ObjectProperty' && propKey(p) === 'method') return staticString(p.value)?.toUpperCase();
    return undefined;
  };
  const optUrl = (n: t.Node | undefined): string | undefined => {
    if (n?.type !== 'ObjectExpression') return undefined;
    for (const p of n.properties) if (p.type === 'ObjectProperty' && (propKey(p) === 'url' || propKey(p) === 'baseURL')) return templateShape(p.value);
    return undefined;
  };
  // track which identifiers were bound to new XMLHttpRequest() so xhr.open is recognised
  const xhrVars = new Set<string>();
  const push = <T>(arr: T[], v: T) => { if (arr.length < max) arr.push(v); };

  walk(ast, ({ node, parent }) => {
    if (node.type === 'VariableDeclarator' && node.id.type === 'Identifier' && node.init?.type === 'NewExpression' && memberName(node.init.callee)?.endsWith('XMLHttpRequest')) xhrVars.add(node.id.name);

    if (node.type === 'StringLiteral' || (node.type === 'TemplateLiteral' && !(parent?.type === 'TaggedTemplateExpression'))) {
      const v = node.type === 'StringLiteral' ? node.value : templateShape(node);
      if (v && v.length <= 2048) {
        if (ABS_URL.test(v) || /^(?:https?|wss?):\/\/[^\s]+\$\{\}/.test(v)) push(r.urls, { ...site(node), value: v, kind: /^wss?:/i.test(v) ? 'websocket' : /graphql/i.test(v) ? 'graphql' : 'absolute' });
        else if (v.startsWith('/') && apiPathLike(v)) push(r.urls, { ...site(node), value: v, kind: /graphql/i.test(v) ? 'graphql' : 'api-path' });
      }
    }

    if (node.type === 'MemberExpression' || node.type === 'OptionalMemberExpression') {
      const name = memberName(node);
      if (name) {
        const m = /^(?:process\.env|import\.meta\.env)\.([A-Za-z_][\w]*)$/.exec(name);
        if (m && m[1]) env.add(m[1]);
      }
    }

    if (node.type === 'CallExpression' || node.type === 'OptionalCallExpression' || node.type === 'NewExpression') {
      const callee = node.callee as t.Node;
      const name = memberName(callee) ?? (callee.type === 'Identifier' ? callee.name : undefined);
      const args = node.arguments as t.Node[];
      const isNew = node.type === 'NewExpression';
      if (!name) return;
      const last = name.split('.').pop() as string;
      const base = name.replace(/^(?:window|self|globalThis)\./, '');

      if (base === 'fetch' && !isNew) push(r.calls, { ...site(node), api: 'fetch', url: urlArg(args[0]), method: optMethod(args[1]) ?? 'GET', kind: 'http' });
      else if (isNew && (base === 'WebSocket' || base === 'ReconnectingWebSocket')) push(r.calls, { ...site(node), api: `new ${base}`, url: urlArg(args[0]), kind: 'websocket' });
      else if (isNew && base === 'EventSource') push(r.calls, { ...site(node), api: 'new EventSource', url: urlArg(args[0]), kind: 'sse' });
      else if (isNew && (base === 'Worker' || base === 'SharedWorker')) push(r.calls, { ...site(node), api: `new ${base}`, url: urlArg(args[0]), kind: 'worker' });
      else if (base === 'navigator.sendBeacon') push(r.calls, { ...site(node), api: 'navigator.sendBeacon', url: urlArg(args[0]), method: 'POST', kind: 'beacon' });
      else if (base === 'importScripts') push(r.calls, { ...site(node), api: 'importScripts', url: urlArg(args[0]), kind: 'script' });
      else if (base === 'navigator.serviceWorker.register') push(r.calls, { ...site(node), api: 'serviceWorker.register', url: urlArg(args[0]), kind: 'worker' });
      else if (!isNew && (base === 'io' || base === 'socketIOClient' || base === 'io.connect')) push(r.calls, { ...site(node), api: base, url: urlArg(args[0]), kind: 'socketio' });
      else if (last === 'open' && args.length >= 2 && staticString(args[0]) && /^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)$/i.test(staticString(args[0]) as string) && (callee.type === 'MemberExpression' && (callee.object.type !== 'Identifier' || xhrVars.has(callee.object.name) || /xhr|request|req/i.test(callee.object.name)))) {
        push(r.calls, { ...site(node), api: 'XMLHttpRequest.open', url: urlArg(args[1]), method: (staticString(args[0]) as string).toUpperCase(), kind: 'http' });
      } else if (/^(?:axios|\$|jQuery|\$http|http|ky|got|superagent|request|api|client|instance|this\.\$axios|this\.http|this\.axios)\.(?:get|post|put|patch|delete|head|options|request|ajax|getJSON)$/.test(base) || (base === 'axios' && !isNew)) {
        const method = HTTP_METHODS.has(last.toLowerCase()) && last !== 'request' ? last.toUpperCase() : last === 'getJSON' ? 'GET' : optMethod(args[0]);
        const url = args[0] && args[0].type !== 'ObjectExpression' ? urlArg(args[0]) : optUrl(args[0]);
        push(r.calls, { ...site(node), api: base, url, method, kind: url && /graphql/i.test(url) ? 'graphql' : 'http' });
      }

      // dynamic code
      if (!isNew && (base === 'eval' || base === 'execScript')) push(r.dynamicCode, { ...site(node), api: base, argument: staticString(args[0])?.slice(0, 200) });
      else if (base === 'Function' || base === 'AsyncFunction') push(r.dynamicCode, { ...site(node), api: isNew ? 'new Function' : 'Function', argument: args.map((a) => staticString(a)).filter(Boolean).join(', ').slice(0, 200) || undefined });
      else if ((base === 'setTimeout' || base === 'setInterval') && args[0] && staticString(args[0]) !== undefined) push(r.dynamicCode, { ...site(node), api: `${base}(string)`, argument: staticString(args[0])?.slice(0, 200) });
      else if (base === 'document.write' || base === 'document.writeln') push(r.dynamicCode, { ...site(node), api: base });
      else if (/^(?:vm\.)?(?:runInNewContext|runInThisContext|runInContext|compileFunction)$/.test(base) || base === 'vm.Script' || (isNew && base === 'Script')) push(r.dynamicCode, { ...site(node), api: base });
      else if (base === 'WebAssembly.instantiate' || base === 'WebAssembly.compile' || base === 'WebAssembly.instantiateStreaming') push(r.dynamicCode, { ...site(node), api: base });

      // feature flags
      if (!isNew && FLAG_CALLEE.test(name)) {
        const f = staticString(args[0]);
        if (f && f.length <= 120 && /^[\w.:/-]+$/.test(f) && (/feature|flag|gate|experiment|variation|treatment|growthbook|statsig|launchdarkly|ld|unleash|optimizely|split/i.test(name) || ['isEnabled', 'isOn', 'isOff', 'checkGate', 'variation', 'useFlag', 'hasFeature'].includes(last))) {
          push(r.featureFlags, { name: f, api: name, line: node.loc?.start.line ?? 0 });
        }
      }
      // storage keys
      if (STORAGE.test(base)) {
        const k = staticString(args[0]);
        if (k) push(r.storageKeys, { key: k, api: base, line: node.loc?.start.line ?? 0 });
      }
      if (last === 'postMessage' && !isNew) push(r.postMessage, site(node));
      if (last === 'addEventListener' && staticString(args[0]) === 'message') push(r.messageListeners, site(node));
    }
    // window.onmessage = ...
    if (node.type === 'AssignmentExpression' && memberName(node.left as t.Node)?.endsWith('onmessage')) push(r.messageListeners, site(node));
    return undefined;
  });
  r.envNames = [...env].sort();
  const hosts = new Set<string>();
  for (const u of r.urls) { const h = hostOf(u.value); if (h) hosts.add(h); }
  for (const c of r.calls) { const h = c.url ? hostOf(c.url) : undefined; if (h) hosts.add(h); }
  r.hosts = [...hosts].sort();
  r.counts = { calls: r.calls.length, urls: r.urls.length, hosts: r.hosts.length, dynamicCode: r.dynamicCode.length, envNames: r.envNames.length, featureFlags: r.featureFlags.length, storageKeys: r.storageKeys.length };
  return r;
}
