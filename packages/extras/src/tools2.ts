// Agent tools for the formats added to close the rea gap list: Windows offline artifacts,
// Apple archives, app containers, API contracts and Swift demangling.

import { inputBytes, page, ParseError, PATH_INPUT, type ToolDef, type InputSpec } from './util.js';
import { Regf } from './windows/regf.js';
import { inspectRegf } from './windows/regf.js';
import { parsePrefetch } from './windows/prefetch.js';
import { parseJumpList } from './windows/jumplist.js';
import { Cfb } from './windows/cfb.js';
import { parsePlistAny } from './apple/plist.js';
import { decodeKeyedArchive, isKeyedArchive } from './apple/keyedarchive.js';
import { parseNib, summarizeNib, isNibArchive } from './apple/nib.js';
import { parseAssetCatalog } from './apple/car.js';
import { jsonSafe } from './tools.js';
import { parseWxapkgAny, wxapkgMember } from './containers/wxapkg.js';
import { parseUnityFs, unityNodeBytes, parseSerializedFile } from './containers/unityfs.js';
import { inspectStandaloneJs, standaloneFile } from './containers/standalone.js';
import { demangleSwift, demangleSwiftTree, Node as SwiftNode } from './demangle/swift/index.js';
import { scanApiContracts, protoToText, schemaToSdl } from './contracts/index.js';

const P = PATH_INPUT;
const LIMIT: Record<string, InputSpec> = {
  offset: { type: 'number', description: 'Index of the first item to return (paging)', optional: true },
  limit: { type: 'number', description: 'Maximum items to return, default 200', optional: true },
};
export const num = (x: unknown, d: number): number => (typeof x === 'number' && Number.isFinite(x) ? x : typeof x === 'string' && x.trim() !== '' && Number.isFinite(Number(x)) ? Number(x) : d);
const nameOf = (i: { path?: string; name?: string }): string | undefined => i.name ?? i.path;

export const WINDOWS_TOOLS: ToolDef[] = [
  {
    name: 'x_registry_hive',
    description: 'Windows registry hive (regf: SYSTEM, SOFTWARE, SAM, NTUSER.DAT, UsrClass.dat, Amcache.hve, BCD). Without key: header (dirty flag, checksum), root and totals. With key: that key, its subkeys and decoded values. With recursive: a paged list of every key path under it.',
    inputSchema: { ...P, key: { type: 'string', description: 'Key path below the root, backslash separated, for example Software\\Microsoft\\Windows\\CurrentVersion\\Run', optional: true }, recursive: { type: 'boolean', description: 'List all key paths under key (paged)', optional: true }, values: { type: 'boolean', description: 'With recursive, include each key\'s values', optional: true }, ...LIMIT },
    async run(i) {
      const b = await inputBytes(i);
      const r = new Regf(b);
      if (i.key === undefined && !i.recursive) return inspectRegf(b);
      const k = i.key ? r.find(String(i.key)) : r.root();
      if (!k) throw new ParseError(`key not found: ${i.key}`);
      if (i.recursive) {
        const w = r.walk(k, { maxKeys: 200000 });
        const rows = w.keys.map((x) => ({ path: x.path, lastWritten: x.lastWritten, subkeys: x.subkeyCount, values: x.valueCount, offset: x.offset }));
        const pg = page(rows, num(i.offset, 0), num(i.limit, 200));
        if (i.values) for (const row of pg.items as (typeof rows[number] & { valueList?: unknown })[]) row.valueList = r.values(r.key(row.offset), { limit: 200 });
        return { header: r.header, from: k.path, truncated: w.truncated, keys: pg };
      }
      return { header: r.header, key: k, subkeys: page(r.subkeys(k).map((s) => ({ name: s.name, lastWritten: s.lastWritten, subkeys: s.subkeyCount, values: s.valueCount, offset: s.offset })), num(i.offset, 0), num(i.limit, 200)), values: r.values(k, { limit: 2000 }) };
    },
  },
  {
    name: 'x_prefetch',
    description: 'Windows Prefetch (.pf) file, XP to 11, including Windows 10+ MAM (LZXPRESS Huffman) compressed files: executable, hash, run count, last 8 run times, loaded files, volumes with serials and directories.',
    inputSchema: { ...P, ...LIMIT },
    async run(i) {
      const p = parsePrefetch(await inputBytes(i));
      return { ...p, files: page(p.files, num(i.offset, 0), num(i.limit, 500)) };
    },
  },
  {
    name: 'x_jump_list',
    description: 'Windows Jump Lists: *.automaticDestinations-ms (DestList entries with path, pin state, access count, host, droid ids, and each embedded shell link) and *.customDestinations-ms (shell links by offset).',
    inputSchema: { ...P, name: { type: 'string', description: 'Original file name, used to report the AppID when bytes are passed', optional: true }, ...LIMIT },
    async run(i) {
      const j = parseJumpList(await inputBytes(i), { name: nameOf(i) });
      if (j.kind === 'automatic') return { ...j, entries: page(j.entries, num(i.offset, 0), num(i.limit, 200)) };
      return { ...j, links: page(j.links, num(i.offset, 0), num(i.limit, 200)) };
    },
  },
  {
    name: 'x_ole_compound',
    description: 'OLE compound file (MSI, legacy Office, Jump Lists, thumbs.db): directory entries with paths, sizes, CLSIDs and times; optionally the hex of one stream.',
    inputSchema: { ...P, stream: { type: 'string', description: 'Stream path to dump (first 4 KiB as hex)', optional: true }, ...LIMIT },
    async run(i) {
      const c = new Cfb(await inputBytes(i));
      if (i.stream) {
        const e = c.stream(String(i.stream));
        if (!e) throw new ParseError(`stream not found: ${i.stream}`);
        const d = c.read(e);
        let hex = '';
        for (const x of d.subarray(0, 4096)) hex += x.toString(16).padStart(2, '0');
        return { stream: e, hex, truncated: d.length > 4096 };
      }
      return { version: c.version, sectorSize: c.sectorSize, entries: page(c.entries.filter((e) => e.type !== 'unknown'), num(i.offset, 0), num(i.limit, 200)) };
    },
  },
];

export const APPLE_TOOLS: ToolDef[] = [
  {
    name: 'x_keyed_archive',
    description: 'Decode an NSKeyedArchiver archive (binary or XML plist, for example .nib keyed archives, NSUserDefaults blobs, iOS backups, saved state): resolves CF$UID references from $top into plain JSON, maps Foundation classes, lists the archived classes. Plain plists are returned as parsed.',
    inputSchema: { ...P, maxDepth: { type: 'number', description: 'Maximum object nesting to resolve, default 64', optional: true } },
    async run(i) {
      const p = parsePlistAny(await inputBytes(i));
      if (!isKeyedArchive(p)) return jsonSafe({ keyedArchive: false, plist: p });
      return jsonSafe({ keyedArchive: true, ...decodeKeyedArchive(p, { maxDepth: num(i.maxDepth, 64) }) });
    },
  },
  {
    name: 'x_nib',
    description: 'Compiled Interface Builder file (.nib from ibtool, NIBArchive format; keyed-archive nibs are decoded too): class histogram, user visible strings, outlet and action connections, custom classes, and the raw objects with typed values (paged).',
    inputSchema: { ...P, objects: { type: 'boolean', description: 'Include raw objects with their values', optional: true }, ...LIMIT },
    async run(i) {
      const b = await inputBytes(i);
      if (!isNibArchive(b)) {
        const p = parsePlistAny(b);
        if (isKeyedArchive(p)) return jsonSafe({ format: 'keyed-archive', ...decodeKeyedArchive(p) });
        throw new ParseError('not a NIBArchive or keyed archive nib');
      }
      const n = parseNib(b);
      const s = summarizeNib(n);
      return jsonSafe({ format: 'NIBArchive', formatVersion: n.formatVersion, coderVersion: n.coderVersion, counts: n.counts, offsets: n.offsets, ...s, objects: i.objects ? page(n.objects, num(i.offset, 0), num(i.limit, 200)) : undefined });
    },
  },
  {
    name: 'x_asset_catalog',
    description: 'Compiled asset catalog (Assets.car, a BOM store): CoreUI header and authoring tool, deployment target, key format, facets (asset names), appearances, and every rendition with name, asset, size, scale, pixel format, layout, idiom and appearance (paged).',
    inputSchema: { ...P, filter: { type: 'string', description: 'Keep renditions whose name or asset contains this text', optional: true }, ...LIMIT },
    async run(i) {
      const c = parseAssetCatalog(await inputBytes(i));
      const f = i.filter ? String(i.filter) : '';
      const rs = f ? c.renditions.filter((r) => r.name.includes(f) || (r.facet ?? '').includes(f)) : c.renditions;
      return { ...c, renditions: page(rs, num(i.offset, 0), num(i.limit, 200)) };
    },
  },
];

const hexOf = (d: Uint8Array, max = 4096): string => { let h = ''; for (const x of d.subarray(0, max)) h += x.toString(16).padStart(2, '0'); return h; };
const textOrHex = (d: Uint8Array, max = 65536): { text?: string; hex?: string; size: number; truncated: boolean } => {
  const s = new TextDecoder('utf-8', { fatal: false }).decode(d.subarray(0, max));
  return /[\x00-\x08\x0e-\x1f]|\uFFFD/.test(s) ? { hex: hexOf(d, Math.min(max, 4096)), size: d.length, truncated: d.length > 4096 } : { text: s, size: d.length, truncated: d.length > max };
};

export const CONTAINER_TOOLS: ToolDef[] = [
  {
    name: 'x_wxapkg',
    description: 'WeChat mini program package (.wxapkg): member table with offsets and sizes, app config, pages, kind (main, subpackage, plugin, game). Decrypts PC client V1MMWX packages when appId is given. With member, returns that file (text or hex).',
    inputSchema: { ...P, appId: { type: 'string', description: 'Mini program AppID (wx...) to decrypt a V1MMWX package', optional: true }, member: { type: 'string', description: 'Member path to read, for example /app-service.js', optional: true }, ...LIMIT },
    async run(i) {
      const w = await parseWxapkgAny(await inputBytes(i), { appId: i.appId });
      const { bytes, ...rest } = w;
      if (i.member) {
        const e = w.entries.find((x) => x.name === i.member || x.name === '/' + String(i.member).replace(/^\//, ''));
        if (!e) throw new ParseError(`member not found: ${i.member}`);
        return { member: e, ...textOrHex(wxapkgMember(bytes, e)) };
      }
      return { ...rest, entries: page(w.entries, num(i.offset, 0), num(i.limit, 500)) };
    },
  },
  {
    name: 'x_unity_bundle',
    description: 'Unity asset bundle (UnityFS): header, Unity version, blocks (compression), node table; each serialized file summarised with target platform, types and objects by class (path id, offset, size). LZ4/LZ4HC and uncompressed blocks are decoded; LZMA blocks are listed only.',
    inputSchema: { ...P, objects: { type: 'boolean', description: 'Include the object list of each serialized file (paged)', optional: true }, ...LIMIT },
    async run(i) {
      const b = await inputBytes(i);
      const u = parseUnityFs(b);
      const files = u.nodes.map((n) => {
        try {
          const d = unityNodeBytes(b, u, n);
          if (n.flags & 4) { const s = parseSerializedFile(d); return { node: n.path, serialized: { ...s, objects: i.objects ? page(s.objects, num(i.offset, 0), num(i.limit, 200)) : undefined } }; }
          return { node: n.path, size: d.length, preview: textOrHex(d, 512) };
        } catch (e) { return { node: n.path, error: (e as Error).message }; }
      });
      return { ...u, files };
    },
  },
  {
    name: 'x_standalone_js',
    description: 'JavaScript apps packed into one executable: Node.js SEA (fuse state, NODE_SEA_BLOB with entry script, code cache, assets, exec argv), Bun --compile (embedded module graph with sources) and Deno compile (metadata JSON, entrypoint, permissions, embedded files). With file, returns that embedded file.',
    inputSchema: { ...P, file: { type: 'string', description: 'Embedded module, asset or entry name to read', optional: true } },
    async run(i) {
      const b = await inputBytes(i);
      const s = inspectStandaloneJs(b);
      if (i.file) {
        let d = standaloneFile(b, s, String(i.file));
        const df = s.deno?.files.find((f) => f.path === i.file);
        if (!d && df) d = b.subarray(df.offset, df.offset + df.size);
        if (!d) throw new ParseError(`embedded file not found: ${i.file}`);
        return { file: i.file, ...textOrHex(d) };
      }
      return s;
    },
  },
];

interface SwiftTreeJson { kind: string; text?: string; index?: number; children?: SwiftTreeJson[] }

/** Swift node tree as plain JSON, capped at 64 levels and 4000 nodes. */
export function swiftTreeJson(n: SwiftNode, budget = { left: 4000 }, depth = 0): SwiftTreeJson {
  budget.left--;
  const o: SwiftTreeJson = { kind: n.kind };
  if (n.text !== undefined) o.text = n.text;
  if (n.index !== undefined) o.index = n.index;
  if (n.children.length) {
    if (depth >= 64 || budget.left <= 0) o.children = [{ kind: '[truncated]' }];
    else o.children = n.children.map((c) => (budget.left > 0 ? swiftTreeJson(c, budget, depth + 1) : { kind: '[truncated]' }));
  }
  return o;
}

/** Demangle Swift symbols like swift-demangle 6.0.3; output is null when a name does not demangle. */
export function swiftDemangleSymbols(symbols: string[], opts: { simplified?: boolean; tree?: boolean } = {}): { input: string; output: string | null; tree?: SwiftTreeJson | null }[] {
  return symbols.slice(0, 10000).map((raw) => {
    const sym = raw.startsWith('__T') || raw.startsWith('__$') ? raw.slice(1) : raw;
    const output = demangleSwift(sym, { simplified: !!opts.simplified });
    if (!opts.tree) return { input: raw, output };
    const t = demangleSwiftTree(sym);
    return { input: raw, output, tree: t ? swiftTreeJson(t) : null };
  });
}

const SWIFT_TOOLS: ToolDef[] = [
  {
    name: 'x_swift_demangle',
    description: 'Demangle Swift symbols (Swift 1 to 3 _T, Swift 4 _T0, Swift 4.x $S, Swift 5+ $s, macro @__swiftmacro_), matching swift-demangle 6.0.3 text. Optional simplified form and node tree. With a binary path, lists the Swift symbols of its symbol table.',
    inputSchema: {
      symbols: { type: 'array', description: 'Mangled Swift names', optional: true },
      ...P,
      simplified: { type: 'boolean', description: 'Short form like swift-demangle -simplified', optional: true },
      tree: { type: 'boolean', description: 'Include the demangler node tree (capped) for each symbol', optional: true },
      filter: { type: 'string', description: 'With a path: keep demangled names containing this text', optional: true },
      ...LIMIT,
    },
    async run(i) {
      if (Array.isArray(i.symbols) || typeof i.symbols === 'string') {
        const list: string[] = (Array.isArray(i.symbols) ? i.symbols : [i.symbols]).map(String);
        return { items: swiftDemangleSymbols(list, { simplified: !!i.simplified, tree: !!i.tree }) };
      }
      const { TOOLS } = await import('./tools.js');
      const all = await TOOLS.find((t) => t.name === 'x_demangle')!.run({ ...i, limit: 1000000, offset: 0 }) as { items: { mangled: string; demangled: string; scheme: string; address: string }[] };
      const rows = all.items.filter((r) => r.scheme === 'swift').map((r) => (i.simplified ? { ...r, demangled: swiftDemangleSymbols([r.mangled], { simplified: true })[0]!.output ?? r.demangled } : r));
      return page(rows, num(i.offset, 0), num(i.limit, 200));
    },
  },
];

export const CONTRACT_TOOLS: ToolDef[] = [
  {
    name: 'x_api_contracts',
    description: 'API contracts shipped inside binaries and JS bundles: protobuf FileDescriptorProto blobs (Go protoc-gen-go raw or gzip, C++, Java, Python _pb2 literals and .pyc, protobuf-es base64) rebuilt as .proto text; OpenAPI 3 / Swagger 2 documents as JSON, YAML (Go embed), minified JS object literals or JSON strings, with operations, servers, security schemes and schemas; AsyncAPI 2.x and 3.x documents with servers, channels, messages and publish/subscribe or send/receive operations; GraphQL schema SDL, introspection results, and operations from gql templates, query strings and precompiled DocumentNode objects. Every hit has its offset.',
    inputSchema: {
      ...P,
      kind: { type: 'string', description: 'protobuf, openapi, asyncapi, graphql or all (default)', optional: true },
      proto: { type: 'boolean', description: 'Include the rebuilt .proto text of every descriptor', optional: true },
      document: { type: 'boolean', description: 'Include each full OpenAPI or AsyncAPI document (can be large)', optional: true },
      sdl: { type: 'boolean', description: 'Include each GraphQL schema rendered as SDL', optional: true },
      ...LIMIT,
    },
    async run(i) {
      const k = String(i.kind ?? 'all');
      const kinds = k === 'all' ? undefined : [k as 'protobuf' | 'openapi' | 'asyncapi' | 'graphql'];
      if (kinds && !['protobuf', 'openapi', 'asyncapi', 'graphql'].includes(k)) throw new ParseError(`unknown kind ${k}`);
      const r = await scanApiContracts(await inputBytes(i), { kinds });
      const off = num(i.offset, 0), lim = num(i.limit, 200);
      return {
        size: r.size,
        counts: { protobuf: r.protobuf.length, openapi: r.openapi.length, asyncapi: r.asyncapi.length, graphqlSchemas: r.graphqlSchemas.length, graphqlOperations: r.graphqlOperations.length },
        protobuf: r.protobuf.map((d) => ({
          offset: d.offset, length: d.length, encoding: d.encoding, name: d.file.name, package: d.file.package, syntax: d.file.syntax, dependencies: d.file.dependencies, goPackage: d.file.goPackage,
          messages: d.file.messages.map((m) => m.name), enums: d.file.enums.map((e) => e.name),
          services: d.file.services.map((s) => ({ name: s.name, methods: s.methods.map((m) => `${m.name}(${m.clientStreaming ? 'stream ' : ''}${m.inputType}) returns (${m.serverStreaming ? 'stream ' : ''}${m.outputType})${m.httpRule ? ' ' + m.httpRule : ''}`) })),
          proto: i.proto ? protoToText(d.file) : undefined,
        })),
        openapi: r.openapi.map(({ document, operations, ...o }) => ({ ...o, operations: page(operations, off, lim), document: i.document ? document : undefined })),
        asyncapi: r.asyncapi.map(({ document, operations, channels, ...o }) => ({ ...o, channels: page(channels, off, lim), operations: page(operations, off, lim), document: i.document ? document : undefined })),
        graphqlSchemas: r.graphqlSchemas.map(({ schema, ...s }) => ({
          ...s, types: schema.types.filter((t) => !t.name.startsWith('__')).map((t) => ({ kind: t.kind, name: t.name, fields: t.fields.length || t.values.length || t.members.length })),
          rootFields: Object.fromEntries((['queryType', 'mutationType', 'subscriptionType'] as const).filter((x) => schema[x]).map((x) => [schema[x]!, schema.types.find((t) => t.name === schema[x])?.fields.map((f) => `${f.name}${f.args.length ? `(${f.args.map((a) => `${a.name}: ${a.type}`).join(', ')})` : ''}: ${f.type}`) ?? []])),
          sdl: i.sdl ? schemaToSdl(schema) : undefined,
        })),
        graphqlOperations: page(r.graphqlOperations.map((o) => ({ ...o, text: o.text.length > 2000 ? o.text.slice(0, 2000) + '...' : o.text })), off, lim),
      };
    },
  },
];

export const GAP_TOOLS: ToolDef[] = [...WINDOWS_TOOLS, ...APPLE_TOOLS, ...CONTAINER_TOOLS, ...SWIFT_TOOLS, ...CONTRACT_TOOLS];
