// API contracts: protobuf descriptors from a Go binary and Python gencode, OpenAPI from Go
// embed YAML and an esbuild bundle, GraphQL SDL, introspection and operations.
// References: protoc 29.3 (descriptor set and recompiling the rebuilt .proto), PyYAML, graphql-js 16.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, mkdtempSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { gunzipSync } from 'node:zlib';
import { execFileSync } from 'node:child_process';
import fc from 'fast-check';
import { buildSchema, parse, introspectionFromSchema, type GraphQLNamedType } from 'graphql';
import * as X from '../src/index.js';
import { TOOLS } from '../src/tools.js';
import { S } from './helpers.js';

const C = join(S, 'contracts');
const file = (f: string): Uint8Array => new Uint8Array(readFileSync(join(C, f)));
const goBin = (): Uint8Array => new Uint8Array(gunzipSync(readFileSync(join(C, 'revdemo-go.elf.gz'))));
const desc = file('revdemo.desc');
// FileDescriptorSet { file = 1 (len) }: the FileDescriptorProto starts after tag and 2-byte length
const refFdBytes = desc.subarray(3);
const refFd = X.decodeFileDescriptor(refFdBytes);
const stripJson = (f: X.ProtoFile): unknown => JSON.parse(JSON.stringify(f, (k, v) => (k === 'jsonName' ? undefined : v)));

test('protobuf: Go protoc-gen-go binary holds the exact protoc descriptor bytes', async () => {
  const found = await X.findProtoDescriptors(goBin());
  const d = found.find((x) => x.file.name === 'revdemo.proto');
  assert.ok(d, 'revdemo.proto found');
  assert.equal(d.encoding, 'raw');
  assert.equal(d.length, refFdBytes.length);
  assert.deepEqual(Buffer.from(d.bytes), Buffer.from(refFdBytes));
  assert.equal(d.file.package, 'revlens.demo.v1');
  assert.equal(d.file.goPackage, 'example.com/revdemo/gen;gen');
  assert.deepEqual(d.file.dependencies, ['google/protobuf/timestamp.proto']);
  assert.deepEqual(d.file.messages.map((m) => m.name), ['User', 'GetUserRequest', 'ListUsersRequest', 'ListUsersResponse', 'Event']);
  const svc = d.file.services[0]!;
  assert.equal(svc.name, 'UserService');
  assert.deepEqual(svc.methods.map((m) => [m.name, m.clientStreaming, m.serverStreaming]), [['GetUser', false, false], ['ListUsers', false, false], ['Watch', false, true], ['Upload', true, false]]);
});

test('protobuf: Python _pb2.py literal and compiled .pyc decode to the protoc descriptor (json_name stripped by gencode)', async () => {
  for (const f of ['revdemo_pb2.py', 'revdemo_pb2.pyc']) {
    const found = await X.findProtoDescriptors(file(f));
    assert.equal(found.length, 1, f);
    assert.equal(found[0]!.encoding, f.endsWith('.py') ? 'python-literal' : 'raw');
    assert.deepEqual(stripJson(found[0]!.file), stripJson(refFd), f);
  }
});

test('protobuf: rebuilt .proto matches the original and recompiles byte for byte', async () => {
  const text = X.protoToText(refFd);
  assert.equal(text, readFileSync(join(C, 'revdemo.rebuilt.proto'), 'utf8'));
  // every declaration of the hand written original appears in the rebuild
  const orig = readFileSync(join(S, 'src', 'proto', 'revdemo.proto'), 'utf8');
  const decl = (s: string): Set<string> => new Set([...s.matchAll(/(\w+)\s*=\s*(\d+)\s*;/g)].map((m) => `${m[1]}=${m[2]}`));
  for (const d of decl(orig)) assert.ok(decl(text).has(d), d);
  for (const rpc of orig.matchAll(/rpc (\w+)\((stream )?(\w+)\) returns \((stream )?(\w+)\)/g)) assert.ok(text.includes(rpc[0]), rpc[0]);
  // when protoc is present, compiling the rebuilt text must give the same descriptor set
  const protoc = [process.env.PROTOC, '/workspace/work/tools/protoc/bin/protoc'].find((p) => p && existsSync(p));
  if (protoc) {
    const dir = mkdtempSync(join(tmpdir(), 'rl-proto-'));
    writeFileSync(join(dir, 'revdemo.proto'), text);
    const inc = join(protoc, '..', '..', 'include');
    execFileSync(protoc, ['-I' + dir, '-I' + inc, '--descriptor_set_out=' + join(dir, 'out.desc'), join(dir, 'revdemo.proto')], { timeout: 30000 });
    assert.deepEqual(readFileSync(join(dir, 'out.desc')), Buffer.from(desc));
  }
});

test('openapi: Go embedded YAML equals the PyYAML load of the source document', () => {
  const docs = X.findOpenApi(X.textView(goBin()).text);
  assert.equal(docs.length, 1);
  const o = docs[0]!;
  assert.equal(o.format, 'yaml');
  assert.equal(o.title, 'RevDemo Users API');
  assert.equal(o.version, '3.0.3');
  assert.equal(o.apiVersion, '1.4.0');
  assert.deepEqual(o.document, JSON.parse(readFileSync(join(C, 'openapi.pyyaml.json'), 'utf8')));
  assert.deepEqual(o.servers, ['https://api.revdemo.example/v1', 'http://localhost:8080/v1']);
  assert.deepEqual(o.operations.map((x) => `${x.method} ${x.path} ${x.operationId}`), ['GET /users listUsers', 'POST /users createUser', 'GET /users/{id} getUser', 'DELETE /users/{id} deleteUser']);
  assert.deepEqual(o.operations[0]!.parameters, ['page_size (query)', 'page_token (query)']);
  assert.deepEqual(o.operations[2]!.parameters, ['id (path)']);
  assert.deepEqual(o.operations[1]!.security, ['bearerAuth']);
  assert.equal(o.operations[3]!.deprecated, true);
  assert.deepEqual(o.securitySchemes, ['bearerAuth', 'apiKey']);
  assert.deepEqual(o.schemas, ['Role', 'User', 'ListUsersResponse']);
});

test('openapi: esbuild inlined petstore.json as a JS literal equals the original JSON', () => {
  const docs = X.findOpenApi(readFileSync(join(C, 'app.bundle.min.js'), 'utf8'));
  assert.equal(docs.length, 1);
  assert.equal(docs[0]!.format, 'js-literal');
  assert.deepEqual(docs[0]!.document, JSON.parse(readFileSync(join(S, 'src', 'contracts-js', 'petstore.json'), 'utf8')));
  assert.deepEqual(docs[0]!.operations.map((x) => x.operationId), ['listPets', 'createPets', 'showPetById']);
});

test('openapi: Swagger 2 JSON string inside JS and a plain JSON file', () => {
  const sw = { swagger: '2.0', info: { title: 'Old', version: '1' }, host: 'api.example.com', basePath: '/v2', schemes: ['https'], paths: { '/a': { get: { operationId: 'getA', parameters: [{ name: 'q', in: 'query' }], responses: { 200: { description: 'ok' } } } } }, definitions: { A: {} }, securityDefinitions: { key: { type: 'apiKey' } } };
  const js = `var x=1;const spec=JSON.parse(${JSON.stringify(JSON.stringify(sw))});`;
  const d = X.findOpenApi(js);
  assert.equal(d.length, 1);
  assert.equal(d[0]!.format, 'json-string');
  assert.deepEqual(d[0]!.servers, ['https://api.example.com/v2']);
  assert.deepEqual(d[0]!.operations[0]!.parameters, ['q (query)']);
  assert.deepEqual(d[0]!.schemas, ['A']);
  assert.equal(X.findOpenApi(JSON.stringify(sw, null, 2))[0]!.format, 'json');
});

const sdlText = readFileSync(join(S, 'src', 'proto', 'schema.graphql'), 'utf8');
const ref = buildSchema(sdlText);
function refShape(): Record<string, string[]> {
  const out: Record<string, string[]> = {};
  for (const t of Object.values(ref.getTypeMap()) as GraphQLNamedType[]) {
    if (t.name.startsWith('__') || ['String', 'Int', 'Float', 'Boolean', 'ID'].includes(t.name)) continue;
    const anyT = t as unknown as { getFields?: () => Record<string, { type: unknown; args?: { name: string; type: unknown }[] }>; getValues?: () => { name: string }[]; getTypes?: () => { name: string }[] };
    if (anyT.getFields) out[t.name] = Object.values(anyT.getFields()).map((f) => `${(f as { name?: string }).name}${f.args?.length ? `(${f.args.map((a) => `${a.name}: ${String(a.type)}`).join(', ')})` : ''}: ${String(f.type)}`);
    else if (anyT.getValues) out[t.name] = anyT.getValues().map((v) => v.name);
    else if (anyT.getTypes) out[t.name] = anyT.getTypes().map((v) => v.name);
    else out[t.name] = [];
  }
  return out;
}
function ourShape(s: X.GqlSchema): Record<string, string[]> {
  const out: Record<string, string[]> = {};
  for (const t of s.types) {
    if (['String', 'Int', 'Float', 'Boolean', 'ID'].includes(t.name)) continue;
    out[t.name] = t.kind === 'ENUM' ? t.values : t.kind === 'UNION' ? t.members : t.fields.map((f) => `${f.name}${f.args.length ? `(${f.args.map((a) => `${a.name}: ${a.type}`).join(', ')})` : ''}: ${f.type}`);
  }
  return out;
}

test('graphql: SDL embedded in the Go binary matches graphql-js buildSchema', () => {
  const found = X.findGraphqlSchemas(X.textView(goBin()).text);
  assert.equal(found.length, 1);
  const s = found[0]!;
  assert.equal(s.source, 'sdl');
  assert.deepEqual(ourShape(s.schema), refShape());
  assert.equal(s.queryType, 'Query');
  assert.equal(s.mutationType, 'Mutation');
  assert.equal(s.subscriptionType, 'Subscription');
  assert.deepEqual(s.schema.directives.map((d) => [d.name, d.locations]), [['auth', ['FIELD_DEFINITION', 'OBJECT']]]);
  const user = s.schema.types.find((t) => t.name === 'User')!;
  assert.deepEqual(user.interfaces, ['Node']);
  assert.equal(user.fields.find((f) => f.name === 'nickname')!.deprecated, 'use displayName');
  // our SDL rendering is accepted by graphql-js and yields the same shape
  assert.deepEqual(ourShape(X.parseSdl(X.schemaToSdl(s.schema))), refShape());
  buildSchema(X.schemaToSdl(s.schema));
});

test('graphql: introspection JSON.parse string in the bundle matches graphql-js introspectionFromSchema', () => {
  const found = X.findGraphqlSchemas(readFileSync(join(C, 'app.bundle.min.js'), 'utf8'));
  assert.equal(found.length, 1);
  assert.equal(found[0]!.source, 'introspection');
  assert.deepEqual(ourShape(found[0]!.schema), refShape());
  // the same through the committed introspection.json file
  const fromFile = X.schemaFromIntrospection(JSON.parse(readFileSync(join(C, 'introspection.json'), 'utf8')))!;
  assert.deepEqual(ourShape(fromFile), refShape());
  assert.deepEqual(ourShape(X.schemaFromIntrospection({ data: introspectionFromSchema(ref) })!), refShape());
});

test('graphql: operations from gql templates, query strings, Go constants and a precompiled document', () => {
  const ops = X.findGraphqlOperations(readFileSync(join(C, 'app.bundle.min.js'), 'utf8'));
  const names = ops.map((o) => `${o.source}:${o.kind}:${o.name}`).sort();
  assert.deepEqual(names, ['document-ast:query:ListUsers', 'text:fragment:UserFields', 'text:mutation:CreateUser', 'text:query:GetUser', 'text:query:SearchUsers', 'text:subscription:UserEvents']);
  for (const o of ops.filter((x) => x.source === 'text')) {
    const d = parse(o.text);
    const def = d.definitions[0] as { name?: { value: string } };
    assert.equal(def.name?.value, o.name, 'graphql-js parses the extracted text');
  }
  const get = ops.find((o) => o.name === 'GetUser')!;
  assert.deepEqual(get.variables, [{ name: 'id', type: 'ID!' }]);
  assert.deepEqual(get.rootFields, ['user']);
  assert.deepEqual(get.fragmentSpreads, ['UserFields']);
  const ast = ops.find((o) => o.source === 'document-ast')!;
  assert.deepEqual(ast.variables, [{ name: 'pageSize', type: 'Int' }]);
  assert.deepEqual(ast.rootFields, ['users']);
  const goOps = X.findGraphqlOperations(X.textView(goBin()).text);
  assert.deepEqual(goOps.map((o) => o.name), ['GetUser']);
  assert.equal(goOps[0]!.text, 'query GetUser($id: ID!) { user(id: $id) { id email role } }');
});

test('x_api_contracts tool and x-api-contracts CLI', async () => {
  const tool = TOOLS.find((t) => t.name === 'x_api_contracts')!;
  const r = (await tool.run({ path: join(C, 'app.bundle.min.js'), sdl: true })) as { counts: Record<string, number>; graphqlSchemas: { sdl: string; rootFields: Record<string, string[]> }[] };
  assert.deepEqual(r.counts, { protobuf: 0, openapi: 1, asyncapi: 0, graphqlSchemas: 1, graphqlOperations: 6 });
  assert.deepEqual(r.graphqlSchemas[0]!.rootFields.Query, ['user(id: ID!): User', 'users(pageSize: Int, pageToken: String): UserPage!', 'search(text: String!): [SearchResult!]!']);
  assert.match(r.graphqlSchemas[0]!.sdl, /type User implements Node \{/);
  const p = (await tool.run({ path: join(C, 'revdemo_pb2.py'), kind: 'protobuf', proto: true })) as { protobuf: { proto: string; services: { methods: string[] }[] }[] };
  assert.equal(p.protobuf[0]!.services[0]!.methods[2], 'Watch(.revlens.demo.v1.GetUserRequest) returns (stream .revlens.demo.v1.Event)');
  assert.match(p.protobuf[0]!.proto, /rpc Upload\(stream Event\) returns \(User\);/);
  await assert.rejects(() => tool.run({ path: join(C, 'revdemo_pb2.py'), kind: 'soap' }));
  const cmd = X.CLI_COMMANDS.find((c) => c.name === 'x-api-contracts')!;
  const logs: string[] = [];
  const orig = console.log;
  console.log = (s: string) => { logs.push(s); };
  try { assert.equal(await cmd.run([join(C, 'revdemo_pb2.py'), '--kind', 'protobuf', '--json']), 0); } finally { console.log = orig; }
  assert.equal(JSON.parse(logs.join('\n')).protobuf[0].name, 'revdemo.proto');
});

test('contracts: hostile input never hangs or throws non-parse errors', async () => {
  const real = [readFileSync(join(C, 'app.bundle.min.js'), 'utf8'), sdlText, readFileSync(join(S, 'src', 'proto', 'openapi.yaml'), 'utf8')];
  await fc.assert(fc.asyncProperty(fc.uint8Array({ maxLength: 4096 }), fc.integer({ min: 0, max: 2 }), fc.nat(), async (junk, which, cut) => {
    const src = real[which]!;
    const t0 = Date.now();
    const at = cut % src.length;
    const text = src.slice(0, at) + Buffer.from(junk).toString('latin1') + src.slice(at + junk.length);
    X.findOpenApi(text); X.findGraphqlSchemas(text); X.findGraphqlOperations(text);
    await X.findProtoDescriptors(new Uint8Array(Buffer.from(text, 'latin1')));
    assert.ok(Date.now() - t0 < 3000);
  }), { numRuns: 60 });
  await fc.assert(fc.asyncProperty(fc.uint8Array({ maxLength: 2000 }), async (b) => {
    try { X.decodeFileDescriptor(b); } catch (e) { assert.ok(e instanceof X.ParseError, String(e)); }
    try { X.parseSdl(Buffer.from(b).toString('latin1')); } catch (e) { assert.ok(e instanceof X.ParseError, String(e)); }
    try { X.parseOperation(Buffer.from(b).toString('latin1')); } catch (e) { assert.ok(e instanceof X.ParseError, String(e)); }
    try { X.parseJsValue(Buffer.from(b).toString('latin1'), 0); } catch (e) { assert.ok(e instanceof X.ParseError, String(e)); }
    await X.scanApiContracts(b);
  }), { numRuns: 200 });
  // deep nesting and huge declared lengths
  assert.throws(() => X.parseJsValue('['.repeat(5000), 0), X.ParseError);
  assert.throws(() => X.parseSdl('type Q { f: ' + '['.repeat(500) + 'X' + ']'.repeat(500) + ' }'), X.ParseError);
  assert.throws(() => X.decodeFileDescriptor(new Uint8Array([0x0a, 0xff, 0xff, 0xff, 0x0f])), X.ParseError);
  const deep = 'query Q { ' + 'a { '.repeat(300) + 'b' + ' }'.repeat(300) + ' }';
  assert.throws(() => X.parseOperation(deep), X.ParseError);
});

// AsyncAPI 2.6 and 3.0: the official Streetlights MQTT examples (asyncapi/spec, Apache-2.0)
// embedded in a Go binary and in a minified bundle; reference load by ruamel.yaml (YAML 1.2).
const aref = JSON.parse(readFileSync(join(C, 'asyncapi.reference.json'), 'utf8'));
const aBin = (): Uint8Array => new Uint8Array(gunzipSync(readFileSync(join(C, 'asyncapi-go.elf.gz'))));
const asrc = (f: string) => readFileSync(join(S, 'src', 'asyncapi', f));

test('asyncapi: two Go-embedded YAML documents (2.6 and 3.0) found at their exact byte ranges and equal to ruamel.yaml', () => {
  const bin = aBin();
  const docs = X.findAsyncApi(X.textView(bin).text);
  assert.equal(docs.length, 2);
  const [v2, v3] = docs as [X.AsyncApiSummary, X.AsyncApiSummary];
  for (const [d, f, ref] of [[v2, 'streetlights-mqtt-2.6.yml', aref.v2], [v3, 'streetlights-mqtt-3.0.yml', aref.v3]] as const) {
    assert.equal(d.format, 'yaml');
    assert.equal(d.length, asrc(f).length, 'whole file, emoji and all');
    assert.deepEqual(Buffer.from(bin.subarray(d.offset, d.offset + d.length)), asrc(f), 'offset points at the embedded bytes');
    assert.deepEqual(d.document, ref);
    assert.equal(d.title, 'Streetlights MQTT API');
    assert.deepEqual(d.protocols, ['mqtt']);
    assert.deepEqual(d.messages, ['lightMeasured', 'turnOnOff', 'dimLight']);
    assert.deepEqual(d.securitySchemes, ['apiKey', 'supportedOauthFlows', 'openIdConnectWellKnown']);
  }
  assert.equal(v2.major, 2); assert.equal(v3.major, 3);
  assert.deepEqual(v2.operations.map((o) => `${o.id} ${o.action}`), ['receiveLightMeasurement publish', 'turnOn subscribe', 'turnOff subscribe', 'dimLight subscribe']);
  assert.deepEqual(v3.operations.map((o) => `${o.id} ${o.action} ${o.channel} ${o.messages.join(',')}`), ['receiveLightMeasurement receive lightingMeasured lightMeasured', 'turnOn send lightTurnOn turnOn', 'turnOff send lightTurnOff turnOff', 'dimLight send lightsDim dimLight']);
  // channel names in 2.x are addresses; in 3.x they are ids with an address field
  assert.deepEqual(v2.channels.map((c) => c.name).sort(), Object.keys(aref.v2.channels).sort());
  assert.deepEqual(v3.channels.map((c) => c.address).sort(), Object.values(aref.v3.channels as Record<string, { address: string }>).map((c) => c.address).sort());
  assert.deepEqual(v3.channels[0]!.parameters, ['streetlightId']);
  assert.equal(v2.servers[0]!.url, 'test.mosquitto.org:{port}');
  assert.equal(v3.servers[0]!.url, 'mqtt://test.mosquitto.org:{port}');
  // the OpenAPI scan does not report AsyncAPI documents
  assert.equal(X.findOpenApi(X.textView(bin).text).length, 0);
});

test('asyncapi: JS literal (3.0) and JSON string (2.6) inside a bundle, and x_api_contracts', async () => {
  const js = readFileSync(join(C, 'asyncapi.bundle.min.js'), 'utf8');
  const docs = X.findAsyncApi(js);
  assert.deepEqual(docs.map((d) => `${d.format} ${d.version}`), ['js-literal 3.0.0', 'json-string 2.6.0']);
  assert.deepEqual(docs[0]!.document, aref.v3);
  assert.deepEqual(docs[1]!.document, aref.v2);
  const t = TOOLS.find((x) => x.name === 'x_api_contracts')!;
  const r = (await t.run({ path: join(C, 'asyncapi.bundle.min.js'), kind: 'asyncapi' })) as { counts: Record<string, number>; asyncapi: { version: string; operations: { total: number } }[] };
  assert.equal(r.counts.asyncapi, 2);
  assert.equal(r.asyncapi[0]!.operations.total, 4);
  const all = (await t.run({ path: join(C, 'asyncapi.bundle.min.js') })) as { counts: Record<string, number> };
  assert.equal(all.counts.openapi, 0);
  assert.equal(all.counts.asyncapi, 2);
});

test('asyncapi: hostile text never throws and stays fast', () => {
  fc.assert(fc.property(fc.string({ maxLength: 3000 }), fc.constantFrom('asyncapi: 2.6.0\n', '{"asyncapi":"3.0.0","channels":', 'asyncapi: "3.0"\n', '\\"asyncapi\\":\\"2.0.0\\"'), fc.nat(3000), (s, plant, at) => {
    const text = s.slice(0, at) + plant + s.slice(at);
    const t = Date.now();
    X.findAsyncApi(text);
    assert.ok(Date.now() - t < 2000);
  }), { numRuns: 200 });
});
