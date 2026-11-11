// One scan for API contracts in a binary or bundle: protobuf descriptors, OpenAPI / Swagger
// documents and GraphQL schemas and operations.

import { latin1, utf8 } from '../util.js';
import { findProtoDescriptors, protoToText, type FoundDescriptor } from './protobuf.js';
import { findOpenApi, type OpenApiSummary } from './openapi.js';
import { findGraphqlSchemas, findGraphqlOperations, schemaToSdl, type FoundSchema, type FoundOperation } from './graphql.js';

export * from './protobuf.js';
export * from './openapi.js';
export * from './graphql.js';
export { parseJsValue, type JsValue } from './jsvalue.js';

export interface ApiContracts {
  size: number;
  protobuf: FoundDescriptor[];
  openapi: OpenApiSummary[];
  graphqlSchemas: FoundSchema[];
  graphqlOperations: FoundOperation[];
}

/** Text view of the bytes: UTF-8 when the input decodes cleanly (JS bundles), else latin1 so offsets stay byte offsets. */
export function textView(b: Uint8Array): { text: string; byteOffsets: boolean } {
  let ascii = true;
  for (let i = 0; i < b.length; i++) if (b[i]! >= 0x80) { ascii = false; break; }
  if (ascii) return { text: latin1(b), byteOffsets: true };
  const u = utf8(b);
  if (!u.includes('\uFFFD') && !/[\x00-\x08\x0e-\x1f]/.test(u.slice(0, 65536))) return { text: u, byteOffsets: false };
  return { text: latin1(b), byteOffsets: true };
}

/** Scan bytes for every supported API contract kind. */
export async function scanApiContracts(b: Uint8Array, opts: { kinds?: ('protobuf' | 'openapi' | 'graphql')[]; maxBytes?: number } = {}): Promise<ApiContracts> {
  const kinds = new Set(opts.kinds ?? ['protobuf', 'openapi', 'graphql']);
  const data = b.length > (opts.maxBytes ?? 512 << 20) ? b.subarray(0, opts.maxBytes ?? 512 << 20) : b;
  const out: ApiContracts = { size: b.length, protobuf: [], openapi: [], graphqlSchemas: [], graphqlOperations: [] };
  if (kinds.has('protobuf')) out.protobuf = await findProtoDescriptors(data);
  if (kinds.has('openapi') || kinds.has('graphql')) {
    const { text } = textView(data);
    if (kinds.has('openapi')) out.openapi = findOpenApi(text);
    if (kinds.has('graphql')) { out.graphqlSchemas = findGraphqlSchemas(text); out.graphqlOperations = findGraphqlOperations(text); }
  }
  return out;
}

export { protoToText, schemaToSdl };
