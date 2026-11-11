// JavaScript engine artifacts: V8 code cache (vm.Script cached data, bytenode .jsc),
// V8 startup snapshot blobs, and Hermes bytecode (React Native .hbc / index.android.bundle).
// Header reading only: nothing is executed or deserialized.

import { View, ParseError, hexs, toHex, latin1 } from '../util.js';

export interface V8CodeCache {
  kind: 'v8-code-cache';
  magic: string;
  /** low 16 bits of the magic, derived from the external reference table size of that V8 build */
  externalReferenceTag: number;
  versionHash: string;
  sourceHash: string;
  /** V8 stores the source length in the low 31 bits of the source hash */
  sourceLength: number;
  isModule: boolean;
  flagHash: string;
  readOnlySnapshotChecksum?: string;
  payloadLength: number;
  checksum: string;
  headerSize: number;
  layout: 'v8-12+' | 'v8-legacy';
  lengthMatches: boolean;
  evidence: { field: string; offset: number; size: number }[];
}

/** Read a V8 code cache header, or throw when the bytes are not one. */
export function parseV8CodeCache(b: Uint8Array): V8CodeCache {
  const v = new View(b, true);
  if (b.length < 24) throw new ParseError('too short for a V8 code cache');
  const magic = v.u32(0);
  if ((magic >>> 16) !== 0xc0de) throw new ParseError('V8 code cache magic 0xC0DExxxx not found', 0);
  // V8 12 and later: magic, version, source, flags, read-only snapshot checksum, payload length, checksum (28 bytes, padded to 32)
  // Older: magic, version, source, flags, payload length, checksum (24 bytes)
  const newLen = b.length >= 28 ? v.u32(20) : -1;
  const oldLen = v.u32(16);
  const isNew = newLen >= 0 && (32 + newLen === b.length || 28 + newLen === b.length);
  const isOld = !isNew && (24 + oldLen === b.length);
  const layout: V8CodeCache['layout'] = isNew || (!isOld && newLen >= 0 && newLen < b.length) ? 'v8-12+' : 'v8-legacy';
  const sh = v.u32(8);
  const common = [
    { field: 'magic', offset: 0, size: 4 }, { field: 'versionHash', offset: 4, size: 4 },
    { field: 'sourceHash', offset: 8, size: 4 }, { field: 'flagHash', offset: 12, size: 4 },
  ];
  if (layout === 'v8-12+') {
    const payloadLength = v.u32(20);
    const headerSize = 32;
    return {
      kind: 'v8-code-cache', magic: hexs(magic, 8), externalReferenceTag: magic & 0xffff, versionHash: hexs(v.u32(4), 8), sourceHash: hexs(sh, 8),
      sourceLength: sh & 0x7fffffff, isModule: (sh >>> 31) === 1, flagHash: hexs(v.u32(12), 8), readOnlySnapshotChecksum: hexs(v.u32(16), 8),
      payloadLength, checksum: hexs(v.u32(24), 8), headerSize, layout, lengthMatches: headerSize + payloadLength === b.length || 28 + payloadLength === b.length,
      evidence: [...common, { field: 'readOnlySnapshotChecksum', offset: 16, size: 4 }, { field: 'payloadLength', offset: 20, size: 4 }, { field: 'checksum', offset: 24, size: 4 }],
    };
  }
  return {
    kind: 'v8-code-cache', magic: hexs(magic, 8), externalReferenceTag: magic & 0xffff, versionHash: hexs(v.u32(4), 8), sourceHash: hexs(sh, 8),
    sourceLength: sh & 0x7fffffff, isModule: (sh >>> 31) === 1, flagHash: hexs(v.u32(12), 8), payloadLength: oldLen, checksum: hexs(v.u32(20), 8),
    headerSize: 24, layout, lengthMatches: 24 + oldLen === b.length,
    evidence: [...common, { field: 'payloadLength', offset: 16, size: 4 }, { field: 'checksum', offset: 20, size: 4 }],
  };
}

export interface V8Snapshot { kind: 'v8-snapshot'; contexts: number; rehashability: number; checksum: string; versionString: string; evidence: { field: string; offset: number; size: number }[] }

/** V8 startup snapshot blob (snapshot_blob.bin, v8_context_snapshot.bin): context count, checksum and the embedded V8 version string. */
export function parseV8Snapshot(b: Uint8Array): V8Snapshot {
  const v = new View(b, true);
  if (b.length < 12 + 64) throw new ParseError('too short for a V8 snapshot');
  const contexts = v.u32(0);
  const rehash = v.u32(4);
  const ver = latin1(v.sub(12, 64)).replace(/\0[\s\S]*$/, '');
  if (contexts < 1 || contexts > 64 || rehash > 1 || !/^\d+\.\d+\.\d+[\w.-]*$/.test(ver)) throw new ParseError('V8 snapshot header not found');
  return {
    kind: 'v8-snapshot', contexts, rehashability: rehash, checksum: hexs(v.u32(8), 8), versionString: ver,
    evidence: [{ field: 'contexts', offset: 0, size: 4 }, { field: 'checksum', offset: 8, size: 4 }, { field: 'versionString', offset: 12, size: 64 }],
  };
}

export const HERMES_MAGIC = 0x1f1903c103bc1fc6n;
export const HERMES_DELTA_MAGIC = ~HERMES_MAGIC & 0xffffffffffffffffn;

export interface HermesHeader {
  kind: 'hermes-bytecode';
  delta: boolean;
  version: number;
  sourceHash: string;
  fileLength: number;
  lengthMatches: boolean;
  globalCodeIndex: number;
  functionCount: number;
  stringKindCount: number;
  identifierCount: number;
  stringCount: number;
  overflowStringCount: number;
  stringStorageSize: number;
  evidence: { field: string; offset: number; size: number }[];
}

/** Hermes bytecode file header (the fields common to bytecode versions 59 to 96). */
export function parseHermes(b: Uint8Array): HermesHeader {
  const v = new View(b, true);
  if (b.length < 64) throw new ParseError('too short for Hermes bytecode');
  const m = v.u64(0);
  if (m !== HERMES_MAGIC && m !== HERMES_DELTA_MAGIC) throw new ParseError('Hermes magic not found', 0);
  const fileLength = v.u32(32);
  return {
    kind: 'hermes-bytecode', delta: m === HERMES_DELTA_MAGIC, version: v.u32(8), sourceHash: toHex(v.sub(12, 20)), fileLength,
    lengthMatches: fileLength === b.length, globalCodeIndex: v.u32(36), functionCount: v.u32(40), stringKindCount: v.u32(44),
    identifierCount: v.u32(48), stringCount: v.u32(52), overflowStringCount: v.u32(56), stringStorageSize: v.u32(60),
    evidence: [{ field: 'magic', offset: 0, size: 8 }, { field: 'version', offset: 8, size: 4 }, { field: 'sourceHash', offset: 12, size: 20 }, { field: 'fileLength', offset: 32, size: 4 }, { field: 'functionCount', offset: 40, size: 4 }],
  };
}

export type JsEngineArtifact = V8CodeCache | V8Snapshot | HermesHeader;

/** Detect and read any supported JavaScript engine artifact, or return null. */
export function inspectJsEngine(b: Uint8Array): JsEngineArtifact | null {
  if (b.length >= 8) {
    const v = new View(b, true);
    const m = v.u64(0);
    if (m === HERMES_MAGIC || m === HERMES_DELTA_MAGIC) return parseHermes(b);
    if ((v.u32(0) >>> 16) === 0xc0de) { try { return parseV8CodeCache(b); } catch { /* fall through */ } }
  }
  try { return parseV8Snapshot(b); } catch { return null; }
}
