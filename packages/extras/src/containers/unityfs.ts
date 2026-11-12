// Unity asset bundles (UnityFS): header, blocks info (none, LZMA, LZ4 or LZ4HC),
// storage blocks and the node (file) table; nodes can be extracted from uncompressed or LZ4
// blocks. Serialized files inside are summarised: Unity version, target platform, types and
// objects by class.

import { View, ParseError, latin1, toHex } from '../util.js';
import { lz4Block } from './lz4.js';
import { lzmaDecodeRaw, decodeProps } from '../compress/lzma.js';

export interface UnityBlock { uncompressedSize: number; compressedSize: number; flags: number; compression: string; offset: number }
export interface UnityNode { path: string; offset: number; size: number; flags: number }
export interface UnityFs {
  signature: string; version: number; unityVersion: string; unityRevision: string; size: number;
  compressedBlocksInfoSize: number; uncompressedBlocksInfoSize: number; flags: number;
  blocksInfoCompression: string; blocksInfoAtEnd: boolean; dataOffset: number; dataHash: string;
  blocks: UnityBlock[]; nodes: UnityNode[];
}

const COMP = ['none', 'lzma', 'lz4', 'lz4hc', 'lzham'];
const compName = (f: number): string => COMP[f & 0x3f] ?? `type${f & 0x3f}`;

/** True for a UnityFS bundle. */
export function isUnityFs(b: Uint8Array): boolean { return b.length > 32 && latin1(b.subarray(0, 8)) === 'UnityFS\0'; }

function decompress(kind: number, src: Uint8Array, size: number): Uint8Array {
  const k = kind & 0x3f;
  if (k === 0) return src.subarray(0, size);
  if (k === 2 || k === 3) return lz4Block(src, size);
  if (k === 1) {
    // Unity LZMA: 5 byte properties (lc/lp/pb byte and dictionary size), then raw LZMA with a known size
    if (src.length < 5) throw new ParseError('LZMA block too short');
    const dict = ((src[1] as number) | ((src[2] as number) << 8) | ((src[3] as number) << 16) | ((src[4] as number) << 24)) >>> 0;
    return lzmaDecodeRaw(src, decodeProps(src[0] as number, Math.max(dict, 4096)), { start: 5, size, maxOut: size }).data;
  }
  throw new ParseError(`${compName(kind)} compressed blocks are not decoded (header and node table only)`);
}

/** Parse a UnityFS header and its blocks/node table. */
export function parseUnityFs(b: Uint8Array): UnityFs {
  if (!isUnityFs(b)) throw new ParseError('not a UnityFS bundle', 0);
  const v = new View(b, false);
  let p = 8;
  const version = v.u32(p); p += 4;
  const unityVersion = v.cstr(p, 64); p += unityVersion.length + 1;
  const unityRevision = v.cstr(p, 64); p += unityRevision.length + 1;
  const size = v.u64n(p); p += 8;
  const cSize = v.u32(p), uSize = v.u32(p + 4), flags = v.u32(p + 8);
  p += 12;
  if (version >= 7) p = (p + 15) & ~15;
  if (uSize > 64 << 20 || cSize > b.length) throw new ParseError('blocks info size out of range', p);
  const atEnd = (flags & 0x80) !== 0;
  const infoOff = atEnd ? b.length - cSize : p;
  v.need(infoOff, cSize);
  const info = new View(decompress(flags, v.sub(infoOff, cSize), uSize), false);
  let dataOffset = atEnd ? p : p + cSize;
  if (flags & 0x200) dataOffset = (dataOffset + 15) & ~15;
  let q = 16;
  const nBlocks = info.i32(q); q += 4;
  if (nBlocks < 0 || nBlocks > 1_000_000) throw new ParseError('bad block count');
  const blocks: UnityBlock[] = [];
  let off = dataOffset;
  for (let i = 0; i < nBlocks; i++) {
    const us = info.u32(q), cs = info.u32(q + 4), fl = info.u16(q + 8);
    blocks.push({ uncompressedSize: us, compressedSize: cs, flags: fl, compression: compName(fl), offset: off });
    off += cs; q += 10;
  }
  const nNodes = info.i32(q); q += 4;
  if (nNodes < 0 || nNodes > 1_000_000) throw new ParseError('bad node count');
  const nodes: UnityNode[] = [];
  for (let i = 0; i < nNodes; i++) {
    const o = info.u64n(q), s = info.u64n(q + 8), f = info.u32(q + 16);
    const path = info.cstr(q + 20, 4096);
    nodes.push({ path, offset: o, size: s, flags: f });
    q += 20 + path.length + 1;
  }
  return { signature: 'UnityFS', version, unityVersion, unityRevision, size, compressedBlocksInfoSize: cSize, uncompressedBlocksInfoSize: uSize, flags, blocksInfoCompression: compName(flags), blocksInfoAtEnd: atEnd, dataOffset, dataHash: toHex(info.sub(0, 16)), blocks, nodes };
}

/** Decompressed bytes of one node (blocks are decoded lazily, capped at maxSize). */
export function unityNodeBytes(b: Uint8Array, u: UnityFs, node: UnityNode, maxSize = 256 << 20): Uint8Array {
  if (node.size > maxSize) throw new ParseError(`node ${node.path} is larger than ${maxSize} bytes`);
  const out = new Uint8Array(node.size);
  let pos = 0, written = 0;
  for (const blk of u.blocks) {
    const start = pos, end = pos + blk.uncompressedSize;
    pos = end;
    if (end <= node.offset || start >= node.offset + node.size) continue;
    if (blk.offset + blk.compressedSize > b.length) throw new ParseError('storage block out of range', blk.offset);
    const data = decompress(blk.flags, b.subarray(blk.offset, blk.offset + blk.compressedSize), blk.uncompressedSize);
    const from = Math.max(node.offset, start), to = Math.min(node.offset + node.size, end);
    out.set(data.subarray(from - start, to - start), from - node.offset);
    written += to - from;
  }
  if (written !== node.size) throw new ParseError(`node ${node.path} is not fully covered by storage blocks`);
  return out;
}

export const UNITY_CLASSES: Record<number, string> = {
  1: 'GameObject', 4: 'Transform', 21: 'Material', 23: 'MeshRenderer', 28: 'Texture2D', 33: 'MeshFilter', 43: 'Mesh', 48: 'Shader', 49: 'TextAsset',
  74: 'AnimationClip', 82: 'AudioSource', 83: 'AudioClip', 89: 'Cubemap', 91: 'AnimatorController', 95: 'Animator', 114: 'MonoBehaviour', 115: 'MonoScript',
  128: 'Font', 137: 'SkinnedMeshRenderer', 142: 'AssetBundle', 150: 'PreloadData', 152: 'MovieTexture', 213: 'Sprite', 222: 'CanvasRenderer', 223: 'Canvas',
  224: 'RectTransform', 290: 'AssetBundleManifest', 329: 'VideoClip', 687078895: 'SpriteAtlas',
};

export interface SerializedFileSummary { version: number; unityVersion: string; targetPlatform: number; typeTree: boolean; types: { classId: number; name: string }[]; objectCount: number; objects: { pathId: string; classId: number; class: string; offset: number; size: number }[]; byClass: Record<string, number>; externals: string[] }

/** Summarise a Unity SerializedFile (asset file inside a bundle, or a loose .assets file). */
export function parseSerializedFile(b: Uint8Array, opts: { maxObjects?: number } = {}): SerializedFileSummary {
  const be = new View(b, false);
  let version = be.u32(8);
  let dataOffset: number, p: number;
  let le: boolean;
  if (version >= 22) { dataOffset = be.u64n(32); le = be.u8(40) === 0; p = 48; }
  else { dataOffset = be.u32(12); le = version >= 9 ? be.u8(16) === 0 : true; p = version >= 9 ? 20 : 0; }
  if (version < 9 || version > 60 || dataOffset > b.length) throw new ParseError(`unsupported serialized file version ${version}`, 8);
  const v = new View(b, le);
  const unityVersion = v.cstr(p, 64); p += unityVersion.length + 1;
  const targetPlatform = v.i32(p); p += 4;
  const typeTree = version >= 13 ? v.u8(p++) !== 0 : true;
  const nTypes = v.i32(p); p += 4;
  if (nTypes < 0 || nTypes > 100000) throw new ParseError('bad type count', p);
  const types: { classId: number; name: string }[] = [];
  for (let i = 0; i < nTypes; i++) {
    const cls = v.i32(p); p += 4;
    if (version >= 16) p += 1;
    if (version >= 17) p += 2;
    if (version >= 13) { if ((version < 16 && cls < 0) || (version >= 16 && cls === 114)) p += 16; p += 16; }
    if (typeTree) {
      if (version < 12 && version !== 10) throw new ParseError('legacy type trees are not supported');
      const nodes = v.i32(p), strSize = v.i32(p + 4);
      if (nodes < 0 || strSize < 0 || nodes > 1_000_000) throw new ParseError('bad type tree', p);
      p += 8 + nodes * (version >= 19 ? 32 : 24) + strSize;
      if (version >= 21) { const deps = v.i32(p); if (deps < 0 || deps > 1_000_000) throw new ParseError('bad type dependencies', p); p += 4 + deps * 4; }
    }
    types.push({ classId: cls, name: UNITY_CLASSES[cls] ?? `class${cls}` });
  }
  if (version >= 7 && version < 14) p += 4;
  const nObj = v.i32(p); p += 4;
  if (nObj < 0 || nObj > 10_000_000) throw new ParseError('bad object count', p);
  const objects: SerializedFileSummary['objects'] = [];
  const byClass: Record<string, number> = {};
  for (let i = 0; i < nObj; i++) {
    if (version >= 14) p = (p + 3) & ~3;
    const pathId = version >= 14 ? v.u64(p) : BigInt(v.i32(p)); p += version >= 14 ? 8 : 4;
    let start: number;
    if (version >= 22) { start = v.u64n(p); p += 8; } else { start = v.u32(p); p += 4; }
    const size = v.u32(p); p += 4;
    const typeId = v.i32(p); p += 4;
    let cls: number;
    if (version < 16) { cls = v.u16(p); p += 2; } else cls = types[typeId]?.classId ?? -1;
    if (version < 11) p += 2;
    if (version >= 11 && version < 17) p += 2;
    if (version === 15 || version === 16) p += 1;
    const name = UNITY_CLASSES[cls] ?? `class${cls}`;
    byClass[name] = (byClass[name] ?? 0) + 1;
    if (objects.length < (opts.maxObjects ?? 5000)) objects.push({ pathId: BigInt.asIntN(64, pathId).toString(), classId: cls, class: name, offset: dataOffset + start, size });
  }
  const externals: string[] = [];
  try {
    if (version >= 11) { const ns = v.i32(p); p += 4; if (ns >= 0 && ns < 100000) for (let i = 0; i < ns; i++) { p = (p + 3) & ~3; p += 12; } }
    const ne = v.i32(p); p += 4;
    if (ne >= 0 && ne < 100000) for (let i = 0; i < ne; i++) {
      if (version >= 6) { const s = v.cstr(p, 1024); p += s.length + 1; }
      if (version >= 5) p += 20;
      const path = v.cstr(p, 4096); p += path.length + 1;
      externals.push(path);
    }
  } catch { /* externals are optional */ }
  void version;
  return { version, unityVersion, targetPlatform, typeTree, types, objectCount: nObj, objects, byClass, externals };
}
