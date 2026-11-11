// Apple BOM stores and compiled asset catalogs (Assets.car): BOM block index, named vars,
// B+ trees, then the CoreUI CARHEADER, EXTENDED_METADATA, KEYFORMAT, FACETKEYS, RENDITIONS
// and APPEARANCEKEYS so every rendition is listed with its name, size, scale and format.

import { View, ParseError, latin1, toHex, utf8 } from '../util.js';

export interface BomStore { version: number; blockCount: number; blocks: { address: number; length: number }[]; vars: Record<string, number> }

/** Parse the BOMStore header, block table and vars. */
export function parseBom(b: Uint8Array): BomStore {
  const v = new View(b, false);
  if (b.length < 32 || latin1(b.subarray(0, 8)) !== 'BOMStore') throw new ParseError('not a BOM store (BOMStore magic expected)', 0);
  const version = v.u32(8), blockCount = v.u32(12), indexOff = v.u32(16), indexLen = v.u32(20), varsOff = v.u32(24), varsLen = v.u32(28);
  v.need(indexOff, Math.min(indexLen, 4));
  const n = v.u32(indexOff);
  if (n > 4_000_000 || !v.has(indexOff + 4, n * 8)) throw new ParseError('BOM block table out of range', indexOff);
  const blocks: { address: number; length: number }[] = [];
  for (let i = 0; i < n; i++) blocks.push({ address: v.u32(indexOff + 4 + i * 8), length: v.u32(indexOff + 8 + i * 8) });
  const vars: Record<string, number> = {};
  v.need(varsOff, Math.min(varsLen, 4));
  const vc = v.u32(varsOff);
  let p = varsOff + 4;
  for (let i = 0; i < Math.min(vc, 10000); i++) {
    const id = v.u32(p), len = v.u8(p + 4);
    vars[latin1(v.sub(p + 5, len))] = id;
    p += 5 + len;
  }
  return { version, blockCount, blocks, vars };
}

/** Bytes of a BOM block by id. */
export function bomBlock(b: Uint8Array, bom: BomStore, id: number): Uint8Array {
  const e = bom.blocks[id];
  if (!e) throw new ParseError(`BOM block ${id} does not exist`);
  if (e.address + e.length > b.length) throw new ParseError(`BOM block ${id} out of range`, e.address);
  return b.subarray(e.address, e.address + e.length);
}

/** Walk a BOM tree; returns (key, value) block byte pairs in order. */
export function bomTree(b: Uint8Array, bom: BomStore, treeId: number, max = 200000): { key: Uint8Array; value: Uint8Array; keyId: number; valueId: number }[] {
  const t = new View(bomBlock(b, bom, treeId), false);
  if (t.length < 21 || latin1(t.sub(0, 4)) !== 'tree') throw new ParseError('BOM tree magic expected');
  let node = t.u32(8);
  const out: { key: Uint8Array; value: Uint8Array; keyId: number; valueId: number }[] = [];
  // descend to the leftmost leaf
  for (let d = 0; d < 64; d++) {
    const nv = new View(bomBlock(b, bom, node), false);
    if (nv.u16(0)) break;
    if (!nv.u16(2)) return out;
    node = nv.u32(12);
  }
  const seen = new Set<number>();
  while (node && !seen.has(node) && out.length < max) {
    seen.add(node);
    const nv = new View(bomBlock(b, bom, node), false);
    const count = nv.u16(2), forward = nv.u32(4);
    for (let i = 0; i < count && out.length < max; i++) {
      const valueId = nv.u32(12 + i * 8), keyId = nv.u32(16 + i * 8);
      out.push({ key: bomBlock(b, bom, keyId), value: bomBlock(b, bom, valueId), keyId, valueId });
    }
    node = forward;
  }
  return out;
}

export const RENDITION_ATTRIBUTES: Record<number, string> = {
  0: 'look', 1: 'element', 2: 'part', 3: 'size', 4: 'direction', 5: 'placeholder', 6: 'value', 7: 'appearance', 8: 'dimension1', 9: 'dimension2',
  10: 'state', 11: 'layer', 12: 'scale', 13: 'localization', 14: 'presentationState', 15: 'idiom', 16: 'subtype', 17: 'identifier', 18: 'previousValue',
  19: 'previousState', 20: 'horizontalSizeClass', 21: 'verticalSizeClass', 22: 'memoryLevelClass', 23: 'graphicsFeatureSetClass', 24: 'displayGamut',
  25: 'deploymentTarget', 26: 'appearanceIdentifier',
};
const IDIOMS: Record<number, string> = { 0: 'universal', 1: 'phone', 2: 'pad', 3: 'tv', 4: 'car', 5: 'watch', 6: 'marketing', 7: 'mac', 8: 'vision' };
const LAYOUTS: Record<number, string> = { 10: 'one-part-fixed', 11: 'one-part-tile', 12: 'one-part-scale', 20: 'three-part-h-tile', 23: 'three-part-v-tile', 30: 'nine-part-tile', 1000: 'gradient', 1001: 'effect', 1002: 'animation-filmstrip', 1003: 'vector', 1004: 'raw-data', 1005: 'external-link', 1006: 'layer-stack', 1007: 'internal-reference', 1008: 'packed-image', 1009: 'name-list', 1010: 'unknown-add-object', 1011: 'texture', 1012: 'texture-image', 1013: 'color', 1014: 'multisize-image', 1015: 'layer-reference', 1016: 'content-rendition', 1017: 'recognition-object', 1019: 'model-asset', 1020: 'model-mesh', 1021: 'model-submesh' };

export interface CarRendition { name: string; facet?: string; width: number; height: number; scale: number; pixelFormat: string; layout: string; layoutId: number; idiom?: string; appearance?: string; attributes: Record<string, number>; payloadSize: number; csiOffset: number }
export interface AssetCatalog {
  bom: { version: number; blockCount: number; vars: string[] };
  header?: { coreuiVersion: number; storageVersion: number; storageTimestamp: number; renditionCount: number; mainVersion: string; version: string; uuid: string; schemaVersion: number; colorSpace: number; keySemantics: number };
  metadata?: { thinningArguments: string; deploymentPlatformVersion: string; deploymentPlatform: string; authoringTool: string };
  keyFormat: string[]; facets: { name: string; identifier?: number; attributes: Record<string, number> }[];
  appearances: { name: string; id: number }[]; renditions: CarRendition[];
}

const cstr = (b: Uint8Array): string => { const z = b.indexOf(0); return utf8(z >= 0 ? b.subarray(0, z) : b); };
const fourcc = (n: number): string => { let s = ''; for (let i = 3; i >= 0; i--) { const c = (n >>> (i * 8)) & 0xff; s += c >= 0x20 && c < 0x7f ? String.fromCharCode(c) : '.'; } return s; };

/** Parse a compiled asset catalog (Assets.car). */
export function parseAssetCatalog(b: Uint8Array, opts: { maxRenditions?: number } = {}): AssetCatalog {
  const bom = parseBom(b);
  const out: AssetCatalog = { bom: { version: bom.version, blockCount: bom.blockCount, vars: Object.keys(bom.vars) }, keyFormat: [], facets: [], appearances: [], renditions: [] };
  if (bom.vars.CARHEADER !== undefined) {
    const h = new View(bomBlock(b, bom, bom.vars.CARHEADER), true);
    if (h.length >= 436 && fourcc(h.u32(0)) === 'CTAR') {
      out.header = { coreuiVersion: h.u32(4), storageVersion: h.u32(8), storageTimestamp: h.u32(12), renditionCount: h.u32(16), mainVersion: cstr(h.sub(20, 128)), version: cstr(h.sub(148, 256)), uuid: toHex(h.sub(404, 16)).toUpperCase(), schemaVersion: h.u32(424), colorSpace: h.u32(428), keySemantics: h.u32(432) };
    }
  }
  if (bom.vars.EXTENDED_METADATA !== undefined) {
    const m = new View(bomBlock(b, bom, bom.vars.EXTENDED_METADATA), true);
    if (m.length >= 1028) out.metadata = { thinningArguments: cstr(m.sub(4, 256)), deploymentPlatformVersion: cstr(m.sub(260, 256)), deploymentPlatform: cstr(m.sub(516, 256)), authoringTool: cstr(m.sub(772, 256)) };
  }
  let keyIds: number[] = [];
  if (bom.vars.KEYFORMAT !== undefined) {
    const k = new View(bomBlock(b, bom, bom.vars.KEYFORMAT), true);
    const n = Math.min(k.u32(8), 64);
    keyIds = Array.from({ length: n }, (_, i) => k.u32(12 + i * 4));
    out.keyFormat = keyIds.map((x) => RENDITION_ATTRIBUTES[x] ?? `attr${x}`);
  }
  const attrs = (v: View, at: number, count: number): Record<string, number> => {
    const r: Record<string, number> = {};
    for (let i = 0; i < count && v.has(at + i * 4, 4); i++) r[RENDITION_ATTRIBUTES[v.u16(at + i * 4)] ?? `attr${v.u16(at + i * 4)}`] = v.u16(at + i * 4 + 2);
    return r;
  };
  const facetById = new Map<number, string>();
  if (bom.vars.FACETKEYS !== undefined) {
    for (const e of bomTree(b, bom, bom.vars.FACETKEYS)) {
      const v = new View(e.value, true);
      const a = v.length >= 6 ? attrs(v, 6, v.u16(4)) : {};
      const name = utf8(e.key);
      out.facets.push({ name, identifier: a.identifier, attributes: a });
      if (a.identifier !== undefined) facetById.set(a.identifier, name);
    }
  }
  const appearanceById = new Map<number, string>();
  if (bom.vars.APPEARANCEKEYS !== undefined) {
    for (const e of bomTree(b, bom, bom.vars.APPEARANCEKEYS)) {
      const id = e.value.length >= 2 ? new View(e.value, true).u16(0) : -1;
      out.appearances.push({ name: utf8(e.key), id });
      appearanceById.set(id, utf8(e.key));
    }
  }
  if (bom.vars.RENDITIONS !== undefined) {
    for (const e of bomTree(b, bom, bom.vars.RENDITIONS, opts.maxRenditions ?? 100000)) {
      const kv = new View(e.key, true);
      const a: Record<string, number> = {};
      keyIds.forEach((id, i) => { if (kv.has(i * 2, 2)) a[RENDITION_ATTRIBUTES[id] ?? `attr${id}`] = kv.u16(i * 2); });
      const c = new View(e.value, true);
      if (c.length < 184 || fourcc(c.u32(0)) !== 'CTSI') continue;
      const layoutId = c.u16(36);
      out.renditions.push({
        name: cstr(c.sub(40, 128)), facet: a.identifier !== undefined ? facetById.get(a.identifier) : undefined,
        width: c.u32(12), height: c.u32(16), scale: c.u32(20) / 100, pixelFormat: fourcc(c.u32(24)).trim(), layout: LAYOUTS[layoutId] ?? String(layoutId), layoutId,
        idiom: a.idiom !== undefined ? IDIOMS[a.idiom] ?? String(a.idiom) : undefined, appearance: a.appearance ? appearanceById.get(a.appearance) : undefined,
        attributes: a, payloadSize: e.value.length, csiOffset: bom.blocks[e.valueId]!.address,
      });
    }
  }
  return out;
}
