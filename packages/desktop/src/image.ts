// Screenshot formats: XWD (what `xwd -root` writes) to RGBA, RGBA to PNG, PNG header reading
// and simple pixel statistics. No Node imports: the PNG encoder takes a deflate function
// (node:zlib deflateSync in Node, CompressionStream or pako in a browser).
import { InputError } from './proc.js';

export interface Rgba { width: number; height: number; data: Uint8Array }

const MAX_PIXELS = 64 * 1024 * 1024;

function maskShift(mask: number): { shift: number; bits: number } {
  if (!mask) return { shift: 0, bits: 0 };
  let shift = 0; while (!((mask >>> shift) & 1) && shift < 32) shift++;
  let bits = 0; while (((mask >>> (shift + bits)) & 1) && shift + bits < 32) bits++;
  return { shift, bits };
}

/** Decode an X Window Dump (ZPixmap, TrueColor or DirectColor with 16, 24 or 32 bits per pixel, or PseudoColor with a colormap). */
export function decodeXwd(b: Uint8Array): Rgba & { name: string } {
  if (b.length < 100) throw new InputError('XWD too short');
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const h = (i: number) => dv.getUint32(i * 4, false);
  const headerSize = h(0), version = h(1), format = h(2), depth = h(3), width = h(4), height = h(5);
  const byteOrder = h(7), bpp = h(11), bpl = h(12), visual = h(13), rmask = h(14), gmask = h(15), bmask = h(16), ncolors = h(19);
  if (version !== 7) throw new InputError(`XWD version ${version} is not 7`);
  if (format !== 2) throw new InputError('only ZPixmap XWD files are supported');
  if (headerSize < 100 || headerSize > 65536 || headerSize > b.length) throw new InputError('bad XWD header size');
  if (!width || !height || width * height > MAX_PIXELS) throw new InputError('bad XWD size');
  if (![8, 16, 24, 32].includes(bpp)) throw new InputError(`unsupported XWD bits per pixel ${bpp}`);
  if (bpl < Math.ceil((width * bpp) / 8) || bpl > width * 8 + 64) throw new InputError('bad XWD bytes per line');
  if (ncolors > 65536) throw new InputError('bad XWD color count');
  const name = new TextDecoder().decode(b.subarray(100, headerSize)).replace(/\0.*$/s, '');
  const cmapAt = headerSize, dataAt = cmapAt + ncolors * 12;
  if (dataAt + bpl * height > b.length) throw new InputError('XWD pixel data truncated');
  const cmap = new Map<number, [number, number, number]>();
  for (let i = 0; i < ncolors; i++) { const o = cmapAt + i * 12; cmap.set(dv.getUint32(o, false), [dv.getUint16(o + 4, false) >> 8, dv.getUint16(o + 6, false) >> 8, dv.getUint16(o + 8, false) >> 8]); }
  const little = byteOrder === 0;
  const R = maskShift(rmask), G = maskShift(gmask), B = maskShift(bmask);
  const scale = (v: number, bits: number) => (bits >= 8 ? v >>> (bits - 8) : bits ? Math.round((v * 255) / ((1 << bits) - 1)) : 0);
  const out = new Uint8Array(width * height * 4);
  const pseudo = visual === 3 || visual === 2 || visual === 0 || visual === 1 || depth <= 8;
  for (let y = 0; y < height; y++) {
    const row = dataAt + y * bpl;
    for (let x = 0; x < width; x++) {
      let p: number;
      const o = row + (x * bpp) / 8;
      if (bpp === 32) p = dv.getUint32(o, little);
      else if (bpp === 24) p = little ? b[o]! | (b[o + 1]! << 8) | (b[o + 2]! << 16) : (b[o]! << 16) | (b[o + 1]! << 8) | b[o + 2]!;
      else if (bpp === 16) p = dv.getUint16(o, little);
      else p = b[o]!;
      const q = (y * width + x) * 4;
      if (pseudo) { const c = cmap.get(p) ?? [p, p, p]; out[q] = c[0]; out[q + 1] = c[1]; out[q + 2] = c[2]; }
      else { out[q] = scale((p & rmask) >>> R.shift, R.bits); out[q + 1] = scale((p & gmask) >>> G.shift, G.bits); out[q + 2] = scale((p & bmask) >>> B.shift, B.bits); }
      out[q + 3] = 255;
    }
  }
  return { width, height, data: out, name };
}

let CRC: Uint32Array | undefined;
export function crc32(b: Uint8Array, start = 0, end = b.length): number {
  if (!CRC) { CRC = new Uint32Array(256); for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; CRC[n] = c >>> 0; } }
  let c = 0xffffffff;
  for (let i = start; i < end; i++) c = CRC[(c ^ b[i]!) & 0xff]! ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

/** Encode RGBA as an 8-bit RGBA PNG. deflate must produce a zlib stream. */
export function encodePng(img: Rgba, deflate: (raw: Uint8Array) => Uint8Array): Uint8Array {
  const { width, height, data } = img;
  if (data.length !== width * height * 4) throw new InputError('RGBA data does not match the size');
  const raw = new Uint8Array((width * 4 + 1) * height);
  for (let y = 0; y < height; y++) { raw[y * (width * 4 + 1)] = 0; raw.set(data.subarray(y * width * 4, (y + 1) * width * 4), y * (width * 4 + 1) + 1); }
  const idat = deflate(raw);
  const chunks: Uint8Array[] = [new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])];
  const chunk = (type: string, body: Uint8Array) => {
    const c = new Uint8Array(12 + body.length); const dv = new DataView(c.buffer);
    dv.setUint32(0, body.length); for (let i = 0; i < 4; i++) c[4 + i] = type.charCodeAt(i); c.set(body, 8);
    dv.setUint32(8 + body.length, crc32(c, 4, 8 + body.length)); chunks.push(c);
  };
  const ihdr = new Uint8Array(13); const hv = new DataView(ihdr.buffer);
  hv.setUint32(0, width); hv.setUint32(4, height); ihdr[8] = 8; ihdr[9] = 6; ihdr[10] = 0; ihdr[11] = 0; ihdr[12] = 0;
  chunk('IHDR', ihdr); chunk('IDAT', idat); chunk('IEND', new Uint8Array(0));
  const total = chunks.reduce((a, c) => a + c.length, 0); const out = new Uint8Array(total); let o = 0;
  for (const c of chunks) { out.set(c, o); o += c.length; }
  return out;
}

/** Width, height, bit depth and colour type from a PNG's IHDR. */
export function pngInfo(b: Uint8Array): { width: number; height: number; bitDepth: number; colorType: number } {
  if (b.length < 33 || b[0] !== 0x89 || b[1] !== 0x50 || b[2] !== 0x4e || b[3] !== 0x47) throw new InputError('not a PNG');
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  if (String.fromCharCode(b[12]!, b[13]!, b[14]!, b[15]!) !== 'IHDR') throw new InputError('PNG without IHDR first');
  return { width: dv.getUint32(16), height: dv.getUint32(20), bitDepth: b[24]!, colorType: b[25]! };
}

/** Crop an RGBA image (clamped to its bounds). */
export function crop(img: Rgba, x: number, y: number, w: number, h: number): Rgba {
  const x0 = Math.max(0, Math.min(img.width, Math.floor(x))), y0 = Math.max(0, Math.min(img.height, Math.floor(y)));
  const x1 = Math.max(x0, Math.min(img.width, Math.floor(x + w))), y1 = Math.max(y0, Math.min(img.height, Math.floor(y + h)));
  const out = new Uint8Array((x1 - x0) * (y1 - y0) * 4);
  for (let r = y0; r < y1; r++) out.set(img.data.subarray((r * img.width + x0) * 4, (r * img.width + x1) * 4), (r - y0) * (x1 - x0) * 4);
  return { width: x1 - x0, height: y1 - y0, data: out };
}

/** Fraction of pixels that differ between two same-size images, and the bounding box of the change. */
export function diffImages(a: Rgba, b: Rgba, threshold = 16): { changed: number; fraction: number; box?: { x: number; y: number; width: number; height: number } } {
  if (a.width !== b.width || a.height !== b.height) throw new InputError('images differ in size');
  let changed = 0, minX = Infinity, minY = Infinity, maxX = -1, maxY = -1;
  for (let i = 0, p = 0; i < a.data.length; i += 4, p++) {
    if (Math.abs(a.data[i]! - b.data[i]!) + Math.abs(a.data[i + 1]! - b.data[i + 1]!) + Math.abs(a.data[i + 2]! - b.data[i + 2]!) > threshold) {
      changed++; const x = p % a.width, y = (p / a.width) | 0;
      if (x < minX) minX = x; if (y < minY) minY = y; if (x > maxX) maxX = x; if (y > maxY) maxY = y;
    }
  }
  return { changed, fraction: Math.round((changed / Math.max(1, a.width * a.height)) * 1e6) / 1e6, box: changed ? { x: minX, y: minY, width: maxX - minX + 1, height: maxY - minY + 1 } : undefined };
}
