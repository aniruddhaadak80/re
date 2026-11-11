// Minimal PNG reader and writer for screenshot comparison. No Node imports: the inflate and deflate
// functions are passed in (zlib in Node, CompressionStream in a browser worker).
import { InputError } from './util.js';

export interface RgbaImage { width: number; height: number; data: Uint8Array }
export type Inflate = (zlibData: Uint8Array) => Uint8Array | Promise<Uint8Array>;
export type Deflate = (raw: Uint8Array) => Uint8Array | Promise<Uint8Array>;

const SIG = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
/** largest image we decode (pixels); a full HD screenshot is about 2 million */
export const MAX_PNG_PIXELS = 40_000_000;

export function isPng(b: Uint8Array): boolean { return b.length >= 8 && SIG.every((v, i) => b[i] === v); }

async function streamInflate(data: Uint8Array): Promise<Uint8Array> {
  const DS = (globalThis as { DecompressionStream?: new (f: string) => TransformStream<Uint8Array, Uint8Array> }).DecompressionStream;
  if (!DS) throw new InputError('no inflate function available in this runtime');
  const stream = new Blob([data as BlobPart]).stream().pipeThrough(new DS('deflate'));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

const u32 = (b: Uint8Array, o: number) => ((b[o]! << 24) | (b[o + 1]! << 16) | (b[o + 2]! << 8) | b[o + 3]!) >>> 0;

/** Decode a non-interlaced PNG (grey, RGB, palette, grey+alpha, RGBA; bit depth 8 or 16, palette 1 to 8) to RGBA 8-bit. */
export async function decodePng(bytes: Uint8Array, inflate: Inflate = streamInflate): Promise<RgbaImage> {
  if (!isPng(bytes)) throw new InputError('not a PNG file');
  let off = 8;
  let width = 0, height = 0, depth = 0, ctype = -1, interlace = 0;
  let palette: Uint8Array | undefined; let trns: Uint8Array | undefined;
  const idat: Uint8Array[] = [];
  let idatLen = 0;
  for (let chunks = 0; off + 12 <= bytes.length && chunks < 100_000; chunks++) {
    const len = u32(bytes, off);
    const type = String.fromCharCode(bytes[off + 4]!, bytes[off + 5]!, bytes[off + 6]!, bytes[off + 7]!);
    const start = off + 8;
    if (len > bytes.length - start - 4) throw new InputError(`truncated PNG chunk ${type}`);
    const body = bytes.subarray(start, start + len);
    if (type === 'IHDR') {
      if (len < 13) throw new InputError('bad IHDR');
      width = u32(body, 0); height = u32(body, 4); depth = body[8]!; ctype = body[9]!; interlace = body[12]!;
    } else if (type === 'PLTE') palette = body;
    else if (type === 'tRNS') trns = body;
    else if (type === 'IDAT') { idat.push(body); idatLen += len; }
    else if (type === 'IEND') break;
    off = start + len + 4;
  }
  if (!width || !height) throw new InputError('PNG has no IHDR');
  if (width * height > MAX_PNG_PIXELS) throw new InputError(`PNG is ${width}x${height}, over the pixel limit`);
  if (interlace) throw new InputError('interlaced PNG is not supported');
  const channels = ({ 0: 1, 2: 3, 3: 1, 4: 2, 6: 4 } as Record<number, number>)[ctype];
  if (!channels) throw new InputError(`unsupported PNG color type ${ctype}`);
  if (!(depth === 8 || depth === 16 || (ctype === 3 && [1, 2, 4].includes(depth)) || (ctype === 0 && [1, 2, 4].includes(depth)))) throw new InputError(`unsupported PNG bit depth ${depth}`);
  const all = new Uint8Array(idatLen);
  let p = 0; for (const c of idat) { all.set(c, p); p += c.length; }
  const raw = await inflate(all);
  const bpp = Math.max(1, (channels * depth) >> 3);
  const stride = Math.ceil((width * channels * depth) / 8);
  if (raw.length < (stride + 1) * height) throw new InputError('PNG image data is truncated');
  const cur = new Uint8Array(stride), prev = new Uint8Array(stride);
  const out = new Uint8Array(width * height * 4);
  for (let y = 0; y < height; y++) {
    const rowStart = y * (stride + 1);
    const filter = raw[rowStart]!;
    for (let x = 0; x < stride; x++) {
      const v = raw[rowStart + 1 + x]!;
      const a = x >= bpp ? cur[x - bpp]! : 0, b = prev[x]!, c = x >= bpp ? prev[x - bpp]! : 0;
      let r: number;
      switch (filter) {
        case 0: r = v; break;
        case 1: r = v + a; break;
        case 2: r = v + b; break;
        case 3: r = v + ((a + b) >> 1); break;
        case 4: { const pp = a + b - c; const pa = Math.abs(pp - a), pb = Math.abs(pp - b), pc = Math.abs(pp - c); r = v + (pa <= pb && pa <= pc ? a : pb <= pc ? b : c); break; }
        default: throw new InputError(`bad PNG filter ${filter} on row ${y}`);
      }
      cur[x] = r & 0xff;
    }
    for (let x = 0; x < width; x++) {
      const o = (y * width + x) * 4;
      const sample = (i: number): number => {
        if (depth === 16) return cur[i * 2]!; // high byte
        if (depth === 8) return cur[i]!;
        const bit = i * depth; const byte = cur[bit >> 3]!; const shift = 8 - depth - (bit & 7);
        return (byte >> shift) & ((1 << depth) - 1);
      };
      if (ctype === 3) {
        const idx = sample(x);
        out[o] = palette?.[idx * 3] ?? 0; out[o + 1] = palette?.[idx * 3 + 1] ?? 0; out[o + 2] = palette?.[idx * 3 + 2] ?? 0;
        out[o + 3] = trns && idx < trns.length ? trns[idx]! : 255;
      } else if (ctype === 0 || ctype === 4) {
        let g = sample(x * channels);
        if (depth < 8) g = Math.round((g * 255) / ((1 << depth) - 1));
        out[o] = out[o + 1] = out[o + 2] = g;
        out[o + 3] = ctype === 4 ? sample(x * channels + 1) : 255;
      } else {
        out[o] = sample(x * channels); out[o + 1] = sample(x * channels + 1); out[o + 2] = sample(x * channels + 2);
        out[o + 3] = ctype === 6 ? sample(x * channels + 3) : 255;
      }
    }
    prev.set(cur);
  }
  return { width, height, data: out };
}

let CRC: Uint32Array | undefined;
function crc32(buf: Uint8Array): number {
  if (!CRC) { CRC = new Uint32Array(256); for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; CRC[n] = c >>> 0; } }
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) c = CRC[(c ^ buf[i]!) & 0xff]! ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

/** Encode RGBA 8-bit pixels as a PNG (filter 0 on every row). */
export async function encodePng(img: RgbaImage, deflate: Deflate): Promise<Uint8Array> {
  const stride = img.width * 4;
  const raw = new Uint8Array((stride + 1) * img.height);
  for (let y = 0; y < img.height; y++) raw.set(img.data.subarray(y * stride, (y + 1) * stride), y * (stride + 1) + 1);
  const z = await deflate(raw);
  const chunk = (type: string, body: Uint8Array) => {
    const c = new Uint8Array(12 + body.length);
    const dv = new DataView(c.buffer);
    dv.setUint32(0, body.length);
    for (let i = 0; i < 4; i++) c[4 + i] = type.charCodeAt(i);
    c.set(body, 8);
    dv.setUint32(8 + body.length, crc32(c.subarray(4, 8 + body.length)));
    return c;
  };
  const ihdr = new Uint8Array(13); const dv = new DataView(ihdr.buffer);
  dv.setUint32(0, img.width); dv.setUint32(4, img.height); ihdr[8] = 8; ihdr[9] = 6;
  const parts = [new Uint8Array(SIG), chunk('IHDR', ihdr), chunk('IDAT', z), chunk('IEND', new Uint8Array(0))];
  const out = new Uint8Array(parts.reduce((s, x) => s + x.length, 0));
  let o = 0; for (const x of parts) { out.set(x, o); o += x.length; }
  return out;
}

export interface PixelDiff {
  widthA: number; heightA: number; widthB: number; heightB: number;
  sizeMatches: boolean;
  /** pixels compared (the union of both canvases) */
  totalPixels: number;
  /** pixels whose largest channel difference is above the threshold, plus pixels outside the overlap */
  diffPixels: number;
  /** 1 means identical, 0 means every pixel differs */
  similarity: number;
  /** mean absolute channel difference over the overlap, 0 to 255 */
  meanAbsDiff: number;
  threshold: number;
  /** bounding box of changed pixels in the overlap, or null */
  bbox: { x: number; y: number; width: number; height: number } | null;
  /** changed pixels as white on black, when asked for */
  mask?: RgbaImage;
}

/** Compare two RGBA images pixel by pixel. threshold is the largest channel difference (0 to 255) still counted as equal. */
export function diffImages(a: RgbaImage, b: RgbaImage, opts: { threshold?: number; mask?: boolean } = {}): PixelDiff {
  const thr = Math.max(0, Math.min(255, Math.floor(opts.threshold ?? 0)));
  const w = Math.min(a.width, b.width), h = Math.min(a.height, b.height);
  const W = Math.max(a.width, b.width), H = Math.max(a.height, b.height);
  const total = W * H;
  let diff = 0, sum = 0, minX = Infinity, minY = Infinity, maxX = -1, maxY = -1;
  const mask = opts.mask ? { width: W, height: H, data: new Uint8Array(W * H * 4) } : undefined;
  for (let y = 0; y < h; y++) {
    for (let x = 0; x < w; x++) {
      const ia = (y * a.width + x) * 4, ib = (y * b.width + x) * 4;
      let m = 0;
      for (let c = 0; c < 4; c++) { const d = Math.abs(a.data[ia + c]! - b.data[ib + c]!); sum += d; if (d > m) m = d; }
      if (m > thr) {
        diff++;
        if (x < minX) minX = x; if (y < minY) minY = y; if (x > maxX) maxX = x; if (y > maxY) maxY = y;
        if (mask) { const o = (y * W + x) * 4; mask.data[o] = mask.data[o + 1] = mask.data[o + 2] = 255; }
      }
    }
  }
  diff += total - w * h;
  if (mask) for (let i = 3; i < mask.data.length; i += 4) mask.data[i] = 255;
  return {
    widthA: a.width, heightA: a.height, widthB: b.width, heightB: b.height,
    sizeMatches: a.width === b.width && a.height === b.height,
    totalPixels: total, diffPixels: diff,
    similarity: total ? Math.round((1 - diff / total) * 1e6) / 1e6 : 1,
    meanAbsDiff: w * h ? Math.round((sum / (w * h * 4)) * 1000) / 1000 : 0,
    threshold: thr,
    bbox: maxX >= 0 ? { x: minX, y: minY, width: maxX - minX + 1, height: maxY - minY + 1 } : null,
    mask,
  };
}
